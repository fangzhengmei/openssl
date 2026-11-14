/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Tests for X.509 chain building in the presence of cyclic issuer
 * back-pointers (a certificate chain whose issuer pointers form a loop).
 *
 * The certificates are generated locally with the libcrypto API, so the
 * tests neither depend on the system clock in any interesting way nor on
 * material shipped in test/certs.  All certificates are valid from one hour
 * before the test starts until a year later.
 *
 * Four shapes are exercised:
 *
 *   - a short loop:      leaf <- A <- B <- A ...
 *   - a repeated loop:   the same short loop many times over in the
 *                        untrusted certificate stack
 *   - a long loop:       LOOP_LEN distinct certificates forming a cycle
 *   - a loop that is (partly) present in the trust store itself
 *
 * plus legal, acyclic chains of various lengths, including ones that are
 * deeper than the configured verification depth.
 *
 * For every loop the tests require that:
 *
 *   - verification terminates within a bounded amount of time,
 *   - verification fails (a loop must never be accepted as a chain),
 *   - the reported error is identifiable (the loop error is distinguishable
 *     from both success and from the "chain too long" error), and
 *   - the chain that was built respects the configured depth limit, i.e.
 *     the loop cannot be used to grow the chain past it.
 *
 * The loop handling is exercised across depth limits (including values below
 * the loop length, so that the depth cap rather than loop exhaustion is what
 * stops the build), trust-anchor arrangements (an unrelated root, no anchor,
 * a trusted stack passed to X509_STORE_CTX_set0_trusted_stack(), a loop
 * member present in the store, and a loop member the application explicitly
 * marks as trusted), and verification purposes/profiles.  The same properties
 * are checked through the two TLS verification entry points: a client
 * verifying the server's certificate chain and a server verifying the
 * client's certificate chain.
 *
 * A loop-free chain that is nevertheless longer than the configured depth
 * must still fail with the "chain too long" error, so that the depth limit
 * cannot be mistaken for loop handling; conversely a legal chain within the
 * depth limit must still verify.
 */

#include <string.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "internal/nelem.h"
#include "internal/time.h"
#include "helpers/ssltestlib.h"
#include "testutil.h"

#if defined(OPENSSL_SYS_UNIX)
# include <unistd.h>
#endif

/*
 * Upper bound on how long a single X509_verify_cert() call may take.  Loops
 * are detected (or cut off at the depth limit) in well under a millisecond,
 * so this is a very generous limit that also holds under ASan, UBSan and
 * valgrind.
 */
#define VERIFY_TIME_BUDGET_MS 10000

/*
 * Whole-process watchdog.  The testutil framework installs a 30-minute
 * watchdog for every test program, but a chain-building loop bug makes
 * verification spin forever, and the point of this suite is to catch that
 * quickly and name it.  A much shorter limit is therefore installed here; it
 * replaces the framework's (it is re-armed after this file's setup_tests()).
 */
#define WATCHDOG_SECONDS 60

#if !defined(OPENSSL_SYS_WINDOWS)
# include <signal.h>

static void watchdog_expired(int sig)
{
    static const char msg[] =
        "\n# x509_chain_loop_test: verification did not terminate within "
        "the time limit, aborting\n";

    (void)sig;
    (void)write(STDERR_FILENO, msg, sizeof(msg) - 1);
    abort();
}

static void watchdog_start(unsigned int seconds)
{
    signal(SIGALRM, watchdog_expired);
    alarm(seconds);
}

static void watchdog_stop(void)
{
    alarm(0);
}
#endif

/* Number of distinct certificates in the long cycle. */
#define LOOP_LEN 16

/* Number of intermediate CA certificates in the legal deep chain. */
#define LEGAL_INTERMEDIATES 5

/*
 * Default verification depth.  X509_VERIFY_PARAM's "default" table uses 100,
 * and a chain may contain at most depth + 2 certificates (depth
 * intermediates plus leaf and trust anchor).
 */
#define DEFAULT_DEPTH 100
#define DEFAULT_MAX_CHAIN (DEFAULT_DEPTH + 2)

/* ------------------------------------------------------------------ */
/* Locally generated certificate material                             */
/* ------------------------------------------------------------------ */

static EVP_PKEY *new_key(void)
{
#ifdef OPENSSL_NO_EC
    return EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
#else
    return EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
#endif
}

static X509_NAME *new_name(const char *cn)
{
    X509_NAME *name = X509_NAME_new();

    if (name != NULL
        && !X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            (const unsigned char *)cn, -1, -1, 0)) {
        X509_NAME_free(name);
        return NULL;
    }
    return name;
}

static int add_ext(X509 *cert, int nid, const char *value)
{
    X509V3_CTX v3ctx;
    X509_EXTENSION *ext;
    int ret;

    X509V3_set_ctx(&v3ctx, NULL, cert, NULL, NULL, 0);
    if ((ext = X509V3_EXT_conf_nid(NULL, &v3ctx, nid, value)) == NULL)
        return 0;
    ret = X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    return ret > 0;
}

/* Subject key identifier: SHA-1 hash of the subjectPublicKey BIT STRING. */
static int add_skid(X509 *cert)
{
    ASN1_OCTET_STRING *skid = NULL;
    X509_EXTENSION *ext = NULL;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;
    int ret = 0;

    if (!X509_pubkey_digest(cert, EVP_sha1(), md, &mdlen)
        || (skid = ASN1_OCTET_STRING_new()) == NULL
        || !ASN1_OCTET_STRING_set(skid, md, (int)mdlen))
        goto err;
    ext = X509V3_EXT_i2d(NID_subject_key_identifier, 0, skid);
    if (ext == NULL || !X509_add_ext(cert, ext, -1))
        goto err;
    ret = 1;
err:
    X509_EXTENSION_free(ext);
    ASN1_OCTET_STRING_free(skid);
    return ret;
}

/* Digest of a public key, in the same form as a subject key identifier. */
static int key_digest(EVP_PKEY *key, unsigned char *md, unsigned int *mdlen)
{
    X509 *tmp = X509_new();
    int ret = 0;

    if (tmp != NULL && X509_set_pubkey(tmp, key))
        ret = X509_pubkey_digest(tmp, EVP_sha1(), md, mdlen);
    X509_free(tmp);
    return ret;
}

/*
 * Authority key identifier pointing at |issuer_key|.  This is built from the
 * key rather than from an issuer certificate so that cyclic chains can be
 * constructed (each certificate's AKID refers to the other's key).
 */
static int add_akid(X509 *cert, EVP_PKEY *issuer_key)
{
    AUTHORITY_KEYID *akid = NULL;
    X509_EXTENSION *ext = NULL;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;
    int ret = 0;

    if (issuer_key == NULL
        || (akid = AUTHORITY_KEYID_new()) == NULL
        || (akid->keyid = ASN1_OCTET_STRING_new()) == NULL
        || !key_digest(issuer_key, md, &mdlen)
        || !ASN1_OCTET_STRING_set(akid->keyid, md, (int)mdlen))
        goto err;
    ext = X509V3_EXT_i2d(NID_authority_key_identifier, 0, akid);
    if (ext == NULL || !X509_add_ext(cert, ext, -1))
        goto err;
    ret = 1;
err:
    X509_EXTENSION_free(ext);
    AUTHORITY_KEYID_free(akid);
    return ret;
}

/*
 * Create a certificate with subject |subject_cn| and issuer name
 * |issuer_cn|, carrying |subject_key| and signed by |signing_key|.  The AKID
 * keyid is derived from |akid_key| (pass NULL for no AKID).  CA certificates
 * get basicConstraints, keyUsage and a SKID.
 */
static X509 *make_cert(const char *subject_cn, const char *issuer_cn,
    EVP_PKEY *subject_key, EVP_PKEY *signing_key, EVP_PKEY *akid_key,
    long serial, int is_ca, const char *eku)
{
    X509 *cert = NULL;
    X509_NAME *subject = NULL, *issuer = NULL;

    if ((cert = X509_new()) == NULL
        || !X509_set_version(cert, X509_VERSION_3)
        || !ASN1_INTEGER_set(X509_get_serialNumber(cert), serial)
        || !X509_gmtime_adj(X509_getm_notBefore(cert), -3600)
        || !X509_gmtime_adj(X509_getm_notAfter(cert), 365 * 24 * 3600)
        || (subject = new_name(subject_cn)) == NULL
        || (issuer = new_name(issuer_cn)) == NULL
        || !X509_set_subject_name(cert, subject)
        || !X509_set_issuer_name(cert, issuer)
        || !X509_set_pubkey(cert, subject_key))
        goto err;
    if (is_ca) {
        if (!add_ext(cert, NID_basic_constraints, "critical,CA:TRUE")
            || !add_ext(cert, NID_key_usage, "critical,keyCertSign,cRLSign")
            || !add_skid(cert))
            goto err;
    } else {
        if (!add_ext(cert, NID_basic_constraints, "critical,CA:FALSE")
            || !add_ext(cert, NID_key_usage,
                "critical,digitalSignature,keyEncipherment"))
            goto err;
    }
    if (eku != NULL && !add_ext(cert, NID_ext_key_usage, eku))
        goto err;
    if (akid_key != NULL && !add_akid(cert, akid_key))
        goto err;
    if (X509_sign(cert, signing_key, EVP_sha256()) <= 0)
        goto err;
    X509_NAME_free(subject);
    X509_NAME_free(issuer);
    return cert;
err:
    X509_NAME_free(subject);
    X509_NAME_free(issuer);
    X509_free(cert);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Fixed test fixtures                                                */
/* ------------------------------------------------------------------ */

static EVP_PKEY *root_key;   /* unrelated, self-signed trust anchor */
static X509 *root_cert;

static EVP_PKEY *loop_key_a, *loop_key_b, *loop_leaf_key;
static X509 *loop_cert_a, *loop_cert_b, *loop_leaf;

static EVP_PKEY *long_keys[LOOP_LEN];      /* signed by next, index 0 by last */
static X509 *long_certs[LOOP_LEN];
static EVP_PKEY *long_leaf_key;
static X509 *long_leaf;

static EVP_PKEY *legal_keys[LEGAL_INTERMEDIATES]; /* [0] issued by root */
static X509 *legal_certs[LEGAL_INTERMEDIATES];
static EVP_PKEY *legal_leaf_key;
static X509 *legal_leaf;

/* Server certificate for handshakes where the server is not under test. */
static EVP_PKEY *server_key;
static X509 *server_cert;

/* Free everything allocated by setup_fixtures(). */
static void free_fixtures(void)
{
    int i;

    X509_free(root_cert);
    root_cert = NULL;
    EVP_PKEY_free(root_key);
    root_key = NULL;

    X509_free(loop_cert_a);
    loop_cert_a = NULL;
    X509_free(loop_cert_b);
    loop_cert_b = NULL;
    X509_free(loop_leaf);
    loop_leaf = NULL;
    EVP_PKEY_free(loop_key_a);
    loop_key_a = NULL;
    EVP_PKEY_free(loop_key_b);
    loop_key_b = NULL;
    EVP_PKEY_free(loop_leaf_key);
    loop_leaf_key = NULL;

    for (i = 0; i < LOOP_LEN; i++) {
        X509_free(long_certs[i]);
        long_certs[i] = NULL;
        EVP_PKEY_free(long_keys[i]);
        long_keys[i] = NULL;
    }
    X509_free(long_leaf);
    long_leaf = NULL;
    EVP_PKEY_free(long_leaf_key);
    long_leaf_key = NULL;

    for (i = 0; i < LEGAL_INTERMEDIATES; i++) {
        X509_free(legal_certs[i]);
        legal_certs[i] = NULL;
        EVP_PKEY_free(legal_keys[i]);
        legal_keys[i] = NULL;
    }
    X509_free(legal_leaf);
    legal_leaf = NULL;
    EVP_PKEY_free(legal_leaf_key);
    legal_leaf_key = NULL;

    X509_free(server_cert);
    server_cert = NULL;
    EVP_PKEY_free(server_key);
    server_key = NULL;
}

static int setup_fixtures(void)
{
    int i;
    char name[32], issuer[32];

    if ((root_key = new_key()) == NULL
        || (root_cert = make_cert("Root", "Root", root_key, root_key, root_key,
                1, 1, NULL)) == NULL)
        return 0;

    /*
     * Short loop: leaf <- A, A <- B, B <- A.  Neither A nor B is self-signed,
     * they cross-issue each other, and each carries an AKID pointing at the
     * other's key, so that the back-pointer looks perfectly legitimate to
     * the "likely issued" test.
     */
    if ((loop_key_a = new_key()) == NULL
        || (loop_key_b = new_key()) == NULL
        || (loop_leaf_key = new_key()) == NULL
        || (loop_cert_a = make_cert("Loop A", "Loop B", loop_key_a, loop_key_b,
                loop_key_b, 2, 1, NULL)) == NULL
        || (loop_cert_b = make_cert("Loop B", "Loop A", loop_key_b, loop_key_a,
                loop_key_a, 3, 1, NULL)) == NULL
        || (loop_leaf = make_cert("Loop Leaf", "Loop A", loop_leaf_key,
                loop_key_a, loop_key_a, 4, 0,
                "serverAuth,clientAuth")) == NULL)
        return 0;

    /*
     * Long loop: LOOP_LEN distinct CA certificates, Long 0 issued by Long 1,
     * Long 1 by Long 2, ..., Long LOOP_LEN-1 by Long 0.  The leaf is issued
     * by Long 0.  Every issuer reference is backed by a correct AKID, so
     * chain building can follow the cycle for as long as it is allowed to.
     */
    for (i = 0; i < LOOP_LEN; i++) {
        if ((long_keys[i] = new_key()) == NULL)
            return 0;
    }
    for (i = 0; i < LOOP_LEN; i++) {
        int next = (i + 1) % LOOP_LEN;

        (void)snprintf(name, sizeof(name), "Long %d", i);
        (void)snprintf(issuer, sizeof(issuer), "Long %d", next);
        long_certs[i] = make_cert(name, issuer, long_keys[i], long_keys[next],
            long_keys[next], 100 + i, 1, NULL);
        if (long_certs[i] == NULL)
            return 0;
    }
    if ((long_leaf_key = new_key()) == NULL
        || (long_leaf = make_cert("Long Leaf", "Long 0", long_leaf_key,
                long_keys[0], long_keys[0], 200, 0,
                "serverAuth,clientAuth")) == NULL)
        return 0;

    /*
     * Legal acyclic chain: Root <- Legal 0 <- Legal 1 <- ... <- Legal
     * LEGAL_INTERMEDIATES-1 <- Legal Leaf.
     */
    for (i = 0; i < LEGAL_INTERMEDIATES; i++) {
        if ((legal_keys[i] = new_key()) == NULL)
            return 0;
    }
    (void)snprintf(name, sizeof(name), "Legal 0");
    legal_certs[0] = make_cert(name, "Root", legal_keys[0], root_key, root_key,
        300, 1, NULL);
    if (legal_certs[0] == NULL)
        return 0;
    for (i = 1; i < LEGAL_INTERMEDIATES; i++) {
        (void)snprintf(name, sizeof(name), "Legal %d", i);
        (void)snprintf(issuer, sizeof(issuer), "Legal %d", i - 1);
        legal_certs[i] = make_cert(name, issuer, legal_keys[i], legal_keys[i - 1],
            legal_keys[i - 1], 300 + i, 1, NULL);
        if (legal_certs[i] == NULL)
            return 0;
    }
    if ((legal_leaf_key = new_key()) == NULL)
        return 0;
    (void)snprintf(issuer, sizeof(issuer), "Legal %d", LEGAL_INTERMEDIATES - 1);
    if ((legal_leaf = make_cert("Legal Leaf", issuer, legal_leaf_key,
                legal_keys[LEGAL_INTERMEDIATES - 1],
                legal_keys[LEGAL_INTERMEDIATES - 1], 400, 0,
                "serverAuth,clientAuth")) == NULL)
        return 0;

    /*
     * An ordinary server certificate, trusted by |root_cert|.  Used when the
     * server is not the side whose chain is being verified.
     */
    if ((server_key = new_key()) == NULL
        || (server_cert = make_cert("Server", "Root", server_key, root_key,
                root_key, 500, 0, "serverAuth")) == NULL)
        return 0;

    return 1;
}

/* ------------------------------------------------------------------ */
/* Verification helpers                                               */
/* ------------------------------------------------------------------ */

typedef struct {
    int ok;          /* X509_verify_cert() return value */
    int error;
    int error_depth;
    int chain_len;   /* -1 if no chain is available */
    uint64_t ms;     /* elapsed wall time */
} verify_result;

/*
 * Run one verification.  |depth| < 0 means "use the default depth".  |purpose|
 * < 0 leaves the purpose alone, otherwise it is passed to
 * X509_STORE_CTX_set_purpose().  |profile| selects a X509_VERIFY_PARAM profile
 * (NULL means leave the default alone).  |trusted_stack|, if non-NULL, is used
 * as an explicit trusted stack instead of looking up issuers in |store|; it
 * must outlive the call.
 */
static verify_result verify_cert(X509 *leaf, STACK_OF(X509) *untrusted,
    X509_STORE *store, STACK_OF(X509) *trusted_stack, int depth,
    const char *profile, int purpose, unsigned long set_flags,
    unsigned long clear_flags)
{
    verify_result res;
    X509_STORE_CTX *ctx = NULL;
    OSSL_TIME start;
    STACK_OF(X509) *chain;

    memset(&res, 0, sizeof(res));
    res.chain_len = -1;
    start = ossl_time_now();

    if ((ctx = X509_STORE_CTX_new()) == NULL
        || !X509_STORE_CTX_init(ctx, store, leaf, untrusted))
        goto end;
    if (trusted_stack != NULL)
        X509_STORE_CTX_set0_trusted_stack(ctx, trusted_stack);
    if (depth >= 0)
        X509_STORE_CTX_set_depth(ctx, depth);
    if (purpose >= 0 && !X509_STORE_CTX_set_purpose(ctx, purpose))
        goto end;
    if (profile != NULL
        && !X509_STORE_CTX_set_default(ctx, profile))
        goto end;
    if (clear_flags != 0 || set_flags != 0) {
        X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(ctx);

        X509_VERIFY_PARAM_clear_flags(param, clear_flags);
        X509_VERIFY_PARAM_set_flags(param, set_flags);
    }

    res.ok = X509_verify_cert(ctx);
    res.error = X509_STORE_CTX_get_error(ctx);
    res.error_depth = X509_STORE_CTX_get_error_depth(ctx);
    chain = X509_STORE_CTX_get0_chain(ctx);
    if (chain != NULL)
        res.chain_len = sk_X509_num(chain);

end:
    res.ms = ossl_time2ms(ossl_time_subtract(ossl_time_now(), start));
    X509_STORE_CTX_free(ctx);
    ERR_clear_error();
    return res;
}

/* The chain may contain at most depth + 2 certificates. */
static int chain_within_depth(const verify_result *res, int depth)
{
    int limit = depth < 0 ? DEFAULT_MAX_CHAIN : depth + 2;

    return res->chain_len < 0 || res->chain_len <= limit;
}

/* True if no certificate appears twice in |chain|. */
static int chain_has_no_duplicates(STACK_OF(X509) *chain)
{
    int i, j, n;

    if (chain == NULL)
        return 1;
    n = sk_X509_num(chain);
    for (i = 0; i < n; i++)
        for (j = i + 1; j < n; j++)
            if (X509_cmp(sk_X509_value(chain, i), sk_X509_value(chain, j)) == 0)
                return 0;
    return 1;
}

static X509_STORE *make_store(X509 *anchor)
{
    X509_STORE *store = X509_STORE_new();

    if (store == NULL)
        return NULL;
    if (anchor != NULL && X509_STORE_add_cert(store, anchor) <= 0) {
        X509_STORE_free(store);
        return NULL;
    }
    return store;
}

static int push_array(STACK_OF(X509) *stack, X509 **certs, int count)
{
    int i;

    for (i = 0; i < count; i++)
        if (!sk_X509_push(stack, certs[i]))
            return 0;
    return 1;
}

/*
 * Common assertion set for a verification that must fail because of a loop:
 * it terminates in time, it does not succeed, it reports |expected_error|,
 * and the chain it built stays within the depth limit.
 */
static int check_loop_failure(const verify_result *res, int depth,
    int expected_error)
{
    return TEST_uint64_t_le(res->ms, VERIFY_TIME_BUDGET_MS)
        && TEST_int_eq(res->ok, 0)
        && TEST_int_eq(res->error, expected_error)
        && TEST_int_ne(res->error, X509_V_OK)
        && TEST_true(chain_within_depth(res, depth))
        /* The reported error depth must lie within the built chain. */
        && TEST_int_ge(res->error_depth, 0)
        && TEST_int_lt(res->error_depth, res->chain_len);
}

/* ------------------------------------------------------------------ */
/* Short loop, untrusted                                              */
/* ------------------------------------------------------------------ */

enum anchor_kind {
    ANCHOR_NONE,             /* empty trust store */
    ANCHOR_ROOT,             /* unrelated self-signed root */
    ANCHOR_PEER,             /* a member of the loop is in the trust store */
    ANCHOR_TRUSTED_STACK     /* unrelated root via set0_trusted_stack() */
};

static const struct {
    int depth;
    enum anchor_kind anchor;
    int expected_error;
} short_loop_cases[] = {
    /*
     * Without a usable trust anchor the loop is exhausted at its second
     * certificate and X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY is
     * reported.  With a depth too small to even contain the loop, the depth
     * limit is hit first and X509_V_ERR_CERT_CHAIN_TOO_LONG is reported.
     * The two errors are deliberately different.
     */
    { 0,   ANCHOR_ROOT, X509_V_ERR_CERT_CHAIN_TOO_LONG },
    { 1,   ANCHOR_ROOT, X509_V_ERR_CERT_CHAIN_TOO_LONG },
    { 2,   ANCHOR_ROOT, X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY },
    { 100, ANCHOR_ROOT, X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY },
    { -1,  ANCHOR_ROOT, X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY },
    { 2,   ANCHOR_NONE, X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY },
    { 100, ANCHOR_NONE, X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY },
    { 2,   ANCHOR_TRUSTED_STACK,
      X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY },
    /* The loop member is not self-signed, so mere presence in the trust
     * store does not make it a trust anchor. */
    { 100, ANCHOR_PEER, X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT },
    { 0,   ANCHOR_PEER, X509_V_ERR_CERT_CHAIN_TOO_LONG },
    { 1,   ANCHOR_PEER, X509_V_ERR_CERT_CHAIN_TOO_LONG },
};

static int test_short_loop(int idx)
{
    const int ncases = (int)OSSL_NELEM(short_loop_cases);
    int depth = short_loop_cases[idx].depth;
    enum anchor_kind anchor = short_loop_cases[idx].anchor;
    int expected_error = short_loop_cases[idx].expected_error;
    X509_STORE *store = NULL;
    STACK_OF(X509) *untrusted = NULL, *trusted = NULL;
    verify_result res;
    int ret = 0;

    if (idx < 0 || idx >= ncases)
        return 0;
    if ((untrusted = sk_X509_new_null()) == NULL
        || !sk_X509_push(untrusted, loop_cert_a)
        || !sk_X509_push(untrusted, loop_cert_b))
        goto end;

    switch (anchor) {
    case ANCHOR_NONE:
        if ((store = make_store(NULL)) == NULL)
            goto end;
        break;
    case ANCHOR_ROOT:
        if ((store = make_store(root_cert)) == NULL)
            goto end;
        break;
    case ANCHOR_PEER:
        if ((store = make_store(loop_cert_b)) == NULL)
            goto end;
        break;
    case ANCHOR_TRUSTED_STACK:
        if ((store = make_store(NULL)) == NULL
            || (trusted = sk_X509_new_null()) == NULL
            || !sk_X509_push(trusted, root_cert))
            goto end;
        break;
    }

    res = verify_cert(loop_leaf, untrusted, store, trusted, depth, NULL, -1,
        0, 0);

    if (!check_loop_failure(&res, depth, expected_error))
        goto end;
    /*
     * The loop must not have been unrolled: a chain built from an
     * untrusted loop contains each certificate at most once.
     */
    if (!TEST_int_ge(res.chain_len, 1)
        || !TEST_int_le(res.chain_len, 3))
        goto end;

    ret = 1;
end:
    X509_STORE_free(store);
    sk_X509_free(untrusted);
    sk_X509_free(trusted);
    return ret;
}

/* The chain returned for an untrusted loop has no duplicate certificates. */
static int test_short_loop_chain_is_unique(void)
{
    X509_STORE *store = NULL;
    STACK_OF(X509) *untrusted = NULL;
    X509_STORE_CTX *ctx = NULL;
    int ret = 0;

    if ((store = make_store(root_cert)) == NULL
        || (untrusted = sk_X509_new_null()) == NULL
        || !sk_X509_push(untrusted, loop_cert_a)
        || !sk_X509_push(untrusted, loop_cert_b))
        goto end;

    if ((ctx = X509_STORE_CTX_new()) == NULL
        || !X509_STORE_CTX_init(ctx, store, loop_leaf, untrusted)
        || !TEST_int_eq(X509_verify_cert(ctx), 0))
        goto end;
    if (!TEST_true(chain_has_no_duplicates(X509_STORE_CTX_get0_chain(ctx))))
        goto end;
    ret = 1;
end:
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_free(untrusted);
    ERR_clear_error();
    return ret;
}

/* ------------------------------------------------------------------ */
/* Repeated certificates / repeated chains                            */
/* ------------------------------------------------------------------ */

/* This many copies of each loop member are placed in the untrusted stack. */
#define LOOP_REPEATS 64

static int test_repeated_loop(void)
{
    X509_STORE *store = NULL;
    STACK_OF(X509) *untrusted = NULL;
    verify_result res;
    int i, ret = 0;

    if ((store = make_store(root_cert)) == NULL
        || (untrusted = sk_X509_new_null()) == NULL)
        goto end;
    for (i = 0; i < LOOP_REPEATS; i++) {
        if (!sk_X509_push(untrusted, loop_cert_a)
            || !sk_X509_push(untrusted, loop_cert_b))
            goto end;
    }

    res = verify_cert(loop_leaf, untrusted, store, NULL, -1, NULL, -1, 0, 0);
    if (!check_loop_failure(&res, -1,
            X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY))
        goto end;
    /*
     * Repeating the loop in the input must not lengthen the built chain:
     * duplicates are not added to the chain.
     */
    if (!TEST_int_eq(res.chain_len, 3))
        goto end;

    /* A small depth still cuts the chain off, duplicates notwithstanding. */
    res = verify_cert(loop_leaf, untrusted, store, NULL, 1, NULL, -1, 0, 0);
    if (!check_loop_failure(&res, 1, X509_V_ERR_CERT_CHAIN_TOO_LONG))
        goto end;
    if (!TEST_int_eq(res.chain_len, 3))
        goto end;

    ret = 1;
end:
    X509_STORE_free(store);
    sk_X509_free(untrusted);
    return ret;
}

/* A legal chain that is repeated several times must still verify normally. */
#define LEGAL_REPEATS 3

static int test_repeated_legal_chain(void)
{
    X509_STORE *store = NULL;
    STACK_OF(X509) *untrusted = NULL;
    verify_result res;
    int i, ret = 0;

    if ((store = make_store(root_cert)) == NULL
        || (untrusted = sk_X509_new_null()) == NULL)
        goto end;
    for (i = 0; i < LEGAL_REPEATS; i++) {
        if (!push_array(untrusted, legal_certs, LEGAL_INTERMEDIATES))
            goto end;
    }

    res = verify_cert(legal_leaf, untrusted, store, NULL,
        LEGAL_INTERMEDIATES, NULL, -1, 0, 0);
    if (!TEST_uint64_t_le(res.ms, VERIFY_TIME_BUDGET_MS)
        || !TEST_int_eq(res.ok, 1)
        || !TEST_int_eq(res.error, X509_V_OK)
        /* leaf + intermediates + anchor, duplicates ignored */
        || !TEST_int_eq(res.chain_len, LEGAL_INTERMEDIATES + 2))
        goto end;

    ret = 1;
end:
    X509_STORE_free(store);
    sk_X509_free(untrusted);
    return ret;
}

/* ------------------------------------------------------------------ */
/* Long loop                                                          */
/* ------------------------------------------------------------------ */

/*
 * Depth sweep across a LOOP_LEN-certificate loop.  Below LOOP_LEN the depth
 * cap is reached first (CERT_CHAIN_TOO_LONG); at or above it the loop is
 * exhausted and the issuer cannot be found (UNABLE_TO_GET_ISSUER_CERT_LOCALLY).
 * Either way building terminates promptly and never succeeds.
 */
static const int long_loop_depths[] = {
    0, 1, 2, LOOP_LEN - 2, LOOP_LEN - 1, LOOP_LEN, LOOP_LEN + 1, 100, -1
};

static int test_long_loop(int idx)
{
    int depth;
    int expected_error;
    X509_STORE *store = NULL;
    STACK_OF(X509) *untrusted = NULL;
    verify_result res;
    int ret = 0;

    if (idx < 0 || idx >= (int)OSSL_NELEM(long_loop_depths))
        return 0;
    depth = long_loop_depths[idx];

    if (depth >= LOOP_LEN || depth < 0)
        expected_error = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
    else
        expected_error = X509_V_ERR_CERT_CHAIN_TOO_LONG;

    if ((store = make_store(root_cert)) == NULL
        || (untrusted = sk_X509_new_null()) == NULL
        || !push_array(untrusted, long_certs, LOOP_LEN))
        goto end;

    res = verify_cert(long_leaf, untrusted, store, NULL, depth, NULL, -1, 0, 0);

    /* check_loop_failure also checks that the chain stayed within depth. */
    if (!check_loop_failure(&res, depth, expected_error))
        goto end;

    ret = 1;
end:
    X509_STORE_free(store);
    sk_X509_free(untrusted);
    return ret;
}

/*
 * A loop that lives entirely inside the trust store.  Issuers taken from the
 * store are not subject to duplicate suppression, so chain building follows
 * the loop until the depth limit stops it.  The important property is that it
 * *does* stop at the limit, promptly and with the depth-limit error, rather
 * than growing without bound.
 */
static const int store_loop_depths[] = { 0, 1, 2, 3, -1 };

static int test_loop_in_store(int idx)
{
    X509_STORE *store = NULL;
    STACK_OF(X509) *untrusted = NULL;
    verify_result res;
    int depth;
    int ret = 0;

    if (idx < 0 || idx >= (int)OSSL_NELEM(store_loop_depths))
        return 0;
    depth = store_loop_depths[idx];

    if ((store = make_store(loop_cert_a)) == NULL
        || X509_STORE_add_cert(store, loop_cert_b) <= 0
        || (untrusted = sk_X509_new_null()) == NULL
        || !sk_X509_push(untrusted, loop_cert_b))
        goto end;

    res = verify_cert(loop_leaf, untrusted, store, NULL, depth, NULL, -1, 0, 0);

    if (!check_loop_failure(&res, depth, X509_V_ERR_CERT_CHAIN_TOO_LONG))
        goto end;

    ret = 1;
end:
    X509_STORE_free(store);
    sk_X509_free(untrusted);
    return ret;
}

/*
 * The same store loop with search-policy flags changed.  None of the policy
 * choices may turn the loop into a valid chain or let it escape the limit.
 */
static int test_loop_in_store_flags(int idx)
{
    X509_STORE *store = NULL;
    STACK_OF(X509) *untrusted = NULL;
    verify_result res;
    int ret = 0;

    if ((store = make_store(loop_cert_a)) == NULL
        || X509_STORE_add_cert(store, loop_cert_b) <= 0
        || (untrusted = sk_X509_new_null()) == NULL
        || !sk_X509_push(untrusted, loop_cert_b))
        goto end;

    switch (idx) {
    case 0: /* trusted-first disabled, alternate chains allowed */
        res = verify_cert(loop_leaf, untrusted, store, NULL, 8, NULL, -1,
            0, X509_V_FLAG_TRUSTED_FIRST);
        break;
    case 1: /* alternate chains disabled */
        res = verify_cert(loop_leaf, untrusted, store, NULL, 8, NULL, -1,
            X509_V_FLAG_NO_ALT_CHAINS, X509_V_FLAG_TRUSTED_FIRST);
        break;
    case 2: /* strict checking */
        res = verify_cert(loop_leaf, untrusted, store, NULL, 8, NULL, -1,
            X509_V_FLAG_X509_STRICT, 0);
        break;
    case 3: /*
             * With partial chains, a certificate taken from the trust store
             * acts as a trust anchor in its own right, so the loop is stopped
             * as soon as the first store certificate is reached.  No loop is
             * traversed and the chain stays short -- that is a successful
             * verification, not an endless loop.
             */
        res = verify_cert(loop_leaf, untrusted, store, NULL, 8, NULL, -1,
            X509_V_FLAG_PARTIAL_CHAIN, 0);
        break;
    default:
        goto end;
    }

    if (idx == 3) {
        if (!TEST_uint64_t_le(res.ms, VERIFY_TIME_BUDGET_MS)
            || !TEST_int_eq(res.ok, 1)
            || !TEST_int_eq(res.error, X509_V_OK)
            || !TEST_int_eq(res.chain_len, 2))
            goto end;
    } else if (!check_loop_failure(&res, 8, X509_V_ERR_CERT_CHAIN_TOO_LONG)) {
        goto end;
    }

    ret = 1;
end:
    X509_STORE_free(store);
    sk_X509_free(untrusted);
    return ret;
}

/* ------------------------------------------------------------------ */
/* Legal chains and depth limits                                      */
/* ------------------------------------------------------------------ */

/*
 * For a legal chain with LEGAL_INTERMEDIATES intermediates, depth must be at
 * least LEGAL_INTERMEDIATES.  Below that the chain is rejected as too long;
 * at that depth and above it verifies successfully with a chain of
 * LEGAL_INTERMEDIATES + 2 certificates.
 */
static int test_legal_chain_depth(int idx)
{
    X509_STORE *store = NULL;
    STACK_OF(X509) *untrusted = NULL;
    verify_result res;
    int depth = idx;
    int ret = 0;

    if (depth < 0 || depth > LEGAL_INTERMEDIATES + 1)
        return 0;
    if ((store = make_store(root_cert)) == NULL
        || (untrusted = sk_X509_new_null()) == NULL
        || !push_array(untrusted, legal_certs, LEGAL_INTERMEDIATES))
        goto end;

    res = verify_cert(legal_leaf, untrusted, store, NULL, depth, NULL, -1, 0, 0);

    if (!TEST_uint64_t_le(res.ms, VERIFY_TIME_BUDGET_MS))
        goto end;
    if (depth >= LEGAL_INTERMEDIATES) {
        if (!TEST_int_eq(res.ok, 1)
            || !TEST_int_eq(res.error, X509_V_OK)
            || !TEST_int_eq(res.chain_len, LEGAL_INTERMEDIATES + 2))
            goto end;
    } else {
        if (!TEST_int_eq(res.ok, 0)
            || !TEST_int_eq(res.error, X509_V_ERR_CERT_CHAIN_TOO_LONG)
            || !TEST_true(chain_within_depth(&res, depth)))
            goto end;
    }

    ret = 1;
end:
    X509_STORE_free(store);
    sk_X509_free(untrusted);
    return ret;
}

/*
 * A legal chain verified through an explicit trusted stack (rather than an
 * X509_STORE) behaves the same way.
 */
static int test_legal_chain_trusted_stack(void)
{
    STACK_OF(X509) *untrusted = NULL, *trusted = NULL;
    verify_result res;
    int ret = 0;

    if ((untrusted = sk_X509_new_null()) == NULL
        || (trusted = sk_X509_new_null()) == NULL
        || !push_array(untrusted, legal_certs, LEGAL_INTERMEDIATES)
        || !sk_X509_push(trusted, root_cert))
        goto end;

    res = verify_cert(legal_leaf, untrusted, NULL, trusted,
        LEGAL_INTERMEDIATES, NULL, -1, 0, 0);
    if (!TEST_uint64_t_le(res.ms, VERIFY_TIME_BUDGET_MS)
        || !TEST_int_eq(res.ok, 1)
        || !TEST_int_eq(res.error, X509_V_OK)
        || !TEST_int_eq(res.chain_len, LEGAL_INTERMEDIATES + 2))
        goto end;

    ret = 1;
end:
    sk_X509_free(untrusted);
    sk_X509_free(trusted);
    return ret;
}

/*
 * A loop member that is explicitly marked as trusted by the application is a
 * legitimate trust anchor.  Success is then correct, and the chain must stop
 * right there instead of following the loop.
 */
static int test_loop_member_explicitly_trusted(void)
{
    X509_STORE *store = NULL;
    STACK_OF(X509) *untrusted = NULL;
    X509 *trusted_a = NULL;
    verify_result res;
    int ret = 0;

    /*
     * Work on a copy so that the auxiliary trust setting does not leak into
     * the fixtures used by the other tests.
     */
    if ((trusted_a = X509_dup(loop_cert_a)) == NULL
        || !X509_add1_trust_object(trusted_a, OBJ_nid2obj(NID_server_auth))
        || (store = make_store(trusted_a)) == NULL
        || (untrusted = sk_X509_new_null()) == NULL
        || !sk_X509_push(untrusted, loop_cert_b))
        goto end;

    res = verify_cert(loop_leaf, untrusted, store, NULL, -1, "ssl_server", -1,
        0, 0);
    if (!TEST_uint64_t_le(res.ms, VERIFY_TIME_BUDGET_MS)
        || !TEST_int_eq(res.ok, 1)
        || !TEST_int_eq(res.error, X509_V_OK)
        /* leaf and its trusted issuer, no loop following */
        || !TEST_int_eq(res.chain_len, 2))
        goto end;

    ret = 1;
end:
    X509_STORE_free(store);
    sk_X509_free(untrusted);
    X509_free(trusted_a);
    return ret;
}

/* ------------------------------------------------------------------ */
/* Error-code distinguishability                                      */
/* ------------------------------------------------------------------ */

/*
 * Collect the three outcomes this suite relies on -- success, a loop, and a
 * depth-limit failure -- and check that the errors are pairwise distinct and
 * have distinct textual descriptions.
 */
static int test_errors_are_distinguishable(void)
{
    X509_STORE *store = NULL;
    STACK_OF(X509) *loop_stack = NULL, *legal_stack = NULL;
    verify_result loop_res, depth_res, ok_res;
    int ret = 0;

    if ((store = make_store(root_cert)) == NULL
        || (loop_stack = sk_X509_new_null()) == NULL
        || (legal_stack = sk_X509_new_null()) == NULL
        || !sk_X509_push(loop_stack, loop_cert_a)
        || !sk_X509_push(loop_stack, loop_cert_b)
        || !push_array(legal_stack, legal_certs, LEGAL_INTERMEDIATES))
        goto end;

    loop_res = verify_cert(loop_leaf, loop_stack, store, NULL, -1, NULL, -1,
        0, 0);
    depth_res = verify_cert(legal_leaf, legal_stack, store, NULL,
        LEGAL_INTERMEDIATES - 1, NULL, -1, 0, 0);
    ok_res = verify_cert(legal_leaf, legal_stack, store, NULL,
        LEGAL_INTERMEDIATES, NULL, -1, 0, 0);

    if (!TEST_int_eq(loop_res.ok, 0)
        || !TEST_int_eq(loop_res.error,
            X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
        || !TEST_int_eq(depth_res.ok, 0)
        || !TEST_int_eq(depth_res.error, X509_V_ERR_CERT_CHAIN_TOO_LONG)
        || !TEST_int_eq(ok_res.ok, 1)
        || !TEST_int_eq(ok_res.error, X509_V_OK))
        goto end;

    /* Three distinct error codes... */
    if (!TEST_int_ne(loop_res.error, depth_res.error)
        || !TEST_int_ne(loop_res.error, ok_res.error)
        || !TEST_int_ne(depth_res.error, ok_res.error))
        goto end;

    /* ...with three distinct descriptions. */
    if (!TEST_str_ne(X509_verify_cert_error_string(loop_res.error),
            X509_verify_cert_error_string(depth_res.error))
        || !TEST_str_ne(X509_verify_cert_error_string(loop_res.error),
            X509_verify_cert_error_string(ok_res.error))
        || !TEST_str_ne(X509_verify_cert_error_string(depth_res.error),
            X509_verify_cert_error_string(ok_res.error)))
        goto end;

    ret = 1;
end:
    X509_STORE_free(store);
    sk_X509_free(loop_stack);
    sk_X509_free(legal_stack);
    return ret;
}

/* ------------------------------------------------------------------ */
/* X509_build_chain()                                                 */
/* ------------------------------------------------------------------ */

/*
 * X509_build_chain() must not spin on a loop either.  Depending on the trust
 * store it either returns NULL (when a complete trusted chain is required) or
 * a chain that stops at the depth limit.
 */
static int test_build_chain_loop(int idx)
{
    STACK_OF(X509) *certs = NULL, *built = NULL;
    X509_STORE *store = NULL;
    OSSL_TIME start;
    uint64_t ms;
    int ret = 0;

    if ((certs = sk_X509_new_null()) == NULL
        || !sk_X509_push(certs, loop_cert_a)
        || !sk_X509_push(certs, loop_cert_b))
        goto end;

    start = ossl_time_now();
    if (idx == 0) {
        /* Explicit trusted stack, no store: a partial chain may be returned. */
        built = X509_build_chain(loop_leaf, certs, NULL, 0, NULL, NULL);
        ms = ossl_time2ms(ossl_time_subtract(ossl_time_now(), start));
        if (!TEST_uint64_t_le(ms, VERIFY_TIME_BUDGET_MS)
            || !TEST_ptr(built)
            || !TEST_int_le(sk_X509_num(built), DEFAULT_MAX_CHAIN))
            goto end;
    } else if (idx == 1) {
        /* With a store but no trusted issuer, no chain can be built. */
        if ((store = make_store(root_cert)) == NULL)
            goto end;
        built = X509_build_chain(loop_leaf, certs, store, 1, NULL, NULL);
        ms = ossl_time2ms(ossl_time_subtract(ossl_time_now(), start));
        if (!TEST_uint64_t_le(ms, VERIFY_TIME_BUDGET_MS)
            || !TEST_ptr_null(built))
            goto end;
    } else if (idx == 2) {
        /* Same, but only one of the loop members is offered. */
        STACK_OF(X509) *one = NULL;

        if ((store = make_store(root_cert)) == NULL
            || (one = sk_X509_new_null()) == NULL
            || !sk_X509_push(one, loop_cert_a))
            goto end;
        built = X509_build_chain(loop_leaf, one, store, 1, NULL, NULL);
        ms = ossl_time2ms(ossl_time_subtract(ossl_time_now(), start));
        sk_X509_free(one);
        if (!TEST_uint64_t_le(ms, VERIFY_TIME_BUDGET_MS)
            || !TEST_ptr_null(built))
            goto end;
    } else {
        goto end;
    }

    ret = 1;
end:
    /*
     * X509_build_chain() returns a stack of up-ref'ed certificates, so the
     * elements must be freed as well as the stack itself.
     */
    OSSL_STACK_OF_X509_free(built);
    sk_X509_free(certs);
    X509_STORE_free(store);
    ERR_clear_error();
    return ret;
}

/* ------------------------------------------------------------------ */
/* TLS client and server verification entry points                    */
/* ------------------------------------------------------------------ */

#ifndef OPENSSL_NO_TLS1_2

/*
 * Run a TLS handshake in which one peer verifies the other peer's certificate
 * chain.  |peer_cert|/|peer_key|/|peer_chain| are installed on the side whose
 * certificate is being verified; |anchor| is put in the verifier's trust
 * store.  Returns 1 if the handshake completed or aborted with a TLS alert,
 * 0 if it failed for any other reason (the caller inspects the verification
 * result to tell these apart).
 */
static int run_tls_handshake(int client_verifies, X509 *peer_cert,
    EVP_PKEY *peer_key, STACK_OF(X509) *peer_chain, X509 *anchor, int depth,
    long *verify_result, int *elapsed_ok)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    X509_STORE *store = NULL;
    SSL *verifier;
    OSSL_TIME start;
    uint64_t ms;
    int ret = 0, success;

    *verify_result = -1;
    *elapsed_ok = 0;

    start = ossl_time_now();
    if (!create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
            TLS1_2_VERSION, 0, &sctx, &cctx, NULL, NULL)
        || (store = make_store(anchor)) == NULL)
        goto end;

    if (client_verifies) {
        if (!SSL_CTX_set1_verify_cert_store(cctx, store))
            goto end;
        SSL_CTX_set_verify(cctx, SSL_VERIFY_PEER, NULL);
        SSL_CTX_set_verify_depth(cctx, depth);
    } else {
        if (!SSL_CTX_set1_verify_cert_store(sctx, store))
            goto end;
        SSL_CTX_set_verify(sctx,
            SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        SSL_CTX_set_verify_depth(sctx, depth);
    }

    if (!create_ssl_objects(sctx, cctx, &serverssl, &clientssl, NULL, NULL))
        goto end;
    verifier = client_verifies ? clientssl : serverssl;

    /*
     * Install the certificates being tested.  When the client is the
     * verifier the server carries the chain under test; when the server is
     * the verifier the client carries it.  A server always needs a
     * certificate of its own, so it uses the dedicated fixture unless it is
     * the side being verified.
     */
    if (client_verifies) {
        if (!SSL_use_certificate(serverssl, peer_cert)
            || !SSL_use_PrivateKey(serverssl, peer_key)
            || (peer_chain != NULL && !SSL_set1_chain(serverssl, peer_chain)))
            goto end;
    } else {
        if (!SSL_use_certificate(clientssl, peer_cert)
            || !SSL_use_PrivateKey(clientssl, peer_key)
            || (peer_chain != NULL && !SSL_set1_chain(clientssl, peer_chain))
            || !SSL_use_certificate(serverssl, server_cert)
            || !SSL_use_PrivateKey(serverssl, server_key))
            goto end;
    }

    /*
     * For a chain that cannot verify we expect the handshake to abort with a
     * TLS alert, i.e. SSL_ERROR_SSL on the side that noticed it.  For a chain
     * that should verify we expect a full handshake.
     */
    success = create_bare_ssl_connection(serverssl, clientssl, SSL_ERROR_SSL,
        0, 0);
    ms = ossl_time2ms(ossl_time_subtract(ossl_time_now(), start));
    *verify_result = SSL_get_verify_result(verifier);
    *elapsed_ok = ms <= VERIFY_TIME_BUDGET_MS;
    ERR_clear_error();
    ret = success;

end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    X509_STORE_free(store);
    return ret;
}

/*
 * A cyclic chain offered by the server must be rejected by the client.  The
 * depth limit determines which of the two failure modes is reached first:
 * with a limit smaller than the loop it is CERT_CHAIN_TOO_LONG, otherwise the
 * loop is exhausted and UNABLE_TO_GET_ISSUER_CERT_LOCALLY is reported.  Both
 * are failures; neither is a successful verification.
 */
static const struct {
    int depth;
    long expected_error;
} tls_loop_cases[] = {
    { -1,  X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY },
    { 100, X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY },
    { 2,   X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY },
    { 0,   X509_V_ERR_CERT_CHAIN_TOO_LONG },
    { 1,   X509_V_ERR_CERT_CHAIN_TOO_LONG },
};

static int test_tls_client_rejects_loop(int idx)
{
    STACK_OF(X509) *chain = NULL;
    long verify_result;
    int elapsed_ok;
    int connected;
    long expected_error;
    int ret = 0;

    if (idx < 0 || idx >= (int)OSSL_NELEM(tls_loop_cases))
        return 0;
    expected_error = tls_loop_cases[idx].expected_error;
    if ((chain = sk_X509_new_null()) == NULL
        || !sk_X509_push(chain, loop_cert_a)
        || !sk_X509_push(chain, loop_cert_b))
        goto end;

    connected = run_tls_handshake(1, loop_leaf, loop_leaf_key, chain,
        root_cert, tls_loop_cases[idx].depth, &verify_result, &elapsed_ok);

    if (!TEST_true(elapsed_ok)
        /* The handshake must not complete... */
        || !TEST_false(connected)
        /* ...and the reason must be the failed verification of a loop. */
        || !TEST_long_ne(verify_result, X509_V_OK)
        || !TEST_long_eq(verify_result, expected_error))
        goto end;

    ret = 1;
end:
    sk_X509_free(chain);
    return ret;
}

/* A cyclic chain offered by the client must be rejected by the server. */
static int test_tls_server_rejects_loop(int idx)
{
    STACK_OF(X509) *chain = NULL;
    long verify_result;
    int elapsed_ok;
    int connected;
    long expected_error;
    int ret = 0;

    if (idx < 0 || idx >= (int)OSSL_NELEM(tls_loop_cases))
        return 0;
    expected_error = tls_loop_cases[idx].expected_error;
    if ((chain = sk_X509_new_null()) == NULL
        || !sk_X509_push(chain, loop_cert_a)
        || !sk_X509_push(chain, loop_cert_b))
        goto end;

    connected = run_tls_handshake(0, loop_leaf, loop_leaf_key, chain,
        root_cert, tls_loop_cases[idx].depth, &verify_result, &elapsed_ok);

    if (!TEST_true(elapsed_ok)
        || !TEST_false(connected)
        || !TEST_long_eq(verify_result, expected_error))
        goto end;

    ret = 1;
end:
    sk_X509_free(chain);
    return ret;
}

/*
 * A legal chain offered over TLS verifies on both entry points when the depth
 * is sufficient, and is rejected as too long when it is not.
 */
static int test_tls_client_accepts_legal_chain(int idx)
{
    STACK_OF(X509) *chain = NULL;
    long verify_result;
    int elapsed_ok;
    int connected;
    int depth = idx == 0 ? LEGAL_INTERMEDIATES : LEGAL_INTERMEDIATES - 1;
    int expect_ok = idx == 0;
    int ret = 0;

    if (idx < 0 || idx > 1)
        return 0;
    if ((chain = sk_X509_new_null()) == NULL
        || !push_array(chain, legal_certs, LEGAL_INTERMEDIATES))
        goto end;

    connected = run_tls_handshake(1, legal_leaf, legal_leaf_key, chain,
        root_cert, depth, &verify_result, &elapsed_ok);

    if (!TEST_true(elapsed_ok))
        goto end;
    if (expect_ok) {
        if (!TEST_true(connected)
            || !TEST_long_eq(verify_result, X509_V_OK))
            goto end;
    } else {
        if (!TEST_false(connected)
            || !TEST_long_eq(verify_result,
                X509_V_ERR_CERT_CHAIN_TOO_LONG))
            goto end;
    }

    ret = 1;
end:
    sk_X509_free(chain);
    return ret;
}

static int test_tls_server_accepts_legal_chain(int idx)
{
    STACK_OF(X509) *chain = NULL;
    long verify_result;
    int elapsed_ok;
    int connected;
    int depth = idx == 0 ? LEGAL_INTERMEDIATES : LEGAL_INTERMEDIATES - 1;
    int expect_ok = idx == 0;
    int ret = 0;

    if (idx < 0 || idx > 1)
        return 0;
    if ((chain = sk_X509_new_null()) == NULL
        || !push_array(chain, legal_certs, LEGAL_INTERMEDIATES))
        goto end;

    connected = run_tls_handshake(0, legal_leaf, legal_leaf_key, chain,
        root_cert, depth, &verify_result, &elapsed_ok);

    if (!TEST_true(elapsed_ok))
        goto end;
    if (expect_ok) {
        if (!TEST_true(connected)
            || !TEST_long_eq(verify_result, X509_V_OK))
            goto end;
    } else {
        if (!TEST_false(connected)
            || !TEST_long_eq(verify_result,
                X509_V_ERR_CERT_CHAIN_TOO_LONG))
            goto end;
    }

    ret = 1;
end:
    sk_X509_free(chain);
    return ret;
}

#endif /* !OPENSSL_NO_TLS1_2 */

/* ------------------------------------------------------------------ */
/* Purpose profiles                                                   */
/* ------------------------------------------------------------------ */

/*
 * Purpose and profile selection must not change how a loop is handled:
 * whichever purpose is requested, the loop is still rejected with the
 * issuer-not-found error and the chain never exceeds the depth limit.
 */
static const struct {
    const char *profile; /* NULL: leave the default profile alone */
    int purpose;         /* -1: leave the purpose alone */
} loop_purpose_cases[] = {
    { "ssl_client", -1 },
    { "ssl_server", -1 },
    { "default", -1 },
    { NULL, X509_PURPOSE_SSL_SERVER },
    { NULL, X509_PURPOSE_SSL_CLIENT },
    { NULL, X509_PURPOSE_ANY },
};

static int test_loop_purpose_profiles(int idx)
{
    X509_STORE *store = NULL;
    STACK_OF(X509) *untrusted = NULL;
    verify_result res;
    int ret = 0;

    if (idx < 0 || idx >= (int)OSSL_NELEM(loop_purpose_cases))
        return 0;
    if ((store = make_store(root_cert)) == NULL
        || (untrusted = sk_X509_new_null()) == NULL
        || !sk_X509_push(untrusted, loop_cert_a)
        || !sk_X509_push(untrusted, loop_cert_b))
        goto end;

    res = verify_cert(loop_leaf, untrusted, store, NULL, -1,
        loop_purpose_cases[idx].profile, loop_purpose_cases[idx].purpose, 0, 0);
    if (!check_loop_failure(&res, -1,
            X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY))
        goto end;

    ret = 1;
end:
    X509_STORE_free(store);
    sk_X509_free(untrusted);
    return ret;
}

/* ------------------------------------------------------------------ */
/* Test driver                                                        */
/* ------------------------------------------------------------------ */

OPT_TEST_DECLARE_USAGE("")

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }
    if (!setup_fixtures()) {
        TEST_error("Failed to create test certificates\n");
        return 0;
    }

#if !defined(OPENSSL_SYS_WINDOWS)
    /*
     * Fail quickly, and with a clear message, if chain building ever stops
     * making progress instead of hanging the test harness.
     */
    watchdog_start(WATCHDOG_SECONDS);
#endif

    ADD_ALL_TESTS(test_short_loop, OSSL_NELEM(short_loop_cases));
    ADD_TEST(test_short_loop_chain_is_unique);
    ADD_TEST(test_repeated_loop);
    ADD_TEST(test_repeated_legal_chain);
    ADD_ALL_TESTS(test_long_loop, OSSL_NELEM(long_loop_depths));
    ADD_ALL_TESTS(test_loop_in_store, OSSL_NELEM(store_loop_depths));
    ADD_ALL_TESTS(test_loop_in_store_flags, 4);
    ADD_ALL_TESTS(test_legal_chain_depth, LEGAL_INTERMEDIATES + 2);
    ADD_TEST(test_legal_chain_trusted_stack);
    ADD_TEST(test_loop_member_explicitly_trusted);
    ADD_TEST(test_errors_are_distinguishable);
    ADD_ALL_TESTS(test_build_chain_loop, 3);
    ADD_ALL_TESTS(test_loop_purpose_profiles,
        OSSL_NELEM(loop_purpose_cases));
#ifndef OPENSSL_NO_TLS1_2
    ADD_ALL_TESTS(test_tls_client_rejects_loop, OSSL_NELEM(tls_loop_cases));
    ADD_ALL_TESTS(test_tls_server_rejects_loop, OSSL_NELEM(tls_loop_cases));
    ADD_ALL_TESTS(test_tls_client_accepts_legal_chain, 2);
    ADD_ALL_TESTS(test_tls_server_accepts_legal_chain, 2);
#endif
    return 1;
}

void cleanup_tests(void)
{
#if !defined(OPENSSL_SYS_WINDOWS)
    watchdog_stop();
#endif
    free_fixtures();
}
