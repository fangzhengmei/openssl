# ASN.1 Length-Field Rejection Analysis

Scope: OpenSSL 4.2.0-dev (`task/63`, commit `0cb912a`).
Question: what happens when an attacker controls an ASN.1 length field — overlong
(non-minimal) encodings, truncated length fields, or values far larger than the
input buffer — at the certificate entry, key entry, and generic ASN.1 entry?

All findings below were reproduced against a local `--debug` build of this tree
(`./Configure --debug && make -j`) with hand-built DER samples and tree-aware
mutated copies of real test certificates/keys. Nothing was assumed from the DER
spec alone; every verdict is an observed decoder result.

---

## 0. TL;DR

| Concern | Verdict |
|---|---|
| Non-minimal (overlong) length encoding | **Accepted everywhere.** No DER minimality check exists in the length parser. This is the one real gap. |
| Length field truncated (too few length octets) | **Rejected** at the length parser before any allocation (`ASN1_R_HEADER_TOO_LONG`) — on every entry that actually descends to the field. Generic `ANY` decoding leaves `SEQUENCE`/`SET` content opaque and never sees a nested one (§3.3). |
| Length value far larger than input | **Rejected** by a `length > available` bound, at every entry and every depth that is inspected. No large allocation, no large read. |
| Legal long form (128..255, 256+, up to `LONG_MAX`) | **Accepted**, provided the bytes are actually present. |
| Error code distinguishes the two failures | **Partly.** Oversized-within-`LONG_MAX` gives `ASN1_R_TOO_LONG`; a truncated field *and* a 9-significant-octet field both give `ASN1_R_HEADER_TOO_LONG`. Not a reliable classifier (§2). |
| Allocation driven by attacker length | Never sized from the declared length on the direct (`d2i`) paths. On the streaming BIO paths the buffer grows to the *actual* bytes read, in bounded chunks. |
| Error-queue path | Rejections are *reported*, not just returned; but the queue is capped at 16 entries and some retrying entry points fill it with unrelated probe errors, hiding the real reason from the caller. |

The single tightening worth doing is a **DER minimality check on the length
field**, and it must be *opt-in per entry point* (see §5), because the same
parser also serves genuine BER callers.

---

## 1. Code map: length encoding, nesting, allocation, error path

### 1.1 Length decoding

`crypto/asn1/asn1_lib.c:42` `asn1_get_length()` is the only place a length
octet string is interpreted. `ASN1_get_object()` (`asn1_lib.c:72`) wraps it.

```c
if (max-- < 1)                      return 0;      /* no length octet at all  */
if (*p == 0x80) { *inf = 1; p++; }                 /* indefinite form         */
else {
    i = *p & 0x7f;                                 /* i = # of length octets  */
    if (*p++ & 0x80) {
        if (max < i)                return 0;      /* (A) field truncated     */
        while (i > 0 && *p == 0) { p++; i--; }     /* (B) skip leading zeroes */
        if (i > (int)sizeof(long))  return 0;      /* (C) too many octets     */
        while (i > 0) { ret <<= 8; ret |= *p++; i--; }
        if (ret > LONG_MAX)         return 0;      /* (D) value into sign bit */
    } else ret = i;
}
```

Two facts matter for the threat model:

* **(B) strips leading zero octets instead of rejecting them.** This is why a
  length field padded with dozens of zero octets *succeeds* rather than fails.
  It is the mechanism behind both the `nonmin*` and `lenoct*_zero` results.
* There is **no check that the encoding is the shortest possible**. `0x81 0x05`
  decodes to 5 exactly like `0x05` does, with no complaint. This is the
  non-minimal gap.

The `max` parameter is `omax - header bytes consumed so far`, so (A) cannot over-read:
the loop never advances past `max` octets.

### 1.2 Caller-side bound (`asn1_lib.c:120`)

```c
if (*plength > (omax - (p - *pp))) {        /* content longer than what's left */
    ERR_raise(ERR_LIB_ASN1, ASN1_R_TOO_LONG);
    ret |= 0x80;                            /* error bit, but plength is set   */
}
```

This is the whole "value far larger than input" defence. It runs *after* the
length is decoded, compares integers only, and touches no memory. Upstream,
`asn1_check_tlen()` (`tasn_dec.c:1183`) re-checks the same relation after
accounting for the header (`tasn_dec.c:1218`) and turns the error bit into
`ASN1_R_BAD_OBJECT_HEADER`.

### 1.3 Nested-object boundaries

`asn1_item_embed_d2i()` (`tasn_dec.c:188`) carries a `len` that is the number of
bytes the *parent* still owns. Each child is decoded with that remaining `len`,
and after it returns the parent does `len -= (long)(p - q)` (`tasn_dec.c:461`).
So a child can never legally consume more than the parent declared, and every
recursive call is depth-limited (`ASN1_MAX_CONSTRUCTED_NEST 30`, `tasn_dec.c:27`,
`:221`). Constructed-string recursion has its own separate limit
(`ASN1_MAX_STRING_NEST 5`, `tasn_dec.c:1080`).

The `ASN1_TLC` cache (`struct ASN1_TLC_st`, `asn1t.h:608`) short-circuits a
second header parse when tag matches. When the cache is reused, the `> len`
check at `tasn_dec.c:1218` is *not* re-run — the first parse already validated it
and `asn1_tlc_clear()` runs on tag match. That ordering is relied on; it is not
a hole, but it does mean the bound is enforced once per header, not once per
access.

### 1.4 Allocation

Nothing on the direct path allocates using the declared length:

* `asn1_ex_c2i()` (`tasn_dec.c:858`) copies `len` bytes out of the *already
  bounded* content region via `ossl_asn1_string_set1_data`, which rejects
  `len > INT_MAX` (`asn1_lib.c:512`).
* `ossl_c2i_ASN1_INTEGER` strips *illegal* padding (`ILLEGAL_PADDING`, `a_int.c:192`) then
  allocates `r`, the stripped length.
* `collect_data()` (`tasn_dec.c:1140`) is the only growth-from-length site:
  `BUF_MEM_grow_clean(buf, len + plen)` with an explicit `len + plen < 0`
  overflow guard. It still only copies `plen` bytes from the input, and
  `plen` has already passed the caller bound.

The streaming reader `asn1_d2i_read_bio()` (`a_d2i_fp.c:110`) is the other site,
and it is deliberately written *not* to trust the declared length: it grows in
chunks from 16 kB, doubling, stopping at the first `BIO_read` that returns EOF
(`a_d2i_fp.c:255–300`). This is explicitly commented at `a_d2i_fp.c:236`.

### 1.5 Error path

`ERR_raise` appends to a per-thread queue capped at `ERR_NUM_ERRORS 16`
(`include/internal/err.h:14`). The queue is **circular and drops the oldest** entry
when full. `d2i_AutoPrivateKey` and the provider decoder chain probe several
structures in a row, each failing and raising; by the time a huge length is
finally reported, up to ten unrelated "wrong tag"/"nested" errors precede it.
The *innermost, most specific* error is the one at the `ERR_raise` site and
therefore is present, but the *first* error a naive caller reads may be a
generic probe failure. This was directly observed (see §3.4).

---

## 2. Rejection taxonomy, with the exact byte that trips it

Built from `/tmp/asn1len-samples/handmade/` — each sample isolates one boundary.

| Class | Sample | `ASN1_get_object` result | Error raised at | Error code |
|---|---|---|---|---|
| Legal short | `ok_short_len` (`30 03 02 01 00`) | accept, len=3 | — | — |
| Legal long, minimal | `ok_long_80` (`... 04 81 80 ...`) | accept, len=128 | — | — |
| Legal long, minimal | `ok_long_100` (`... 04 82 01 00 ...`) | accept, len=256 | — | — |
| Legal long, large (minimal) | `legalbig_8M_min` (`30 83 80 00 00 ...`) | accept, len=8388608 | — | — |
| **Non-minimal at scale** | `legalbig_8M` (`30 84 00 80 00 00 ...`) | **accept**, len=8388608 | — | — |
| **Non-minimal, short value** | `nonmin_len_81_for_3` (`30 81 03 ...`) | **accept, len=3** | — | — |
| **Non-minimal, zero-padded** | `nonmin_len_82_zero_pad` (`30 82 00 03 ...`) | **accept, len=3** | — | — |
| **Non-minimal, 8-octet field** | `nonmin_len_88_zero_pad` | **accept, len=3** | — | — |
| **Non-minimal long→longer long** | `nonmin_len_128_as_82` (`30 82 00 80 ...`) | **accept, len=128** | — | — |
| **Truncated field, 0 octets of 2** | `trunc_len_no_octets` (`30 82`) | **reject** | `asn1_lib.c:131` (`err:`) | `ASN1_R_HEADER_TOO_LONG` (123) |
| **Truncated field, 1 octet of 2** | `trunc_len_one_octet` (`30 82 01`) | **reject** | `asn1_lib.c:131` | `ASN1_R_HEADER_TOO_LONG` |
| **Truncated field, 2 octets of 4** | `trunc_len_84` | **reject** | `asn1_lib.c:131` | `ASN1_R_HEADER_TOO_LONG` |
| 9 *significant* length octets | `lenoct_9_significant` | **reject** | `asn1_lib.c:131` | `ASN1_R_HEADER_TOO_LONG` |
| 127 *significant* length octets | `lenoct_127_significant` | **reject** | `asn1_lib.c:131` | `ASN1_R_HEADER_TOO_LONG` |
| **9..127 *zero* length octets** | `lenoct_9_zero`, `lenoct_127_zero` | **accept, len=0** | — | — |
| Huge value 2^31 | `huge_2^31` | **reject** | `asn1_lib.c:121` | `ASN1_R_TOO_LONG` (155) |
| Huge value 2^32-1 | `huge_2^32-1` | **reject** | `asn1_lib.c:121` | `ASN1_R_TOO_LONG` |
| Huge value exactly LONG_MAX | `huge_2^63-1` | **reject** | `asn1_lib.c:121` | `ASN1_R_TOO_LONG` |
| Value LONG_MAX+1 | `huge_2^63` | **reject** | `asn1_lib.c:131` | `ASN1_R_HEADER_TOO_LONG` |
| Content truncated after header | `trunc_len_at_eof` | **reject** | `asn1_lib.c:121` | `ASN1_R_TOO_LONG` |
| Indefinite-length primitive | `indef_primitive` | **reject** | `asn1_lib.c:117` | `ASN1_R_HEADER_TOO_LONG` |

Two observations that do not fit the naive "truncated vs huge" split:

1. **Truncated and 9-significant-octet cases share `HEADER_TOO_LONG`**, because
   both exit through the single `err:` label at `asn1_lib.c:131`. So the error
   code does not distinguish "field cut off" from "field absurdly wide". A
   caller cannot tell the two apart from reason code alone.
2. **`LONG_MAX` and `LONG_MAX+1` produce different reason codes** (`TOO_LONG` vs
   `HEADER_TOO_LONG`) — again a consequence of which `return 0` fires, not a
   designed distinction.

### 2.1 Legal long form is genuinely accepted

`ok_long_7f` through `ok_long_100`, plus `legalbig_8M_min`, all decode and
consume exactly the expected bytes with the error queue empty. Any tightening
must preserve these — this is the hard constraint on §5.

A useful near-miss: the first 8 MB sample built for this study used
`30 84 00 80 00 00` — four length octets for a value of `0x800000`, which needs
only three. The decoder **accepted it**, and so did `d2i_ASN1_TYPE` and the BIO
reader. That is the non-minimality gap reproducing at multi-megabyte scale on a
sample that was written believing it was legal. `legalbig_8M_min`
(`30 83 80 00 00`) is the corrected, genuinely minimal version; both are
accepted, which is exactly why the gap is easy to miss.

---

## 3. Entry-point matrix (observed)

Corpus: 177 mutated cert files (15 target nodes × up to 14 length variants),
46 mutated key files (4 nodes × up to 14), and 60 hand-built minimal samples —
283 DER files, 2992 (sample, entry) observations across 11 entries. "REJECT"
below always means the entry returned failure *and* left at least one error
queued.

### 3.0 A caveat on the mutation labels

The tree mutator rewrites a length field in place and leaves the rest of the
file intact. For the `trunclen*` variants that means the *following* content
bytes get consumed as length octets rather than the file ending early:

* `top__trunclen0` (`30 84 30 82 02 69 ...`) declares 4 length octets and
  therefore reads `30 82 02 69` as the value → **813,826,665**, an oversized
  value, not a truncation.
* `top__trunclen1` (`30 82 01 30 82 ...`) declares 2 length octets and reads
  `01 30` → **304**, a value that still fits, so it may be accepted.

True truncation — where the file genuinely ends inside or just after the
length field — is covered only by the hand-built samples (`trunc_len_no_octets`,
`trunc_len_one_octet`, `trunc_len_84`, `trunc_len_88`, `trunc_len_at_eof`).
Claims below are attributed to whichever set actually demonstrates them. Note
that `top__trunclen1` being accepted (308 of 900 bytes consumed by
`d2i_ASN1_TYPE`) is an *oversized-but-fitting* value, and the trailing bytes
are simply left unconsumed by that entry — not evidence about truncation.

### 3.1 Certificate entry — `d2i_X509`

Reproduced rejections and where they surface:

| Variant (target node) | Result | Deepest ASN.1 error | Location |
|---|---|---|---|
| `top__huge32` | REJECT | `too long` | `asn1_lib.c:121` → `tasn_dec.c:1226` → `tasn_dec.c:375` |
| `top__trunclen0` | REJECT | `too long` | `TOO_LONG` at `asn1_lib.c:121` (the in-place mutation yields a huge value, see §3.0) |
| `top__trunclen1` | (not shown here; accepted by generic entries, see §3.3) | — | value `304` fits in the file |
| hand-built `trunc_len_no_octets`/`_84`/`_88` | REJECT | `header too long` | `asn1_lib.c:131` |
| `top__lenoct9` | REJECT | `field missing` | `tasn_dec.c:491` (`Field=cert_info, Type=X509`) |
| `top__nonminpad` | **ACCEPT** | — | — |
| any `*__nonmin*` / `*__validlong` | **ACCEPT** whenever the unmutated node was accepted | — | — |
| `issuer__huge32` | REJECT | `too long` | `asn1_lib.c:121` → `tasn_dec.c:639` (`asn1_template_noexp_d2i`) |
| `spki__huge32` | REJECT | `too long` | nested under `Field=key, Type=X509_CINF` |

Key point for `d2i_X509`: **no oversized length is ever accepted** (0/19 for
every `huge*` and `trunclen0` site — the latter is also a huge value per §3.0),
and **every non-minimal variant that was legal without the mutation stays
accepted** — 14/14 cert sites and 8/8 key sites whose `validlong` baseline
decoded, i.e. not one rejection was caused by non-minimality at any level.
True truncation rejection is shown by the hand-built samples (§2), which fail
with `ASN1_R_HEADER_TOO_LONG` at the parser. Certificate parsing therefore
inherits the parser's minimality-blindness wholesale, while being strict about
oversize and about genuinely truncated length fields.

### 3.2 Key entry — `d2i_PKCS8_PRIV_KEY_INFO` / `d2i_AutoPrivateKey`

Same shape. `d2i_PKCS8_PRIV_KEY_INFO` accepts `top__nonmin*` and
`version__nonmin*` — 4/4 key sites and 1/1 cert site whose baseline decoded,
with no non-minimality rejection anywhere — and reports:
`too long` at `asn1_lib.c:121` for oversized, `field missing` at
`tasn_dec.c:491` (`Field=version`) for the zero-padded-overwide field, and
`illegal zero content` at `a_int.c:160` when the zero-padding collapses a
1-octet INTEGER length to 0.

`d2i_AutoPrivateKey` reports `unsupported` from `OSSL_DECODER_from_bio`
(`crypto/encode_decode/decoder_lib.c:105`, raised at `:104`) for **every**
malformed input including the huge-length ones — the real `too long`/`header
too long` errors are still beneath it on the queue, but the entry-level reason
is generic. This is the error-queue visibility problem of §1.5 in practice: the
caller-visible reason is the probe outcome, not the length rejection. It also
means a caller that only inspects the *reason string* cannot distinguish
"malformed length" from "wrong key type".

### 3.3 Generic ASN.1 entry — `d2i_ASN1_TYPE`, `d2i_ASN1_SEQUENCE_ANY`, `ASN1_parse`

**This is where the entries diverge sharply, and where a naive reading of the
results will mislead you.**

`d2i_ASN1_TYPE` (ANY) only validates the header of *one* TLV, and only descends
into constructed *string* types. For `SEQUENCE` and `SET` it deliberately keeps
the content as an opaque blob (`tasn_dec.c:784–809`: "SEQUENCE, SET and OTHER
are left in encoded form"), so malformed lengths *inside* those are never
examined:

| Sample | `d2i_ASN1_TYPE` | Why |
|---|---|---|
| `plain_seq_bad_child` (`30 07 04 84 ff ff ff ff 41`) | **ACCEPT** | SEQUENCE content stored opaque; bad child never parsed |
| `set_bad_child` | **ACCEPT** | SET stored opaque |
| `d3_nested_int_huge_repaired` | **ACCEPT** | three SEQUENCEs of opaque blobs |
| `cons_octet_def_bad_child` (`24 07 04 84 ...`) | **REJECT** `too long` | constructed string *is* walked by `asn1_collect` (`tasn_dec.c:826`) |
| `top__trunclen1` / `top__lenoct9` (outer header malformed) | see below | header itself is validated |

So the 19-site matrix counts for ANY must be read as "outer header valid, inner
content not inspected". At the *outer* header, ANY rejected `trunclen0`
(17/19 accepted, i.e. only the `top` node rejected — and that case is a huge
value per §3.0, not a truncation), rejected `huge32` at the same 17/19, and
accepted `trunclen1` and `lenoct9` at 19/19 for the reasons in §3.0 and §1.1
respectively. The clean statement of the entry-specific rule is the
hand-built pair below, not the in-place mutation counts.

`d2i_ASN1_SEQUENCE_ANY` *does* recurse (`TFLG_SEQUENCE_OF` over `ASN1_ANY`), so
it catches malformed lengths one level in but still stops at the same opaque
boundary two levels down:

| Sample | `d2i_ASN1_SEQUENCE_ANY` |
|---|---|
| `d1_child_int_huge_repaired` (bad child directly inside outer SEQ) | **REJECT** `too long` |
| `d2_nested_int_huge_repaired` (bad child two levels down) | **ACCEPT** — inner SEQ opaque |
| `d3_nested_int_huge_repaired` | **ACCEPT** |
| `lenoct9`/`lenoct127` in matrix | 17/19 accepted (zero-padding collapses to 0) |

`ASN1_parse` walks the tree itself with a 128-frame budget and its own bound at
`asn1_parse.c:139`; it rejected `trunclen0` and `huge32` at 0/19 but accepted
`lenoct9` at 14/19 (it prints a zero-length element rather than rejecting the
padding).

Conclusion: **a result obtained through `d2i_ASN1_TYPE`, `d2i_ASN1_SEQUENCE_ANY`
or `ASN1_parse` does not transfer to `d2i_X509` or the key entries.** The
structured decoders are strictly stricter than the generic ones, because they
know the nested template and therefore descend; the generic ones leave
`SEQUENCE`/`SET` opaque. This asymmetry runs in the *safe* direction (generic
acceptance is not evidence that the cert decoder accepts), but it means the
generic entries cannot be used as a proxy for the structured ones.

### 3.4 Streaming (BIO) entry — `d2i_X509_bio`, `d2i_PKCS8_PRIV_KEY_INFO_bio`

These use `asn1_d2i_read_bio`, which *pre-checks* the length before allocating:

| Variant | Result | Location |
|---|---|---|
| `top__huge32` (2^32-1 > INT_MAX) | REJECT `too long` | `a_d2i_fp.c:264` (`asn1_d2i_read_bio`, `want > INT_MAX`) |
| `streambig_over_intmax` (2^31) | REJECT `too long` | `a_d2i_fp.c:264` |
| `streambig_16M`/`256M`/`2G` (≤ INT_MAX, input tiny) | REJECT `not enough data` | `a_d2i_fp.c:285` — chunked read hit EOF |
| `streambig_2^63-1` shares the 2^63 split of §2 | `header too long` | `asn1_lib.c:131` first |

The chunked read is why a 2 GB *declaration* over a 9-byte input fails in
**0.003 ms with a 0 kB peak RSS delta** — it reads 16 kB, gets EOF, and stops.
This is the strongest anti-allocation property in the whole set.

---

## 4. Time and memory observations

Environment: 12 vCPU, `--debug` build, measurements are best-of-run after a
warm-up decode of the same entry, `drss` from `/proc/self/statm`,
`peak` from `getrusage(RUSAGE_SELF).ru_maxrss`.

Representative figures (full TSV captured in `cert.tsv`, `key.tsv`,
`handmade.tsv`):

| Input | Entry | Time | Peak RSS Δ |
|---|---|---|---|
| `huge_2^32-1` (9 B input, 2^32-1 declared) | `d2i_X509` | 0.003 ms | 0 kB |
| `huge_2^32-1` | `d2i_X509_bio` | 0.003 ms | 0 kB |
| `top__huge32` (903 B cert, 2^32-1 declared at the top) | `d2i_X509` | 0.003 ms | 0 kB |
| `streambig_256M` (256 MB declared, tiny input) | `d2i_X509_bio` | 0.004 ms | 0 kB |
| `top__nonminpad` (accepted) | `d2i_X509` | 0.047 ms | 0 kB |
| valid `alt1-cert.der` (901 B) | `d2i_X509` | 0.047 ms | 0 kB |
| `legalbig_8M_min` (8 MB, minimal, legal) | `d2i_ASN1_TYPE` | 3.5 ms | +8192 kB |
| `legalbig_8M` (8 MB, 4-octet length where 3 suffice) | `d2i_ASN1_TYPE` | 3.5 ms | +8192 kB |

The decisive result: **the cost of rejecting an oversized length does not
scale with the declared value.** A 2^32-1 declaration costs the same as a
2^31 one — sub-microsecond, no allocation — because the bound is an integer
comparison before any copy. Allocating work is observed only for
*legal* large objects (`legalbig_8M_min`, +8 MB, proportional to real bytes).
(The `legalbig_8M` row is included to show the cost is identical when only the
length *encoding* is bloated — the non-minimality itself costs nothing to
process, which is part of why it goes unnoticed.)

Two caveats on these numbers:

* `d2i_AutoPrivateKey` and the provider decoder chain repeatedly show
  50–120 ms on inputs that other entries handle in microseconds (`top__huge32`
  on a cert took 0.12 ms via `d2i_AutoPrivateKey` vs 0.002 ms via `d2i_X509`,
  and `legalbig_8M_min` took 119 ms). That is **decoder-chain retry cost**, not
  length-handling cost — many provider decoders each attempt and fail. It is
  attacker-influencable (a caller that invokes `d2i_AutoPrivateKey`
  on untrusted input pays it) but it is not specific to malformed lengths.
* `drss`/`peak` in these tables are process-lifetime maxima, so a `+0 kB`
  row does not prove a single decode allocated nothing; it proves nothing
  above the prior high-water mark was touched. In every oversized-length case
  the *code path* also demonstrably allocates nothing (§1.4), and the streaming
  cases were additionally confirmed by the `not enough data` outcome
  (chunked read, no full-size allocation).

---

## 5. Tightening proposal that does not break legal long objects

### 5.1 What to check, and where

The gap is precisely one predicate: **is the length field the shortest
encoding of the value it carries?** It belongs in `asn1_get_length()`,
`crypto/asn1/asn1_lib.c:142`, because that is the single chokepoint every entry
passes through.

Concrete rule (DER, X.690 8.1.3.5 / 10.1):

* short form `0x00..0x7f` — always minimal.
* long form `0x8n`:
  * **forbid a leading zero octet** — `n >= 2 && p[0] == 0` is non-minimal;
    *all* zero-octet fields beyond `n == 0` similarly;
  * **forbid `n == 1 && value < 0x80`** — that value has a short form;
  * forbid `n == 0` (that is the indefinite marker `0x80`, handled separately);
  * allow everything else, including `n == 1 && value >= 0x80`, `n == 2 && value
    >= 0x100`, and `n == 8` with a value ≤ `LONG_MAX`.

The prototype (§5.3) confirms this accepts `0x81 0x80`, `0x81 0xff`,
`0x82 0x01 0x00`, `0x84 0x80 0x00 0x00 0x00` and rejects `0x81 0x05`,
`0x82 0x00 0x05`, `0x84 00 00 00 03`, `0x88` + 7 zeros + `03`.

### 5.2 Why it must be opt-in, not global

`ASN1_get_object` is a public API also used by:

* `crypto/pkcs7/pk7_doit.c:88` — PKCS#7, where the stored structure may be BER;
* `apps/s_client.c:4151..4178` — TLS debug printing of received messages;
* `crypto/asn1/asn1_parse.c:120` — the generic printer, whose job is to
  *describe* BER as well as DER;
* `crypto/asn1/a_d2i_fp.c:229` — the streaming reader must accept
  indefinite length.

Making the check unconditional would regress PKCS#7 and the printer. The
correct shape is a flag threaded from the DER-only entry points:

```
 static int asn1_get_length(const unsigned char **pp, int *inf, long *rl,
-                           long max)
+                           long max, int strict_der)
```

and an accompanying `ASN1_get_object_ex(..., int flags)` — or, cheaper, gate it
on the existing internal `ASN1_TLC`-style context so that only the
`d2i_*` DER paths set it. Entry points that should set it: `asn1_check_tlen`
when decoding universal/known-tagged items (`tasn_dec.c:1183`), the certificate
and key d2i paths, and `X509_NAME` decoding. Entry points that must *not*: the
PKCS#7 data decoder and `ASN1_parse`.

A `ASN1_R_LENGTH_TOO_LONG` (already defined, `asn1err.h:83`) is the natural
reason code; today it is used only by `collect_data` and the OID decoder.

### 5.3 Prototype verification

`/tmp/asn1len-harness/proto_len.c` mirrors the real parser with the proposed
predicate and reports it:

```
short 3                    ok=1 len=3            nonminimal=0
short 127                  ok=1 len=127          nonminimal=0
long 81 80 (minimal)       ok=1 len=128          nonminimal=0
long 81 ff (minimal)       ok=1 len=255          nonminimal=0
long 82 01 00 (min)        ok=1 len=256          nonminimal=0
long 81 05 (NONMIN)        ok=1 len=5            nonminimal=1   <- rejected by patch
long 82 00 05 (NONMIN)     ok=1 len=5            nonminimal=1   <- rejected by patch
long 84 00 00 00 03        ok=1 len=3            nonminimal=1   <- rejected by patch
long 88 + 7 zeros +3       ok=1 len=3            nonminimal=1   <- rejected by patch
long 84 80 00 00 00        ok=1 len=2147483648   nonminimal=0
```

The predicate never fires on a legal long form in the corpus (including
`ok_long_80`, `ok_long_ff`, `ok_long_100`, `legalbig_8M_min`), and fires on
*every* non-minimal sample generated — including `legalbig_8M`, which was
originally written as a legal control and turned out to be non-minimal (§2.1).
It also correctly declines to decide on truncated fields
(`trunc_len_no_octets`), leaving those to the existing rejection path. Because
the check is a pure comparison on already bounds-checked bytes, it adds no
allocation and no over-read.

### 5.4 Residual risk if the patch is *not* made

Non-minimal lengths currently let a caller smuggle arbitrary header padding per
object: the `lenoct_127_zero` sample encodes a zero-length SEQUENCE in 132 bytes
instead of the minimal 2, i.e. 130 bytes of pure overhead accepted without
complaint. Two consequences worth naming:

* **Stable-hash / signature ambiguity.** Two byte-distinct encodings decode to
  the same structure. Anything that hashes or compares the *encoding* (rather
  than the parsed value) sees different bytes for equal semantics. OpenSSL's
  X.509 `X509_NAME` cache preserves original bytes (`x_name.c:180`), so this
  is at least observable, not silently normalised.
* **Policy bypass by "looks different but means the same"**, e.g. bypassing
  an exact-bytes denylist. The parser will happily accept it.

Neither is a memory-safety issue. Both are correctness/comparability issues
that a DER-only caller should not have to reason about.

---

## 6. Regression tests to add

All of the following already exist as byte arrays in
`/tmp/asn1len-samples/handmade/`; they need to be pasted into
`test/asn1_decode_test.c` (direct API) and `test/asn1_internal_test.c` (parser
boundary) and wired into their `ADD_TEST` lists.

**Parser boundary (`test/asn1_internal_test.c`, near the existing
`test_d2i_read_bio_*` family):**

1. `test_length_legal_long_forms` — `0x81 0x80`, `0x81 0xff`, `0x82 0x01 0x00`
   must decode with the exact expected length; error queue empty.
2. `test_length_nonminimal_rejected` — `0x81 0x05`, `0x82 0x00 0x05`,
   `0x84 00 00 00 03`, `0x88`+7 zeros+`03` must fail with `ASN1_R_LENGTH_TOO_LONG`.
3. `test_length_truncated_rejected` — `30 82`, `30 82 01`, `30 84 00 00` must
   fail with the code chosen in the patch, and must **not** read past the buffer.
4. `test_length_huge_value_rejected` — 2^31, 2^32-1, 2^63-1 → `ASN1_R_TOO_LONG`;
   2^63 → `ASN1_R_HEADER_TOO_LONG`; assert **no allocation** by checking
   that the parser is called directly rather than through a BIO.
5. `test_length_zeros_only_field` — 9 and 127 zero octets: assert the *post-patch*
   verdict (reject), recording that pre-patch this collapsed to length 0.
6. `test_length_boundary_long_max` — 2^63-1 accepted by the length parser
   (value fits and input present), rejected by the content bound.

**Entry-point tests (`test/asn1_decode_test.c`):**

7. `test_x509_nonminimal_length_rejected` — reuse a minimal `SEQUENCE{INTEGER}`,
   wrap it, and assert `d2i_X509`, `d2i_PKCS8_PRIV_KEY_INFO`, `d2i_ASN1_TYPE`
   all reject non-minimal with a *specific* reason (not just "some error").
8. `test_x509_huge_length_rejected` — the same entries on `huge_2^32-1`.
9. `test_streaming_huge_length_no_alloc` — `d2i_X509_bio` on
   `streambig_256M` returns failure with `ASN1_R_NOT_ENOUGH_DATA` or
   `ASN1_R_TOO_LONG` and the process RSS does not grow by more than a small
   bound; this pins the chunked-read property.
10. `test_ber_still_accepted` — indefinite-length `30 80 ... 00 00` and
    `seqany_child_seq_nonmin` must still be accepted by the *generic* entries
    (`d2i_ASN1_SEQUENCE_ANY`, `ASN1_parse`), proving the opt-in did not leak
    into BER callers.

**Property test (recommended, not just examples):**

11. A generate-and-check loop over length fields of width 1..128 and values
    0..2^32 that asserts: legal-minimal accepted; any `n >= 2` with leading
    zero rejected; `n == 1 && value < 0x80` rejected. This is what actually
    covers the 127-octet corner the hand-built samples only spot-check.

---

## 7. Which conclusions are entry-specific

Be careful quoting these outward; several do **not** generalise.

| Conclusion | Applies to | Does *not* apply to |
|---|---|---|
| Non-minimal length is accepted | every entry tested (cert, key, type, seq-any, parse, BIO) | — (this one is universal) |
| Truncated length field is rejected | the length parser itself, hence `d2i_X509`, `d2i_X509_PUBKEY`, `d2i_PUBKEY`, `d2i_PKCS8_PRIV_KEY_INFO`, BIO entries — shown by the hand-built `trunc_len_*` samples | **`d2i_ASN1_TYPE`** and **`d2i_ASN1_SEQUENCE_ANY`** when the truncated field is inside a constructed `SEQUENCE`/`SET`, which is kept opaque and never walked |
| Oversized length is rejected | all structured entries and BIO entries (0/19 for `huge*`) | generic `ANY`/`SEQUENCE_ANY` at depth ≥ 2, opaque content |
| `d2i_ASN1_TYPE` descends into any constructed type | never — it validates only the outer header, then stores `SEQUENCE`/`SET` as bytes | constructed *string* types, which it does walk (`asn1_collect`, `tasn_dec.c:826`) |
| Huge length is rejected without allocation | direct `d2i_*` and BIO entries | `d2i_AutoPrivateKey` reports only `unsupported`, hiding the real reason |
| Zero-padded length collapses to 0 | `ASN1_get_object`, `d2i_ASN1_TYPE`, `d2i_ASN1_SEQUENCE_ANY` | `d2i_X509`/key, where the parent then hits `FIELD_MISSING` (`tasn_dec.c:491`) |
| "Rejection is cheap, sub-microsecond" | oversized-length cases on `d2i_X509`, BIO reader | `d2i_AutoPrivateKey` / provider chain (50–120 ms retry cost, unrelated to length) |
| The `too long` vs `header too long` split means "oversized" vs "truncated" | not reliable in general | `LONG_MAX` maps to `TOO_LONG` while `LONG_MAX+1` maps to `HEADER_TOO_LONG`; and both a truncated field and a 9-significant-octet field map to `HEADER_TOO_LONG` |
| Depth limit bounds recursion cost | `d2i_*` item decode (`ASN1_MAX_CONSTRUCTED_NEST 30`) | `ASN1_parse` (`ASN1_PARSE_MAXDEPTH 128`) and constructed strings (`ASN1_MAX_STRING_NEST 5`) each have their *own*, different limit |
| No crash on adversarial lengths | all sampled mutations (901-prefix truncation sweep, 2000 random length-field mutations, 0 crashes) | fuzzing did not cover every structural path; treat "no crash observed" as evidence, not proof |

Also worth stating plainly: **`ASN1_parse` is a diagnostic printer.** It walks
BER intentionally and applies its length bound later (`asn1_parse.c:139`). A
reject/accept verdict from `openssl asn1parse` is not a statement about
`d2i_X509`, and the two disagreed on `lenoct9` in 5 of 19 sites during this
study.

---

## 8. Reproduction

Artifacts live outside the tree, in `/tmp/`, as untrusted-input practice:

* `/tmp/asn1len-harness/asn1len_probe.c` — entry-point probe; reports verdict,
  consumed/residual, error stack with `file:line`, ms, RSS delta.
* `/tmp/asn1len-harness/mutate.py` — tree-aware length mutator; rewrites one
  length field and repairs ancestors so the only illegal byte is the target.
* `/tmp/asn1len-harness/handmade.py` — the minimal boundary samples in §2.
* `/tmp/asn1len-harness/proto_len.c` — the proposed minimality predicate.
* `/tmp/asn1len-harness/collect.py` — runs the probe over a directory, emits TSV.
* `/tmp/asn1len-samples/{cert,key,handmade}/` — 283 generated DER files.
* `cert.tsv`, `key.tsv`, `handmade.tsv` — 2992 raw result rows.

The scratch harnesses are analysis tools only; none of them is wired into the
OpenSSL build, and the working tree is unchanged apart from this document
(`git status --short` shows only `?? asn1-length-rejection.md`).

Build and run:

```sh
./Configure --debug && make -j"$(nproc)"
gcc -O1 -I include -o /tmp/probe /tmp/asn1len-harness/asn1len_probe.c -L. -lcrypto
LD_LIBRARY_PATH=$PWD /tmp/probe /tmp/asn1len-samples/handmade/nonmin_len_81_for_3.der --verbose
```

Rebuilding the corpus:

```sh
python3 -I /tmp/asn1len-harness/handmade.py /tmp/asn1len-samples/handmade
python3 -I /tmp/asn1len-harness/mutate.py /tmp/asn1len-data/alt1-cert.der \
        /tmp/asn1len-samples/cert "[(0,'huge32','top'),(176,'huge32','spki'),(58,'nonmin1','utc')]"
```
