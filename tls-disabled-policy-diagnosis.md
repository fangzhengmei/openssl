# TLS 禁用算法策略失效诊断报告

> 诊断对象：OpenSSL 4.2.0-dev（本工作树，分支 `task/52`）
> 范围：算法策略从**配置解析 → CTX/SSL 状态 → 握手协商**的完整路径
> 方法：静态代码走查 + 本地自建证书与回环握手样本（无外部网络、无容器）
> 结论速览：故障分为**配置错误（5 类，可通过收紧配置/开启诊断规避）**与**实现缺陷（1 类，已给出最小修复并附回归测试）**。实现缺陷是 TLS 1.2/DTLS 1.2 会话恢复路径绕过新增的禁用/安全级别策略，是“安全级别变化后套件重新出现”的直接根因。

---

## 1. 策略管线全景（代码事实）

一个密码套件最终能否被协商，要依次穿过 5 道闸门；任何一道被绕过或误配，都会表现为“禁用后仍被选中”。

| # | 闸门 | 关键代码 | 作用 | 时机 |
|---|------|----------|------|------|
| G1 | 编译/Provider 可用性掩码 | `ssl/ssl_ciph.c:273 ssl_load_ciphers()` 生成 `disabled_{mkey,auth,enc,mac}_mask`；`ssl_cipher_collect_ciphers()` `ssl_ciph.c:635` 过滤 | Provider 取不到算法即整体剔除 | CTX 创建，一次性 |
| G2 | 规则字符串筛选（TLS 1.2 及更早） | `ssl_create_cipher_list()` `ssl_ciph.c:1422` → `ssl_cipher_process_rulestr()` `ssl_ciph.c:952` → `ssl_cipher_apply_rule()` `ssl_ciph.c:762` | 解析 `!`/`-`/`+`/裸名/别名，生成 `cipher_list` | 每次 `set_cipher_list` **整体重建** |
| G3 | TLS 1.3 独立通道 | `set_ciphersuites()` `ssl_ciph.c:1295`（名称精确匹配 `ciphersuite_cb`）；`update_cipher_list()` `ssl_ciph.c:1334` 把 1.3 套件 unshift 到列表头部 | TLS 1.3 套件**不经过 G2 规则字符串** | 每次 `set_ciphersuites` 整体重建 |
| G4 | 协议版本边界 | 套件自带 `min_tls/max_tls/min_dtls/max_dtls`；客户端 `ssl_cipher_disabled()` `t1_lib.c:3024`、服务端 `ssl3_choose_cipher()` `s3_lib.c:4921-4925` | 版本不符即跳过 | 每次握手 |
| G5 | 安全级别 / 安全回调 | 默认回调 `ssl_security_default_callback()` `ssl_cert.c:1244`；经 `ssl_security()` `ssl_cert.c:1313` 派发 `SSL_SECOP_CIPHER_*` | 位强度、aNULL、MD5、SHA1、PFS（level≥3）等 | 每次握手选套件时 |

正常（非恢复）握手的服务端选择在 `ssl3_choose_cipher()`（`s3_lib.c:4803`）内同时执行：
成员交集（`sk_SSL_CIPHER_find(allow,c)`，`s3_lib.c:4972`）+ G5 安全回调（`SSL_SECOP_CIPHER_SHARED`，`s3_lib.c:4975`）+ 版本/掩码检查。
**问题就在于会话恢复（`s->hit`）路径完全不调用这个函数**，详见第 3 节。

### 1.1 规则操作符语义（G2，`ssl_ciph.c:971-985, 855-895`）

| 写法 | 规则 | 语义 | 能否被后续规则恢复 |
|------|------|------|--------------------|
| `NAME`（无前缀） | `CIPHER_ADD` | 激活并移到队尾 | — |
| `-NAME` | `CIPHER_DEL` | 停用但**保留在链表中** | 能，后续裸名 `ADD` 可加回 |
| `!NAME` | `CIPHER_KILL` | **从链表摘除** | 不能，后续任何 `ADD` 都加不回 |
| `+NAME` | `CIPHER_ORD` | 仅调整已激活项顺序，**不激活任何东西** | — |
| `@SECLEVEL=n` | special | 直接写 `c->sec_level`（`ssl_ciph.c:1179`），不改变列表内容 | — |

实测确认（`openssl ciphers`，本构建）：

```
DEFAULT:-AES256:AES256   → 256 位套件计数恢复为基线 43   # DEL 可被裸名加回
DEFAULT:!AES256:AES256   → 仅剩 18                        # KILL 不可恢复
DEFAULT:!AES256:+AES256  → 仅剩 18                        # + 只是排序，救不回 KILL
```

---

## 2. 配置错误类触发条件（实现行为正确，但配置会让策略“看起来失效”）

以下 5 类均经本地样本复现。它们不是库的代码缺陷，但都能造成“已经禁用却仍协商到”的现象。

### CFG-1　`-`（DEL）被后续裸名/多段配置恢复，而 `!`（KILL）不会
`-` 只是停用，节点仍在链表；任何后置 `ADD`（裸名）都会重新激活。
真实诱因：多个配置段/多次 API 调用拼接规则串时，后面的 `ALL`、具体套件名把前面的 `-` 抵消。
**收紧建议：禁用一律使用 `!`，不要用 `-`。**

### CFG-2　TLS 1.3 与 TLS 1.2 是两条独立通道，禁用一边不影响另一边（最高频误区）
`CipherString`（G2）**完全不作用于 TLS 1.3 套件**；TLS 1.3 只受 `Ciphersuites`（G3）控制。
实测：

```
CipherString = DEFAULT:!AES128
  → TLS 1.2 的 128 位 AES 全部消失
  → TLS_AES_128_GCM_SHA256 仍然在协商列表中（G3 默认三件套未动）
```
握手样本 D3 证实：服务端 `cipher='DEFAULT:!AES128'`、客户端 `ciphersuites='TLS_AES_128_GCM_SHA256' -tls1_3`
仍成功协商 `TLS_AES_128_GCM_SHA256`。
**收紧建议：要禁用某对称算法，必须同时在 `CipherString` 与 `Ciphersuites` 两处禁用（例如同时去掉 `*AES128*` 与 `TLS_AES_128_GCM_SHA256`）。**

### CFG-3　未知名/拼写错误被静默忽略，禁用根本没生效
- TLS 1.2 规则串：`ssl_cipher_process_rulestr()` 找不到别名时 `found=0`，仅跳过该 token，**不报错**（`ssl_ciph.c:1064-1065, 1200-1203`）。
- TLS 1.3：`ciphersuite_cb()` 找不到名称返回 1 以“继续解析其余项”（`ssl_ciph.c:1278-1280`），仅当**整串一个都没匹配**才报 `NO_CIPHER_MATCH`（`ssl_ciph.c:1303-1308`）。

实测：`DEFAULT:!ECDHE-RSA-AES128-GCM-SHA512-TYPO` 返回成功且目标套件仍在；握手样本 D4 中服务端拼写错误的禁用被客户端成功协商。
**收紧建议：禁用后用 `openssl ciphers -v '<规则串>'` 做离线断言，确认目标套件确实从输出消失；不要假设拼写错误会失败。**

### CFG-4　重复/后置的 `CipherString` 整体重建，覆盖前面的禁用
`SSL_CTX_set_cipher_list()` 每次都调用 `ssl_create_cipher_list()` **从零重建** `cipher_list`（`ssl_lib.c:3785`），不是增量修改。
实测（C 程序）：先 `set_cipher_list("DEFAULT:!AES128")` 再 `set_cipher_list("DEFAULT")`，AES128 计数从 0 回到 23。
真实诱因：同一 section 多条 `CipherString`（CONF 后者覆盖前者）、应用初始化后又有模块调用 set、或多文件 include 顺序变化。
**收紧建议：全进程只在一处定义规则串；需要叠加策略时在同一字符串内用 `!` 表达，而不是再次调用 set。**

### CFG-5　系统默认配置的错误在未开诊断时被静默吞掉（`ssl_mcnf.c`）
`ssl_do_config()` 在 `system=1` 且未启用 `config_diagnostics` 时，任何命令失败都 `ERR_pop_to_mark()` 并 `return 1`（`ssl/ssl_mcnf.c:122-129`）。
实测：系统配置写 `CipherString = DEFAULT:@SECLEVEL=9`（非法级别）
- 无诊断：`SSL_CTX_new` 静默成功，回退到默认 60 个套件（策略行被整体丢弃）；
- **顶层** `config_diagnostics = 1`（注意必须在配置文件顶层，写在 `[openssl_init]` 内不生效，见 `crypto/conf/conf_mod.c:75`）：`SSL_CTX_new` 明确失败并报 `error in system default config`。

**收紧建议：在 openssl.cnf 顶层设置 `config_diagnostics = 1`，让坏配置快速失败而不是带病运行。**

> 补充（安全的失败，不是缺陷）：多段交集别名若各段无公共组件（如 `ECDHE+RSA`，mkey 与 auth 掩码交集为空）会在 `ssl_ciph.c:1068-1073` 显式报 `no cipher match`；空列表/全禁用也会让 `set_cipher_list` 返回失败（`ssl_lib.c:3802-3803`）。

---

## 3. 实现缺陷：TLS 1.2 / DTLS 1.2 会话恢复绕过新增策略（已修复）

### 3.1 根因
服务端处理 ClientHello 的 `tls_early_post_process_client_hello()`（`statem_srvr.c:2292`）中，
若会话缓存命中（`s->hit = 1`，`statem_srvr.c:2541`），对非 TLS 1.3 分支只做了一项检查（`statem_srvr.c:2558-2588`，修复前）：

```c
/* 仅确认该套件仍出现在“客户端本次发来的”列表里 */
for (i = 0; i < sk_SSL_CIPHER_num(ciphers); i++)
    if (c->id == s->session->cipher->id) { j = 1; break; }
if (j == 0) SSLfatal(... REQUIRED_CIPHER_MISSING);
```

随后在 `tls_post_process_client_hello()` 中，命中分支**直接采用会话里的旧套件**：

```c
} else {
    /* Session-id reuse */
    s->s3.tmp.new_cipher = s->session->cipher;   /* statem_srvr.c:3038 */
}
```

这条路径：
- **不调用** `ssl3_choose_cipher()`，因此不检查套件是否还在**服务端当前** `cipher_list` 中；
- **不调用** `ssl_security(SSL_SECOP_CIPHER_SHARED)`，因此不重跑安全级别/安全回调。

而完整握手在 `statem_srvr.c:3019` 走 `ssl3_choose_cipher()`，两道闸门都在。两者不一致即漏洞。
TLS 1.3 不受影响：它在恢复之前就先经 `ssl3_choose_cipher()` 选定套件（`statem_srvr.c:2455-2473`），且 PSK 绑定校验套件与摘要。

### 3.2 本地复现（同进程、内部会话缓存、内存 BIO，无网络）
测试程序 `resume_bypass.c` / `server_only_policy.c`（三段式 H1 完整握手 → H2 正常恢复验证 `reused=1` → H3 收紧策略后再恢复）：

修复前实测：
```
[H1] cipher=ECDHE-RSA-AES128-GCM-SHA256 reused=0
[H2] cipher=ECDHE-RSA-AES128-GCM-SHA256 reused=1     # 复用机制健全
[H3] 服务端 set_cipher_list("DEFAULT:!ECDHE-RSA-AES128-GCM-SHA256") 后
     cipher=ECDHE-RSA-AES128-GCM-SHA256 reused=1      # 被禁用套件经恢复复活
VERDICT: 漏洞确认
```
安全回调维度（`server_only_policy.c`，仅服务端收紧、客户端保持放行）：
```
[H2] 正常恢复：srv_cipher_calls=0      # hit 路径本来就不调用 CIPHER 安全检查
[H3] 开启拦截后：仍 reused=1，srv_calls=0
VERDICT: 服务端 hit 恢复完全跳过 CIPHER 安全检查，单侧收紧被绕过
```

这精确解释了题述两个现象：
1. “禁用一组算法但握手仍选到”——长生命周期 `SSL_CTX` 缓存了禁用前签发的会话，客户端持旧会话/票据恢复即可命中旧套件；
2. “安全级别变化后重新出现”——运行期调高 `sec_level` 或安装更严格的安全回调，对 `hit` 恢复完全不生效。

影响面：同一段 `tls_early_post_process_client_hello()` 被 TLS 1.2 与 DTLS 1.2 共用（状态机在 `statem_srvr.c`，DTLS 仅在 `statem_dtls.c` 处理重传），且重新协商的 abbreviated 握手同样置 `hit`，故三者都受影响。

### 3.3 最小修复（`ssl/statem/statem_srvr.c`，已实现）
在既有“客户端是否仍提供该套件”检查之后，补齐与 `ssl3_choose_cipher()` 对等的两道闸门（约 `statem_srvr.c:2589-2610`）：

```c
/* 1) 套件必须仍在服务端“当前”配置中（cipher_list_by_id 同时含 TLS1.3 头，
 *    但本分支已限定非 1.3，命中的是 1.2 套件，成员关系判断无歧义） */
if (sk_SSL_CIPHER_find(ssl_get_ciphers_by_id(s),
                       s->session->cipher) < 0) {
    SSLfatal(s, SSL_AD_ILLEGAL_PARAMETER, SSL_R_REQUIRED_CIPHER_MISSING);
    goto err;
}
/* 2) 安全级别 / 安全回调必须仍允许该套件 */
if (!ssl_security(s, SSL_SECOP_CIPHER_SHARED,
                  s->session->cipher->strength_bits, 0,
                  (void *)s->session->cipher)) {
    SSLfatal(s, SSL_AD_HANDSHAKE_FAILURE, SSL_R_NO_SHARED_CIPHER);
    goto err;
}
```

设计要点：
- 复用现有 `ssl_get_ciphers_by_id()`（`ssl_lib.c:3721`，自动回退到 CTX 列表，兼容 per-SSL 覆盖）与现有错误码/alert，不新增结构体字段、不改线协议；
- 仅在原本就存在的 `(!VERSION13 && s->hit)` 分支内追加，完整握手与 TLS 1.3 路径零改动；
- 检查失败时拒绝恢复，客户端可不带会话发起**全新完整握手**（此时走 G2/G5 正常策略），属于优雅降级而非连接能力永久丧失。

### 3.4 修复验证
- 原 PoC 修复后：H3 变为 `required cipher missing` / `no shared cipher`，禁用套件不再复活；H2 正常恢复 `reused=1` 不受影响。
- 全量 `test/sslapitest`：**150 个顶层测试全部 `ok`，0 个 `not ok`**；重点的 `test_ccs_change_cipher`、`test_session_with_only_{int,ext,both}_cache`、`test_multi_resume`、`test_ciphersuite_change`、`test_set_ciphersuite` 等全部通过。

---

## 4. 本地握手样本证据矩阵

证书均为本地 `openssl req -x509` 生成（RSA-2048 与 RSA-1024 各一），服务端 `s_server -www`、客户端 `s_client` 走 127.0.0.1；
策略隔离用例（PFS、单侧回调）用内存 BIO 的 C 程序驱动。脚本与程序位于 `/tmp/ossl52-diag/`。

### 4.1 禁用套件必须被拒绝（全为预期 FAIL，alert 40 / no shared cipher）
| 用例 | 服务端策略 | 客户端提供 | 结果 |
|------|-----------|-----------|------|
| A1 | `!ECDHE-RSA-AES128-GCM-SHA256` | 仅该套件 | FAIL `no shared cipher`（`statem_srvr.c`） |
| A2 | `!AES128` | 仅 `AES128-GCM-SHA256` | FAIL |
| A3 | `!CHACHA20` | 仅 CHACHA20-POLY1305 | FAIL |
| A4 | 1.3 仅 `TLS_AES_256_*` | 仅 `TLS_AES_128_*` | FAIL（G3 通道独立生效） |

### 4.2 允许套件正常协商（全为预期 OK）
| 用例 | 结果协商套件 |
|------|--------------|
| B1 双方 DEFAULT，TLS1.2 | `ECDHE-RSA-AES256-GCM-SHA384` |
| B2 双方固定 ECDHE-RSA-AES128-GCM-SHA256 | `ECDHE-RSA-AES128-GCM-SHA256` |
| B3 双方 TLS_AES_256_GCM_SHA384，TLS1.3 | `TLS_AES_256_GCM_SHA384` |
| B4 服务端 `!AES128`，客户端同时给 128+256 | 选中 `AES256-GCM-SHA384`（256），128 不出现 |

### 4.3 安全级别 / 降级时实际生效的策略
| 用例 | 配置 | 结果 | 证明的闸门 |
|------|------|------|-----------|
| C1 | RSA-1024 证书 + `@SECLEVEL=2` | FAIL `ee key too small`（`ssl_rsa.c:252`，证书加载期即拒） | G5 位强度 |
| C2 | 同一 RSA-1024 + `@SECLEVEL=0` | OK，协商 ECDHE-RSA-AES256-GCM | 降级确实放通 |
| C3 | 2048 证书 + `@SECLEVEL=2` + 静态 RSA（非 PFS） | OK | PFS 限制是 level≥3 专属，level2 不强制 |
| C4 | `@SECLEVEL=0` 尝试 `ADH-AES128-SHA` | FAIL（aNULL 仍受成员/掩码约束） | G1/G2 与级别正交 |
| P1/P3 | 自定义回调 level3，仅静态 RSA 非 PFS | FAIL `no ciphers available` | G5 的 PFS-only（`ssl_cert.c:1286`） |
| P2/P4 | 同 level3，ECDHE（PFS）/ TLS1.3 | OK | PFS 套件与 1.3 放行 |

> 说明：默认回调 level=3 的 `minbits=192`（`ssl_cert.c:1226`）会先在证书加载阶段拒绝 2048 位证书，
> 因此无法用 s_server 单独观察“PFS-only”套件规则；P1–P4 用自定义回调放行证书检查、只保留套件判定来隔离该逻辑。

### 4.4 配置错误与版本边界
| 用例 | 现象 | 归类 |
|------|------|------|
| D1 | `DEFAULT:-AES128:DEFAULT` 仍禁用（`DEFAULT` 自身只做 KILL 不含 ADD，重复展开不会加回；但裸名 `AES128` 可加回 DEL 项） | CFG-1 操作符 |
| D2 | `DEFAULT:!AES128:DEFAULT` 仍禁用 | KILL 不可恢复（正确行为） |
| D3 | TLS1.2 字符串禁 AES128，TLS1.3 仍协商 AES_128 | CFG-2 双通道 |
| D4 | 拼写错误的 `!...-TYPO` 静默成功、禁用未生效 | CFG-3 |
| E1/E2 | 版本不匹配返回 alert 70（protocol_version） | G4 版本边界正确 |

---

## 5. 修复 / 收紧方案与兼容性边界

### 5.1 代码修复（实现缺陷，已完成）
见 3.3。兼容性边界：
- **行为变化**仅作用于“会话命中且该套件已不在服务端当前策略内”的恢复请求——这类请求在正确策略下本就不应成功；
- 失败后客户端退化为全新握手，不影响可用性，只损失一次复用的 RTT 优化；
- 不影响 TLS 1.3、完整握手、策略未变情况下的正常恢复（H2 与 150 项测试佐证）；
- 告警沿用既有 `illegal_parameter(47)` / `handshake_failure(40)`，无需对端升级。

### 5.2 配置收紧（配置错误，建议落地）
1. 禁用统一用 `!`，禁止 `-`；需要排序才用 `+`。
2. 对称算法禁用同时覆盖 `CipherString` 与 `Ciphersuites` 两个通道。
3. 顶层开启 `config_diagnostics = 1`，让坏规则/坏级别在 `SSL_CTX_new` 阶段失败。
4. 全进程单点定义规则串，避免多次 `set_cipher_list` 整体重建覆盖；策略叠加在同一字符串内完成。
5. 上线前用 `openssl ciphers -v '<规则串>'` 与 `openssl ciphers -tls1_3 -ciphersuites '<...>'` 做离线核对，确认被禁套件确实消失。

### 5.3 应加入的回归断言
已在 `test/sslapitest.c` 新增 `test_resumption_honours_disabled_cipher()`（并在 main 注册、`#ifndef OPENSSL_NO_TLS1_2` 守卫）：
1. TLS1.2 完整握手取得会话；
2. 断言策略不变时恢复 `SSL_session_reused()==1`（防过度拦截）；
3. 服务端 `set_cipher_list("DEFAULT:!ECDHE-RSA-AES128-GCM-SHA256")` 收紧后，持旧会话恢复必须
   `TEST_false(create_ssl_connection(...))`（核心回归断言）。

验证：该测试在**修复前 `not ok`**（连接错误地成功）、**修复后 `ok`**，具备失败-通过双向有效性。
建议后续再补两条断言（同一测试模式即可）：
- 安全级别维度：恢复前调高 `SSL_CTX_set_security_level()`，断言旧会话中不再满足级别（如弱位强度）的套件被拒；
- DTLS 1.2 维度：用 DTLS 方法对同一 `hit` 分支补一个恢复被拒用例（代码路径共用，测试用于锁定行为）。

---

## 6. 关键代码索引
- 规则解析与操作符：`ssl/ssl_ciph.c:952`（process_rulestr）、`:762`（apply_rule）、`:1179`（@SECLEVEL）
- TLS1.2 列表构建 / G1 掩码：`ssl/ssl_ciph.c:1422`、`:273`、`:635`
- TLS1.3 独立通道：`ssl/ssl_ciph.c:1295`、`:1334`
- 整体重建语义：`ssl/ssl_lib.c:3785`（CTX_set_cipher_list）
- 握手期套件禁用判定：`ssl/t1_lib.c:3024`（ssl_cipher_disabled）、`ssl/s3_lib.c:4803`（ssl3_choose_cipher）
- 默认安全回调 / 级别位表：`ssl/ssl_cert.c:1244`、`:1226`
- **缺陷点与修复**：`ssl/statem/statem_srvr.c:2558`（hit 分支）、`:3038`（直接采用 session->cipher）、修复 `:2589-2610`
- 系统配置静默吞错 / 诊断开关：`ssl/ssl_mcnf.c:122`、`crypto/conf/conf_mod.c:75`
- 回归测试：`test/sslapitest.c` `test_resumption_honours_disabled_cipher()`
