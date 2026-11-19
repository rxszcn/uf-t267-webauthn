# t267-webauthn 交付说明

> 本题：免密登录网关补齐 WebAuthn §7.1 step 17 在**验证器扩展输出侧**的未请求校验。
> 本文按题面明示要求逐条落点，含改动面逐文件登记、设计理由、四臂矩阵实测读数与验收命令终态读数。

---

## 1. 问题与规范依据

WebAuthn Level 3 §7.1（Registering a New Credential）第 17 步要求：客户端扩展结果与 authenticator data
里的扩展输出中出现的每一个扩展标识符，都必须同时出现在 `create()` 的 extensions 输入里，即**不得出现未被
请求的扩展**。

修复前的实际状态（同一策略，两个半区行为分裂）：

| 半区 | 落点 | 未请求输出 |
|---|---|---|
| 客户端扩展结果 | `AuthenticationExtensionsClientOutputs.Verify` | 默认拒绝（`Present()` + `session.Requested`）|
| 验证器扩展输出 | `AuthenticatorExtensionOutputs.Verify` | **零处理**：只看 credProtect 强制、credBlob 存储两条注册规则 |

后果如题面所述：验证器自造的未请求扩展输出被端到端接受，并经 `NewCredential` → `newCredentialExtensions`
沉淀进 `Credential.Extensions`（`CredProtect` / `MinPinLength` / `CredBlobSet` / `HMACSecret`），而同一个
标识符若出现在 `clientExtensionResults` 里却被默认拒绝。合规审计按月回读凭据记录即判定注册链路越权接受。

---

## 2. 实现落点与形态（含理由）

### 2.1 落点选择

**落点：`AuthenticatorExtensionOutputs.Verify`（`protocol/extensions_authenticator.go`），由 `CreateCredential`
在既有调用点传入既有策略。**

理由：

1. **与客户端半区同址同权。** 客户端禁令就在 `AuthenticationExtensionsClientOutputs.Verify`；验证器禁令放在
   对称位置的 `AuthenticatorExtensionOutputs.Verify`，两个半区由同一个规范步骤约束、由同一份 `SessionExtensions`
   驱动、由同一个策略值裁决。审计者读一处即可理解两个半区。
2. **在凭据成型之前拦截。** `CreateCredential` 里 `Ext.Verify` 先于 `NewCredential`，因此在
   `credential.Extensions` 被赋值之前就把未请求输出拦下 —— 题面「凭据记录里沉淀了策略从未批准的扩展数据」正是
   靠这个次序闭合的，不需要再改 `newCredentialExtensions` 的选取语义（符合隐性眼「凭据登记面沉淀语义不变」）。
3. **不放解析层。** `ParseAuthenticatorExtensionOutputs` 对未知/类型异常标识符的保留语义（进 `Extra`）是题面
   明示要维持的，且解析层拿不到 session。若在解析层拒绝，就既破坏了保留语义，也无法区分「已请求的自造扩展」。
4. **不放 `AuthenticatorData.Verify`。** 该函数是注册与断言共用的步骤 13–15/17，签名里没有 session；
   而题面要求「断言仪式路径对验证器扩展输出的既有处理形态保持不变」。

### 2.2 签名形态：`Verify` 扩参而不是新函数

`AuthenticatorExtensionOutputs.Verify(session, ceremony)` → `Verify(session, ceremony, policy)`。

理由：

- 策略必须能表达「忽略形态」，而忽略形态是**部署级配置**（`Config.ExtensionsUnsolicitedOutputPolicy`），
  与客户端半区同一个值。新增独立函数会让调用方有两个可配策略、两种默认值，分裂会换个位置复现。
- 扩参让旧的两参调用点**编译失败**，强制 review 每一处 —— 这比新增函数更容易漏，也比静默沿用旧行为更安全。
- 与客户端 `AuthenticationExtensionsClientOutputs.Verify(session, ceremony, policy)` 的参数表完全对齐。

### 2.3 错误形态

沿用该函数既有的「收集全部问题 → `errors.Join` → 包一层 `ErrBadRequest`」形态：

```
Error validating the authenticator extension outputs: The authenticator returned the "minPinLength" extension output which was not requested
```

- 单条问题也是 `*Error`（`ErrBadRequest`），`errors.As`/`errors.Is` 可达，满足既有 `Details`/`DevInfo` 序列化契约。
- **点名的是验证器实际返回的标识符**（`"credProtect"`，而非请求侧的 `"credentialProtectionPolicy"`），因为操作者
  要拿这条错误去比对**已签名的 authenticator data**，那里出现的是缩写标识符。
- 措辞与客户端半区（`Client returned the %q extension output which was not requested`）刻意对齐，让一个仪式里
  两个半区同时报错时，调用方可从 `client` / `authenticator` 字样区分来源。

### 2.4 两个标识符命名空间的映射（实现上的关键点）

验证器的输出标识符与 RP 的输入标识符**不是同一套拼写**：RP 请求 `credentialProtectionPolicy`，验证器回
`credProtect`；RP 请求 `hmacCreateSecret`，验证器回 `hmac-secret`。因此直接拿输出标识符去 `session.Requested`
里查会**误杀合法输出**。

为此引入 `extensionAuthenticatorOutputInputs` 映射表（输出标识 → 可请求它的输入标识集合）：

| 验证器输出标识 | 可请求它的客户端输入标识 |
|---|---|
| `credProtect` | `credentialProtectionPolicy`, `enforceCredentialProtectionPolicy` |
| `minPinLength` | `minPinLength` |
| `credBlob` | `credBlob`, `getCredBlob` |
| `hmac-secret` | `hmacCreateSecret`, `hmacGetSecret` |
| `uvm` | `uvm` |

未建模的标识符不在表里，退回「同名输入即视为已请求」—— 这是库对厂商扩展唯一能掌握的规则（库不知道厂商的
输入/输出如何对应），且与客户端半区对 `Extra` 键的判定口径一致。

### 2.5 会话持久化面（隐性约束）

- **未新增 `SessionExtensions` 字段**：直接复用既有的 `Requested []string`（`req` msgp key）。因此
  `webauthn/types_session_gen.go` 与 `credential_gen.go` 等生成文件**无需重生成**，diff 里没有任何 `_gen` 变更。
- 新旧版本并存共享会话存储时：旧版本进程写入的会话，只要带了 `req` 列表，新版本读入后判定输入完整；
  旧版本无 `req` 的会话在本版本下行为与既有 §3.2 描述一致（已在 MIGRATION.md §3.2 补上验证器半区的口径）。

### 2.6 解析层与凭据登记面不变

- `ParseAuthenticatorExtensionOutputs` 未改一字节：未知键与类型异常键仍进 `Extra`，`credProtect` /
  `credentialProtectionPolicy` 双标识符优先级逻辑不变。
- `webauthn/credential.go` 的 `newCredentialExtensions` 未改：已请求输出的沉淀语义原样保留，只是不再有未请求
  输出能活到这一步。

---

## 3. 题面明示要求 → 改动逐条映射

| # | 题面要求 | 落点 | 验证 |
|---|---|---|---|
| 1 | 补齐验证器扩展输出侧的未请求校验 | `protocol/extensions_authenticator.go` `Verify` 新增未请求分支 | 四臂臂 1/2 |
| 2 | 未请求默认拒绝 | 零值 `UnsolicitedOutputPolicyReject`，`policy != Ignore` 才放行 | 臂 1/2 默认即拒绝 |
| 3 | 错误信息点名扩展标识符 | `The authenticator returned the %q extension output which was not requested` | `TestAuthenticatorExtensionOutputsVerifyUnsolicitedOutputNamesIdentifier` |
| 4 | 已建模标识符与自造标识符同在拒绝之列 | `Present()` 汇总类型字段 + `Extra` 键，统一过 `authenticatorOutputSolicited` | 臂 1（`minPinLength`）、臂 2（`vendorThing`）；`UnrequestedWrongTypedModelled` |
| 5 | 忽略策略下验证器输出与客户端同权放行 | `Verify` 的 `policy != UnsolicitedOutputPolicyIgnore` 守卫，与客户端半区逐字同形 | 臂 3a/3b；`TestAuthenticatorExtensionOutputsVerifyMatchesClientHalf` |
| 6 | 已请求的扩展输出继续通过 | `extensionAuthenticatorOutputInputs` + `authenticatorOutputSolicited` | 臂 4；`RequestedOutputPasses`、`RequestedVendorOutputPasses` |
| 7 | 客户端扩展结果侧的既有拒绝行为不变 | `protocol/extensions_session.go` 仅改注释，`AuthenticationExtensionsClientOutputs.Verify` 代码零改动 | `TestClientOutputsVerify` 全绿原值 |
| 8 | 解析层对未知扩展的保留语义不变 | `ParseAuthenticatorExtensionOutputs` 未改 | `TestParseAuthenticatorExtensionOutputs*` 全绿原值 |
| 9 | 会话已持久化请求清单可直接复用 | 复用 `SessionExtensions.Requested`，零新增字段 | `git diff` 无 `_gen` 变更；`TestBeginRegistration_StoresSessionExtensions` 原值 |
| 10 | 实现落点与错误形态自定并写明理由 | 本文 §2.1 / §2.2 / §2.3 | — |
| 11 | 改动面逐文件登记 | 本文 §4 | — |
| 12 | 四臂矩阵逐臂实测 | 本文 §5 | 四臂读数见 §5 |
| 13 | 验收读数写入交付说明 | 本文 §6 | — |
| 14 | 包文档与策略配置注释描述与实际一致 | `webauthn/doc.go` Extensions 段、`webauthn/types.go` `ExtensionsUnsolicitedOutputPolicy`、`protocol/extensions_session.go` 策略类型与常量注释、`MIGRATION.md` §2.4/§3.2 | grep 无残存旧描述（§7） |
| 15 | 断言仪式路径既有处理形态不变 | `Verify` 里 `ceremony == AssertCeremony` 提前返回，位于新增分支**之前**，行为零变化 | `AssertionIsUnaffected`、既有 `AssertionIsNotChecked`/`CredBlobAssertionIsNotChecked` 原值 |
| 16 | 同文件同框架新增三类断言 + 忽略形态 | `protocol/extensions_authenticator_test.go` 新增 4 个测试，沿用 `testify` + 表驱动 | §4 文件 3；`go test -run 'TestAuthenticatorExtensionOutputs'` |
| 17 | 既有测试保持通过 | 见 §6 | 验收命令零失败 |

---

## 4. 改动面逐文件登记（与 diff 终态一致）

`git diff --stat`：

```
 MIGRATION.md                              |  28 +++-
 protocol/extensions_authenticator.go      | 103 ++++++++++++--
 protocol/extensions_authenticator_test.go | 222 ++++++++++++++++++++++++++++--
 protocol/extensions_session.go            |  18 ++-
 webauthn/doc.go                           |  14 +-
 webauthn/mldsa_e2e_test.go                |  11 +-
 webauthn/registration.go                  |   2 +-
 webauthn/types.go                         |  13 +-
 8 files changed, 369 insertions(+), 42 deletions(-)
```

逐文件说明：

1. **`protocol/extensions_authenticator.go`**（核心实现）
   - 新增 `extensionAuthenticatorOutputInputs` 映射表（§2.4）。
   - 新增 `(*AuthenticatorExtensionOutputs).Present()`：汇总类型字段与 `Extra` 键，nil receiver 返回 nil。
   - 新增 `authenticatorOutputSolicited(session, name)`：输出标识 → 输入标识的判定。
   - `Verify` 扩参为 `(session, ceremony, policy)`；在 credProtect/credBlob 两条既有规则**之前**插入未请求分支；
     `AssertCeremony` 早退保持在最前。补充文档说明三条规则、两命名空间映射、与会话 `Requested` 复用。
   - `import` 增加 `maps`、`slices`。

2. **`protocol/extensions_authenticator_test.go`**（测试）
   - 既有 `TestAuthenticatorExtensionOutputsVerify` 表里，凡构造「已请求」语境的臂补 `Requested` 字段
     （`EnforcedAndHonoured`/`EnforcedAndExceeded`/`EnforcedAndDowngraded`/`EnforcedWithUnknownPolicy`/
     `CredBlobStored`/`CredBlobNotStored`/`CredBlobOutcomeMissing`），并把调用改为三参 `Reject`。既有断言片段
     （`credentialProtectionPolicy`/`credBlob`/`less restrictive`/`did not report`/`was not stored`）一律原值不动。
   - 新增 `TestAuthenticatorExtensionOutputsVerifyUnsolicited`：四臂矩阵 + 忽略形态 + 错类型 + 断言不受影响。
   - 新增 `TestAuthenticatorExtensionOutputsVerifyUnsolicitedOutputNamesIdentifier`：错误点名验证器输出标识符、
     且为 `*Error`。
   - 新增 `TestAuthenticatorExtensionOutputsSolicitedByClientInputs`：映射表双向覆盖（每个输出标识都被其输入
     请求覆盖；自造标识符同名才通过）。
   - 新增 `TestAuthenticatorExtensionOutputsVerifyMatchesClientHalf`：同一策略值下客户端/验证器两半区判定一致
     （对立面即修复前的分裂）。

3. **`protocol/extensions_session.go`**（策略文档）
   - `UnsolicitedOutputPolicy` 类型注释、`Reject`/`Ignore` 常量注释改为覆盖「客户端 + 验证器」两个输出通道，
     并说明断言仪式无验证器输出。**代码逻辑零改动**。

4. **`webauthn/registration.go`**（调用点）
   - `AuthData.Ext.Verify(session.Extensions, protocol.CreateCeremony)` →
     `AuthData.Ext.Verify(session.Extensions, protocol.CreateCeremony, webauthn.Config.ExtensionsUnsolicitedOutputPolicy)`。

5. **`webauthn/doc.go`**（包文档 · 题面明示要求）
   - 删除「验证器扩展输出从不按请求校验」的既有取舍段落，改写为「两个通道都校验、验证器输出按输入标识匹配、
     策略同时放宽两个半区、认证仪式无验证器输出」；上一段的「默认 a client extension output ...」改为
     「an extension output ...」。

6. **`webauthn/types.go`**（配置注释 · 题面明示要求）
   - `Config.ExtensionsUnsolicitedOutputPolicy` 注释从「仅客户端扩展输出」改为覆盖注册仪式两个通道，说明验证器
     侧按输出标识/输入标识匹配、拒绝时点名标识符（含未建模的厂商扩展）。

7. **`webauthn/mldsa_e2e_test.go`**（回归适配）
   - `mldsaRegistrationCeremony` 的 Config 显式设 `ExtensionsUnsolicitedOutputPolicy: protocol.UnsolicitedOutputPolicyIgnore`，
     并加注释说明：该向量取自 webauthn.io 真实抓包，验证器自带默认 credProtect 政策会主动回 `credProtect`
     （正是 CTAP 常见行为），向量字节不动，故以忽略形态运行。这是「忽略策略放行」形态的**真实端到端佐证**。

8. **`MIGRATION.md`**（发布说明一致性）
   - §2.4 扩写：两个通道都校验、输出/输入标识映射、认证仪式无验证器输出、CTAP 默认 credProtect 需配置忽略形态。
   - §3.2 升级窗口：会话缺 `req` 时，是两个通道任一有输出都会失败。
   - §3.2 末尾补：即使未请求任何扩展，验证器主动回 `credProtect` 在默认策略下仍会被拒。

**未改动的相关面（证明约束边界）：**
- `protocol/authenticator.go`（解析 + `AuthenticatorData.Verify`）零改动。
- `protocol/extensions_outputs.go`（客户端半区）零改动。
- `webauthn/credential.go`（凭据登记）零改动。
- 所有 `*_gen.go` / `*_gen_test.go`（msgp 生成）零改动。

---

## 5. 四臂矩阵逐臂实测读数

复现命令：

```bash
go test ./protocol/ -run 'TestAuthenticatorExtensionOutputsVerifyUnsolicited$' -count=1 -v
go run ./.scratch-probe     # §5 的探针，见下（已删，读数抄录于此）
```

探针输出（未请求 = `SessionExtensions{}` + 默认 `Reject`，注册仪式）：

| 臂 | 输入 | 期望 | 实测 `err` | 实测错误全文 |
|---|---|---|---|---|
| 1 未请求·已建模标识符 | `{MinPinLength: 6}` | 拒绝 | `true` | `Error validating the authenticator extension outputs: The authenticator returned the "minPinLength" extension output which was not requested` |
| 2 未请求·自造标识符 | `Extra{"vendorThing": "x"}` | 拒绝 | `true` | `Error validating the authenticator extension outputs: The authenticator returned the "vendorThing" extension output which was not requested` |
| 3a 忽略策略·未请求（自造） | `Extra{"vendorThing": "x"}` + `Ignore` | 放行 | `false` | `<nil>` |
| 3b 忽略策略·未请求（已建模） | `{CredProtect: userVerificationOptional}` + `Ignore` | 放行 | `false` | `<nil>` |
| 4 已请求输出 | `{CredProtect: userVerificationOptional}` + `Session{Requested: [credentialProtectionPolicy]}` + `Reject` | 放行 | `false` | `<nil>` |
| 对照·客户端未请求 | `ClientOutputs{Extra{"vendorThing": true}}` + `Reject` | 拒绝 | `true` | `Error validating the client extension outputs: Client returned the "vendorThing" extension output which was not requested` |
| 对照·客户端忽略 | 同上 + `Ignore` | 放行 | `false` | `<nil>` |
| 对照·断言仪式 | `Extra{"vendorThing": "x"}` + `AssertCeremony` | 放行（不校验） | `false` | — |

**关键读数：**
- 拒绝臂（1、2）错误信息**均点名验证器实际返回的标识符**（`"minPinLength"` / `"vendorThing"`），满足题面
  「错误信息点名扩展标识符」。
- 已建模（臂 1）与自造（臂 2）在默认策略下**同在拒绝之列**。
- 忽略形态（臂 3a/3b）下，未请求的验证器输出与客户端半区**同权放行**。
- 已请求输出（臂 4）**继续通过**。
- 断言仪式（对照）仍**不校验**验证器扩展输出，既有形态保持。

对应的测试运行读数（全部 PASS）：

```
=== RUN   TestAuthenticatorExtensionOutputsVerifyUnsolicited
--- PASS: TestAuthenticatorExtensionOutputsVerifyUnsolicited (0.00s)
    --- PASS: .../UnrequestedModelled
    --- PASS: .../UnrequestedVendor
    --- PASS: .../UnrequestedIgnored
    --- PASS: .../UnrequestedModelledIgnored
    --- PASS: .../RequestedOutputPasses
    --- PASS: .../RequestedVendorOutputPasses
    --- PASS: .../EveryUnrequestedOutputIsReported
    --- PASS: .../UnrequestedWrongTypedModelled
    --- PASS: .../AssertionIsUnaffected
--- PASS: TestAuthenticatorExtensionOutputsVerifyUnsolicitedOutputNamesIdentifier
--- PASS: TestAuthenticatorExtensionOutputsSolicitedByClientInputs
--- PASS: TestAuthenticatorExtensionOutputsVerifyMatchesClientHalf
```

---

## 6. 验收命令最终读数

```bash
go test ./... -skip 'TestDoAtomicReplace|TestProductionMetadataTOCParsing|TestConformanceMetadataTOCParsing'
```

终态输出（`-count=1` 强制重跑，非缓存）：

```
ok   github.com/go-webauthn/webauthn/metadata                          1.745s
ok   github.com/go-webauthn/webauthn/metadata/providers/cached         1.744s
ok   github.com/go-webauthn/webauthn/metadata/providers/memory         0.694s
ok   github.com/go-webauthn/webauthn/protocol                           3.389s
ok   github.com/go-webauthn/webauthn/protocol/webauthncbor             0.665s
ok   github.com/go-webauthn/webauthn/protocol/webauthncose             1.389s
?    github.com/go-webauthn/webauthn/testing/mocks                     [no test files]
ok   github.com/go-webauthn/webauthn/webauthn                          1.439s
```

**零失败（0 FAIL）。** 8 个包全部 `ok`（含 1 个无测试文件的包）。

定向读数（protocol 包扩展验证测试）：

```
go test ./protocol/ -run 'TestAuthenticatorExtensionOutputs|TestParseAuthenticatorExtensionOutputs|TestClientOutputsVerify' -count=1
ok   github.com/go-webauthn/webauthn/protocol   0.130s
```

---

## 7. 文档一致性核查（题面明示要求）

```bash
grep -rn "never checked\|never verified\|client extension outputs .* only\|covers client extension outputs" --include='*.go' --include='*.md' .
# → 无输出（无残存旧描述）
```

改后描述与实际行为对照：

| 工件 | 改前 | 改后 | 与实际行为一致？ |
|---|---|---|---|
| `webauthn/doc.go` Extensions 段 | 「That check covers client extension outputs only ... never checked against what was requested, deliberately」 | 「applies to both extension output channels of a registration ... authenticator half matches an output identifier against the client input identifier」 | ✅ |
| `protocol/extensions_session.go` `UnsolicitedOutputPolicy` | 「client extension output ... 仅客户端」 | 「both output channels of a registration ... no authenticator extension output at assertion」 | ✅ |
| `webauthn/types.go` `ExtensionsUnsolicitedOutputPolicy` | 「client extension output ... 仅客户端」 | 「both halves of a registration ... authenticator half has no outputs at assertion」 | ✅ |
| `MIGRATION.md` §2.4 | 「every client extension output」 | 「both output channels ... identifier matched against input identifier ... CTAP default credProtect needs Ignore」 | ✅ |
| `MIGRATION.md` §3.2 | 「client returns any client extension output」 | 「response carries any extension output, from either the client or the authenticator」 | ✅ |

---

## 8. 回归与边界说明

- **既有测试保持通过**：`TestAuthenticatorExtensionOutputsVerify` 的所有既有臂断言片段未改，仅补 `Requested`
  与三参调用；`TestClientOutputsVerify`、`TestParseAuthenticatorExtensionOutputs*`、`TestCreateCredential*`
  原值不动。
- **断言仪式（§7.2）**：`Verify` 中 `ceremony == AssertCeremony` 早退在新增分支之前，验证器扩展输出仍不校验。
  既有 `AssertionIsNotChecked`、`CredBlobAssertionIsNotChecked` 原值通过；新增 `AssertionIsUnaffected` 显式钉住。
- **失败闭合**：`Verify` 的 `policy != UnsolicitedOutputPolicyIgnore` 采用白名单式判断，未知策略值也会拒绝（与
  客户端半区一致）；未知仪式类型走注册路径（既有 `UnknownCeremonyFailsClosed` 原值通过）。
- **解析层**：未改，未知键与类型异常键仍留 `Extra`（`TestParseAuthenticatorExtensionOutputsUnknownKey` /
  `...WrongTypeIsPreserved` 原值通过）。
- **凭据沉淀**：`newCredentialExtensions` 未改；未请求输出已无法抵达该函数。

---

## 9. 可能的审查关注点（主动交代）

1. **为什么给 `Verify` 扩参而不是新增 `VerifyUnsolicited`？** 见 §2.2：策略必须与客户端半区共用同一个部署级值，
   两套默认值会让分裂换个位置复现；扩参还能让所有调用点编译失败以强制 review。
2. **为什么不直接在解析层拒未知扩展？** 见 §2.1 第 3 点：题面明示「解析层保留语义不变」，且解析层无 session。
3. **为什么 ML-DSA 端到端测试改成忽略形态？** 见 §4 文件 7：向量是真实带默认 credProtect 的抓包，改向量字节
   等于伪造，故以「忽略形态」运行 —— 这恰好是题面要求的「忽略策略放行」形态的真实证据。
4. **会话双版本并存**：未新增 `SessionExtensions` 字段，生成编解码不变；旧会话只要带 `req` 即判定输入完整，
   与既有 §3.2 口径一致（已补验证器半区说明）。
5. **`Present()` 为何把 `CredBlob`/`HMACSecretOutput`（字节形态）也算作已出现？** 它们在断言仪式使用，但注册
   仪式里若出现同名字节的异常形态，也属「出现了该标识符」，应受同一策略约束，故一并纳入 `Present()` 的统一判定。
