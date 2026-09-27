# go-device-enrollment

基于一次性挑战的设备注册服务，支持注册后的密钥轮换、设备禁用与绑定密钥版本的认证校验。

开发环境：Go 1.23.0，仅依赖标准库。

运行测试：

    go test ./... -race

## 核心概念

| 概念 | 类型 | 说明 |
| --- | --- | --- |
| 挑战 | `Challenge` | 管理员签发的一次性注册凭证，短期有效，绑定预期设备属性 |
| 证明 | attestation | 设备私钥对注册消息的签名，证明持有与公钥对应的私钥 |
| 密钥版本 | `KeyVersion` | 设备公钥的版本化记录：`active` / `superseded` / `revoked` |
| 轮换 | `Rotation` | 一次密钥轮换状态机：`pending` → `confirmed` / `cancelled` / `expired` |
| 设备状态 | `DeviceStatus` | `active` / `disabled` |

## 接口与流程

### 1. 挑战签发 — `IssueChallenge(attrs)`

- 管理员为预期设备属性（型号、序列号）签发挑战，默认 5 分钟有效（`Config.ChallengeTTL`）。
- 明文秘密只通过返回值交给调用方；**存储层只保存秘密的 SHA-256 摘要**。
- 过期判断统一通过注入的 `Clock` 接口获取当前时间，测试可替换为假时钟。

### 2. 设备注册 — `Enroll(req)`

设备携带挑战 ID、秘密、外部注册号、设备属性、公钥及证明（私钥对
`EnrollmentMessage(challengeID, externalID)` 的 ed25519 签名）完成注册：

- 依次校验：挑战存在 → 未被消费 → 未过期 → 秘密摘要匹配 → 属性匹配 → 证明有效；
  全部通过后**原子地**消费挑战、写入设备与初始密钥版本（版本 1）。
- 幂等语义（以 `ExternalID` 为幂等键，按注册内容指纹比对）：
  - 同号同内容的重复调用 → 返回原设备身份（即使挑战已被消费）；
  - 同号异内容 → `ErrEnrollmentConflict`；
  - 并发使用同一挑战 → 只有一个注册成功，其余得到 `ErrChallengeAlreadyConsumed`。

### 3. 密钥轮换 — `StartRotation` / `ConfirmRotation` / `CancelRotation`

- `StartRotation(deviceID, newPublicKey)`：开启轮换，旧钥与新钥必须在确认窗口
  （`Config.RotationWindow`，默认 10 分钟）内共同完成确认；同一设备同一时间只允许一个待确认轮换。
- `ConfirmRotation(rotationID, oldSig, newSig)`：同时验证旧钥与新钥对
  `RotationMessage(rotationID)` 的签名，全部有效才提交——设备当前密钥版本前移，
  **旧钥立即失效**（`superseded`）。
- `CancelRotation(rotationID)`：取消待确认的轮换。
- 确认、取消与超时（惰性过期）互相竞争时，只有最先到达的状态迁移生效，
  **轮换只产生一个终态**；已终态的轮换再操作返回 `ErrRotationFinalized`，
  超窗确认返回 `ErrRotationWindowExpired`。

### 4. 设备禁用 — `DisableDevice(deviceID)`

原子地终止注册有效性与全部待处理轮换：设备置为 `disabled`、所有密钥版本吊销
（`revoked`）、所有 `pending` 轮换进入 `cancelled` 终态。重复调用幂等。

### 5. 认证校验 — `Authenticate(deviceID, keyVersion, nonce, sig)`

- 请求必须绑定设备**当前有效**的密钥版本，并用对应私钥签名
  `AuthMessage(deviceID, nonce)`。
- 携带旧密钥版本的迟到请求返回 `ErrStaleKeyVersion`，不会覆盖或回滚任何新状态。
- 已禁用设备返回 `ErrDeviceDisabled`。

## 错误分类

错误按域分组，均可用 `errors.Is` 判定（见 `errors.go`）：

- 挑战：`ErrChallengeNotFound` / `ErrChallengeExpired` / `ErrChallengeAlreadyConsumed` /
  `ErrChallengeSecretMismatch` / `ErrChallengeAttributeMismatch`
- 证明：`ErrAttestationInvalid`
- 密钥版本：`ErrStaleKeyVersion` / `ErrUnknownKeyVersion`
- 状态：`ErrDeviceNotFound` / `ErrDeviceDisabled` / `ErrRotationNotFound` /
  `ErrRotationPendingExists` / `ErrRotationFinalized` / `ErrRotationWindowExpired`
- 幂等冲突：`ErrEnrollmentConflict`
- 认证失败：`ErrAuthenticationFailed`

## 持久化与并发

- 持久化层抽象为 `Store` 接口（`store.go`），`MemoryStore` 为内存参考实现；
  替换为 SQL 实现时，应把同一服务方法内的多次读写包进一个事务。
- `Service` 用单个互斥锁串行化所有"检查-写入"序列，保证挑战单次消费、
  轮换单终态、及禁用的原子性；测试使用 `-race` 验证。

## 代码结构

- `clock.go` — 统一时间来源 `Clock` 接口与系统时钟实现
- `types.go` — 挑战、设备、密钥版本、轮换等持久化模型
- `errors.go` — 按域分类的错误定义
- `store.go` — `Store` 接口与内存实现
- `service.go` — 挑战签发、注册、轮换、禁用、认证校验
- `service_test.go` — 含并发场景的自动化测试
