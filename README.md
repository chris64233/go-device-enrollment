# go-device-enrollment

基于一次性挑战（challenge）的设备注册服务，支持注册后的密钥轮换、跨租户受控转移、
禁用与认证校验。纯 Go 标准库实现，无第三方依赖。

开发环境：Go 1.23.0。

## 能力概览

- **挑战签发（管理员）**：管理员为指定租户签发挑战，挑战短期有效，绑定预期的外部注册号
  与设备属性；数据库只保存挑战秘密的加盐 HMAC-SHA256 摘要，明文秘密仅在签发响应中出现一次。
- **设备注册**：设备携带 ed25519 公钥及私钥对注册报文的证明（attestation）完成注册，
  注册成功即归属签发挑战的租户。
  - 外部注册号与注册内容（属性 + 公钥）都相同的重复调用幂等返回原设备身份；
  - 同号异内容返回 `idempotency_conflict`，且不会覆盖既有设备；
  - 挑战只能被成功消费一次，并发使用同一挑战只有一个注册成功。
- **密钥轮换**：
  - 由当前密钥签名发起，登记一把 `pending` 新钥并打开有限确认窗口（默认 10 分钟）；
  - 旧钥与新钥在窗口内分别对同一轮换报文签名确认，两侧齐备的瞬间轮换原子完成，
    旧钥立即失效、新钥生效；
  - 支持当前钥取消、窗口超时（惰性 + 显式 sweep）、管理员禁用中止；
  - 确认、取消、超时、中止互相竞争，轮换只产生一个终态，迟到操作一律被拒绝。
- **跨租户设备转移（受控）**：
  - 源租户发起时冻结设备身份、当前密钥版本与目标租户，并生成短期有效的一次性接收凭据；
    持久化只保存凭据的加盐摘要，明文仅在发起响应中出现一次；
  - 目标租户接收时必须同时提交新的设备公钥与新私钥对接收报文的证明；成功即在同一原子
    变更内切换归属、启用新密钥版本，并使源租户的全部认证资格（所有旧密钥）立即失效；
  - 证明、凭据或冻结版本任一不匹配都会整体失败，绝不留下“归属已变但新密钥未生效”的中间态；
  - 接收、源租户取消、凭据过期（以及设备禁用中止）互相竞争，只产生一个终态；
  - 设备禁用、存在未完成轮换或已有活动转移时不得发起；活动转移期间也不得发起轮换；
  - 源租户的迟到认证、旧轮换的迟到确认都不能覆盖新归属，目标租户不能重复接收同一设备；
  - 发起与接收均支持幂等：同号同内容返回首次结果，同号异内容返回冲突。
- **认证**：请求必须携带租户标识与设备当前有效的密钥版本号并以对应私钥签名。
  设备转移后源租户不再匹配当前归属（`transfer_tenant_mismatch`）；使用旧版本密钥的迟到
  请求得到 `key_version_invalid`，旧状态无法覆盖新状态。
- **禁用（管理员）**：在同一个持久化快照变更中终止设备注册有效性、失效全部密钥，
  并把待处理轮换与活动转移原子中止（`aborted`）。禁用幂等，可重复调用。
- **归属历史查询**：可查询设备当前归属、完整归属链，以及每次转移的两端决定和密钥版本变化；
  结果不包含凭据、公钥或证明等敏感内容。
- **统一时钟**：挑战过期、轮换窗口与转移凭据窗口判断都经由可替换的 `Clock` 接口，
  生产用 UTC 墙钟，测试用可推进的固定时钟。

## 数据模型与状态

```
ChallengeRecord  id, salt, secret_digest, tenant_id, external_id, attributes,
                 expires_at, consumed, consumed_at, consumed_by_device

DeviceRecord     id, external_id, attributes, content_hash,
                 tenant_id, ownership[]{tenant, transfer_id, key_version, started_at, ended_at},
                 status(active|disabled), current_key_version, keys[]{version,state}

KeyRecord        version, public_key, state(active|pending|invalidated)

RotationRecord   id, device_id, old_version, new_version,
                 old_key_confirmed, new_key_confirmed,
                 status(pending|confirmed|cancelled|timed_out|aborted),
                 deadline, created_at, completed_at

TransferRecord   id, device_id, source_tenant, target_tenant, frozen_version,
                 credential_salt, credential_digest,
                 request_id, content_hash, accept_hash,
                 status(pending|accepted|cancelled|expired|aborted),
                 deadline, created_at, completed_at
```

> `credential_salt` / `credential_digest` 是接收凭据的全部落盘内容；凭据明文、
> 接收请求携带的新公钥证明（attestation）都不持久化。新公钥在接收成功后进入
> 设备密钥集；`accept_hash` 只保存“目标租户 + 新公钥”的摘要用于幂等判定。

轮换状态机（`pending` 只允许迁出一次）：

```
                 ┌── confirmed（旧新钥都确认；旧钥失效，新钥生效）
pending ─────────┼── cancelled（当前钥取消；pending 新钥失效）
                 ├── timed_out（超过确认窗口；pending 新钥失效）
                 └── aborted  （设备被禁用；pending 新钥失效）
```

转移状态机（与轮换同构，`pending` 只允许迁出一次）：

```
                 ┌── accepted（目标租户凭据 + 新公钥证明；归属原子切换、新钥生效、源租户全部密钥失效）
pending ─────────┼── cancelled（源租户取消；归属与密钥不变）
                 ├── expired  （凭据超过窗口；归属与密钥不变）
                 └── aborted  （设备被禁用；归属与密钥随禁用终止）
```

## 持久化

默认使用 JSON 快照文件（`Store`），每次状态变更都在服务互斥锁内修改同一份快照，
再以「临时文件 + rename」原子替换落盘。因此像「消费挑战 + 建立设备」「禁用设备 +
中止轮换」这类多步修改对外原子可见；进程重启后自动恢复。路径为空时退化为纯内存存储。

> 该存储适合单实例/演示场景；多实例部署需把快照替换为带事务的数据库实现
> （服务内全部变更点都集中在同一临界区，移植时对应为一个数据库事务）。

## HTTP 接口

字节串字段（attributes/public_key/signature/message）使用 base64 **RawURLEncoding**，
可通过 `deviceenrollment.EncodeBase64` 编码。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/admin/challenges` | 管理员为租户签发挑战 |
| POST | `/devices/register` | 设备注册（幂等） |
| GET  | `/devices/{id}` | 查询设备 |
| GET  | `/devices/{id}/ownership` | 查询归属链与每次转移的两端决定/版本变化 |
| POST | `/devices/{id}/rotations` | 发起密钥轮换 |
| POST | `/devices/{id}/authenticate` | 认证校验（成功 204） |
| POST | `/devices/{id}/disable` | 管理员禁用设备 |
| POST | `/devices/{id}/transfers` | 源租户发起跨租户转移（幂等） |
| GET  | `/rotations/{id}` | 查询轮换单（惰性结算超时） |
| POST | `/rotations/{id}/confirm` | 提交旧/新钥确认（可一次或分次） |
| POST | `/rotations/{id}/cancel` | 当前钥取消轮换 |
| GET  | `/transfers/{id}` | 查询转移单（不含凭据/公钥/证明） |
| POST | `/transfers/{id}/accept` | 目标租户凭凭据 + 新公钥证明接收设备 |
| POST | `/transfers/{id}/cancel` | 源租户取消转移 |
| POST | `/admin/rotations/sweep` | 显式结算所有超时轮换 |
| POST | `/admin/transfers/sweep` | 显式结算所有过期转移凭据 |

错误响应统一为 `{"code": "...", "message": "..."}`，错误码到 HTTP 状态码的映射：

| 错误码 | 状态码 |
| --- | --- |
| `invalid_argument` | 400 |
| `challenge_not_found` / `device_not_found` / `rotation_not_found` / `key_version_not_found` / `transfer_not_found` | 404 |
| `challenge_secret_mismatch` / `attestation_failed` / `signature_invalid` / `credential_mismatch` | 401 |
| `device_disabled` / `transfer_tenant_mismatch` | 403 |
| `challenge_expired` / `credential_expired` | 410 |
| `challenge_consumed` / `challenge_attribute_mismatch` / `idempotency_conflict` / `key_version_invalid` / `rotation_in_progress` / `rotation_closed` / `transfer_in_progress` / `transfer_closed` / `transfer_version_mismatch` | 409 |

## 典型调用流程

### 1. 管理员签发挑战

```jsonc
// POST /admin/challenges
{
  "tenant_id": "tenant-a",       // 设备注册成功后的初始归属租户
  "external_id": "sn-0001",
  "attributes": "bW9kZWwtQQ",   // base64("model-A")
  "ttl": "5m"                    // 可选，缺省用服务默认 15m
}
// 201 -> {"id": "C...", "secret": "k..."}   // secret 只出现这一次
```

### 2. 设备注册

设备用初始 ed25519 私钥对规范报文

```
ENROLL|<challengeID>|<externalID>|<attributes>|<publicKey>
```

（可由 `EnrollAttestationMessage` 生成）签名，作为 attestation：

```jsonc
// POST /devices/register
{
  "challenge_id": "C...",
  "secret": "k...",
  "external_id": "sn-0001",
  "attributes": "bW9kZWwtQQ",
  "public_key": "<base64 ed25519 公钥>",
  "attestation": "<base64 签名>"
}
```

同号同内容重试返回同一个设备 `id`；同号异内容返回 409 `idempotency_conflict`。

### 3. 认证

设备对业务报文用当前私钥签名，请求中带上租户标识与当前 `key_version`：

```jsonc
// POST /devices/{id}/authenticate
{"tenant_id": "tenant-a", "key_version": 1, "message": "<base64>", "signature": "<base64>"}
```

设备转移到新租户后，源租户的认证得到 403 `transfer_tenant_mismatch`；
旧密钥版本的迟到认证得到 409 `key_version_invalid`。

### 4. 跨租户设备转移

1. **源租户发起** `POST /devices/{id}/transfers`，冻结设备身份/当前密钥版本/目标租户：

   ```jsonc
   {"request_id": "tx-0001", "source_tenant": "tenant-a", "target_tenant": "tenant-b", "ttl": "15m"}
   // 201 -> {"transfer": {...,"status":"pending","frozen_version":1},
   //         "credential": "k..."}          // 一次性凭据，只出现这一次；重放不再返回
   ```

   `request_id` 是幂等号：同号同内容重放返回首次转移单，同号异内容返回 409。
   设备已禁用、存在未完成轮换或已有活动转移时拒绝发起。

2. **目标租户接收** `POST /transfers/{id}/accept`，必须同时给出凭据、新公钥，以及**新私钥**对

   ```
   TRANSFER_ACCEPT|<transferID>|<deviceID>|<targetTenant>|<frozenVersion>|<newPublicKey>
   ```

   （`TransferAcceptMessage`）的证明：

   ```jsonc
   {
     "credential": "k...",
     "target_tenant": "tenant-b",
     "new_public_key": "<base64 ed25519 新公钥>",
     "attestation": "<base64 新私钥签名>"
   }
   ```

   成功即在同一原子变更内：归属切到 `tenant-b`、新密钥版本生效、源租户全部密钥失效。
   凭据错误（401 `credential_mismatch`）、证明失败（401 `attestation_failed`）、
   冻结版本已变化（409 `transfer_version_mismatch`）或目标租户不符（403）都会整体失败，
   设备归属与密钥保持原状，凭据不被消费。同内容重放返回首次结果；换一把新公钥重复接收
   返回 409 `transfer_closed`。

3. **源租户取消**（接收前）`POST /transfers/{id}/cancel`：`{"source_tenant":"tenant-a"}`；
   凭据超过窗口未接收则变为 `expired`（查询时惰性结算，也可调
   `POST /admin/transfers/sweep` 批量结算）。取消/过期都不改变设备归属与密钥。

4. **查询**：`GET /transfers/{id}` 返回转移单（无凭据/公钥/证明）；
   `GET /devices/{id}/ownership` 返回当前归属、完整归属链与每次转移的两端决定和版本变化。

### 5. 密钥轮换

1. `POST /devices/{id}/rotations`，body 为新公钥与**当前钥**对
   `ROTATION_BEGIN|<deviceID>|<newPublicKey>`（`RotationBeginMessage`）的签名，得到轮换单。
2. 旧钥与新钥分别对
   `ROTATION_CONFIRM|<deviceID>|<rotationID>|<oldVersion>|<newVersion>`
   （`RotationConfirmMessage`）签名，调用 `/rotations/{id}/confirm`
   （可在一次请求的 `confirmations` 里给齐两个，也可分两次）。
3. 两侧齐备即完成：返回 `confirmed`，此后旧版本立即不能认证。
4. 需要放弃时，当前钥对 `RotationCancelMessage` 签名调用 `/rotations/{id}/cancel`；
   超过窗口未完成则变为 `timed_out`（查询时惰性结算，也可由管理员调 sweep 批量结算）。

### 6. 禁用

`POST /devices/{id}/disable`：设备变 `disabled`、所有密钥失效、打开的轮换与活动转移
变 `aborted`，随后任何认证都返回 403。

## 作为库使用

```go
svc, err := deviceenrollment.New(deviceenrollment.Config{
    Store:          deviceenrollment.NewFileStore("data/state.json"), // 或 NewMemoryStore()
    Clock:          deviceenrollment.SystemClock(),
    ChallengeTTL:   15 * time.Minute,
    RotationWindow: 10 * time.Minute,
    TransferTTL:    15 * time.Minute,
})

ch, err := svc.IssueChallenge("tenant-a", "sn-0001", []byte("model-A"), 5*time.Minute)

dev, err := svc.Register(deviceenrollment.RegisterRequest{
    ChallengeID: ch.ID,
    Secret:      ch.Secret,
    ExternalID:  "sn-0001",
    Attributes:  []byte("model-A"),
    PublicKey:   pub,
    Attestation: attestationSig,
})

// 源租户发起转移（credential 明文仅此一次）
tr, credential, err := svc.BeginTransfer("tx-0001", dev.ID, "tenant-a", "tenant-b", 15*time.Minute)

// 目标租户用新私钥对 TransferAcceptMessage(...) 签名后接收
accView, err := svc.AcceptTransfer(deviceenrollment.AcceptTransferRequest{
    TransferID:   tr.ID,
    Credential:   credential,
    TargetTenant: "tenant-b",
    NewPublicKey: newPub,
    Attestation:  newPrivSig,
})
```

启动 HTTP 服务：

```sh
go run ./cmd/server -addr :8080 -state data/state.json
```

## 安全说明

### 机密存储

- 挑战秘密与转移接收凭据都使用每凭据独立随机盐 + HMAC-SHA256 存储，明文与摘要均不落
  日志/快照；比较使用恒定时间比较。
- 明文秘密/凭据只在各自签发响应中出现一次：挑战秘密在 `IssueChallenge`，转移凭据在首次
  `BeginTransfer`；幂等重放只返回单据视图，不再回吐明文。
- 目标租户接收时提交的公钥证明（attestation 签名）只在请求处理期间存在，不持久化；
  新公钥在成功后进入设备密钥集。归属历史与转移单视图都不返回凭据、公钥或证明内容。

### 身份与密钥绑定

- 注册证明把挑战号、外部号、属性、公钥绑定在同一份签名报文里，防止属性/公钥替换。
- 轮换的发起、确认、取消分别要求对应私钥签名，且完成与旧钥失效在同一原子变更内发生。
- 转移接收证明把转移单号、设备号、目标租户、发起时冻结的密钥版本与新公钥绑定在同一份
  报文 `TRANSFER_ACCEPT|...` 中，缺一不可：换目标租户、换设备、换公钥都会导致验签失败，
  从而无法用一张凭据把设备接收到别处或替换成他人公钥。

### 设备转移的安全边界

- **发起授权**：只有设备当前归属租户能发起转移；设备已禁用、存在未完成轮换、或已有活动
  转移时一律拒绝。活动转移期间同样禁止发起新轮换，保证“冻结版本”在窗口内不被轮换改变。
- **接收三要素**：凭据（持有即一次性接收权）、新公钥证明（新私钥确实在授权这次接收）、
  冻结版本（设备在发起后未被改动）必须同时成立；任一不匹配整笔失败。
- **原子性**：归属切换、新密钥版本生效、源租户全部密钥失效、归属链追加在同一次快照变更内
  完成，不存在“归属已变但新密钥未生效”或反之的中间态。
- **终态唯一**：接收、源租户取消、凭据过期、设备禁用中止并发时，`pending` 只迁出一次，
  由服务互斥锁与原子快照保证只有一个终态。
- **旧资格即时失效**：接收成功后源租户的全部密钥（含历史版本与任何 pending 钥）立即
  invalidated。源租户的迟到认证因租户不再匹配被拒；旧轮换的迟到确认因轮换已终态被拒；
  二者都不能覆盖新归属。
- **不可重复接收**：已 `accepted` 的转移，同内容重放幂等返回首次结果，换公钥/换租户的
  重复接收返回 `transfer_closed`，一台设备不会被接收第二次、也不会产生第二个新版本。
- **取消/过期不影响归属**：取消与过期只关闭转移单，设备仍属源租户、源密钥继续可用；
  过期凭据随惰性结算或显式 sweep 失效，窗口边界（含 deadline 当刻）与轮换一致。
- **幂等冲突**：发起幂等号与接收内容都做摘要比对，同号异内容返回
  `idempotency_conflict`，防止重试被利用来改变目标租户或新公钥。

### 部署边界

- 示例服务未包含租户/管理员鉴权中间件与传输层安全：`tenant_id`、`source_tenant` 等字段
  在本实现中是“声明即采用”，生产部署必须在入口处由可信鉴权层强制校验调用方身份与租户
  归属，并在 `/admin/*` 前加管理员鉴权；全部链路应使用 TLS，避免凭据与签名明文外泄。
- JSON 快照文件按 0600 权限写入，但其中仍含设备公钥与凭据摘要，应放置于受控目录并加密
  静态存储；多实例部署需把快照替换为带事务的数据库实现（服务内全部变更点都集中在同一
  临界区，移植时对应为一个数据库事务）。

## 运行测试

    go test ./...            # 全套单元 + 并发竞态 + HTTP 端到端 + 持久化重启测试
    go test -race ./...      # 带竞态检测

测试覆盖：挑战摘要存储/过期/属性绑定/证明失败；注册幂等、同号异内容冲突、
32 路并发单挑战；轮换正常完成（含旧钥即时失效、迟到旧版本认证被拒）、
确认原子性、取消、超时（含 deadline 边界与惰性结算）、确认/取消/超时 20 轮混跑竞争；
禁用级联中止；快照落盘与重启恢复。

设备转移部分覆盖：发起冻结与凭据仅存摘要（视图/序列化快照不含明文）、发起前置守卫
（禁用/未完成轮换/活动转移/非归属租户）、发起幂等同号同内容与同号异内容冲突；
接收原子切换与源租户认证资格即时失效、凭据/证明/租户/版本各类失败不留中间态且不消费凭据、
同内容幂等重放与换钥重复接收被拒；源租户取消、凭据过期（deadline 边界）、
接收/取消/过期 25 轮并发竞争唯一终态；迟到轮换确认不能覆盖新归属；
A→B→C 多跳归属链与每次转移两端决定/版本变化查询且不泄露凭据公钥；
转移状态落盘重启恢复；转移 HTTP 端到端与归属历史敏感内容隔离。
