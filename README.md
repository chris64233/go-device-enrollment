# go-device-enrollment

基于一次性挑战（challenge）的设备注册服务，并支持注册后的密钥轮换、跨租户受控转移、
禁用与认证校验。纯 Go 标准库实现，无第三方依赖。

开发环境：Go 1.23.0。

## 能力概览

- **挑战签发（管理员）**：挑战短期有效，绑定预期的外部注册号、设备属性与**初始归属租户**；
  数据库只保存挑战秘密的加盐 HMAC-SHA256 摘要，明文秘密仅在签发响应中出现一次。
- **设备注册**：设备携带 ed25519 公钥及私钥对注册报文的证明（attestation）完成注册，
  同时建立归属链第一站。
  - 外部注册号与注册内容（属性 + 公钥）都相同的重复调用幂等返回原设备身份；
  - 同号异内容返回 `idempotency_conflict`，且不会覆盖既有设备；
  - 挑战只能被成功消费一次，并发使用同一挑战只有一个注册成功。
- **密钥轮换**：
  - 由当前密钥签名发起，登记一把 `pending` 新钥并打开有限确认窗口（默认 10 分钟）；
  - 旧钥与新钥在窗口内分别对同一轮换报文签名确认，两侧齐备的瞬间轮换原子完成，
    旧钥立即失效、新钥生效，设备版本（version）同时 +1；
  - 支持当前钥取消、窗口超时（惰性 + 显式 sweep）、管理员禁用中止、转移接受时连带中止；
  - 确认、取消、超时、中止互相竞争，轮换只产生一个终态，迟到操作一律被拒绝。
- **跨租户受控转移**：
  - 源租户发起时**冻结**设备身份、当前密钥版本、设备版本与目标租户，并签发短期有效的
    **一次性接收凭据**（默认 15 分钟）；凭据明文只在发起响应中出现，落盘仅有盐与加盐
    HMAC-SHA256 摘要；
  - 目标租户接受时必须同时提交新公钥与新私钥对规范报文的证明；证明、凭据、设备版本
    三者全部通过后才在同一个原子变更内：切换归属 → 登记并启用新密钥版本 → 失效设备
    此前全部密钥（源租户认证资格立即终止）→ 追加归属链；任一不匹配整单失败、零副作用，
    不存在「归属已变但新密钥未生效」的中间态；
  - 接受、源租户取消、凭据过期（惰性 + 显式 sweep）、设备禁用中止互相竞争，
    `pending` 只迁出一次，终态唯一；目标租户不可能重复接收同一设备；
  - 转移号（源租户提供的幂等号）同号同内容返回首次转移单，同号异内容返回
    `idempotency_conflict`。
- **认证**：请求必须携带设备当前有效的密钥版本号并以对应私钥签名。
  使用旧版本密钥（包括转移后旧租户的迟到请求）得到 `key_version_invalid`，无法覆盖新状态。
- **归属链查询**：返回设备每一站归属、关联转移单两端决定与密钥版本变化；
  视图不包含凭据、凭据摘要/盐或任何证明签名材料。
- **禁用（管理员）**：在同一个持久化快照变更中终止设备注册有效性、失效全部密钥，
  并把待处理轮换与活动转移原子中止（分别为 `aborted`）。禁用幂等，可重复调用。
- **统一时钟**：挑战过期、轮换窗口与转移接收窗口判断都经由可替换的 `Clock` 接口，
  生产用 UTC 墙钟，测试用可推进的固定时钟。

## 数据模型与状态

```
ChallengeRecord  id, salt, secret_digest, external_id, tenant_id, attributes,
                 expires_at, consumed, consumed_at, consumed_by_device

DeviceRecord     id, external_id, attributes, content_hash,
                 tenant_id(当前归属), version(设备版本，单调递增),
                 status(active|disabled), current_key_version, keys[]{version,state}

KeyRecord        version, public_key, state(active|pending|invalidated)

RotationRecord   id, device_id, old_version, new_version,
                 old_key_confirmed, new_key_confirmed,
                 status(pending|confirmed|cancelled|timed_out|aborted),
                 deadline, created_at, completed_at

TransferRecord   id, idempotency_key, content_hash, device_id,
                 source_tenant_id, target_tenant_id,
                 frozen_key_version, frozen_device_version,
                 credential_salt, credential_digest,
                 status(pending|accepted|cancelled|expired|aborted),
                 source_decision, target_decision, accepted_new_key_version,
                 deadline, created_at, resolved_at

OwnershipEvent   seq, tenant_id, transfer_id, from_version, to_version, at
```

轮换状态机（`pending` 只允许迁出一次）：

```
                 ┌── confirmed（旧新钥都确认；旧钥失效，新钥生效，设备版本 +1）
pending ─────────┼── cancelled（当前钥取消；pending 新钥失效）
                 ├── timed_out（超过确认窗口；pending 新钥失效）
                 └── aborted  （设备被禁用或转移被接受；pending 新钥失效）
```

转移状态机（同样 `pending` 只允许迁出一次）：

```
                 ┌── accepted  （凭据+证明+设备版本三匹配；归属切换、新钥生效、旧钥全失效）
pending ─────────┼── cancelled（源租户用冻结的当前钥签名取消）
                 ├── expired   （超过接收窗口，凭据失效；惰性/sweep 结算）
                 └── aborted   （设备被禁用）
```

转移发起后设备版本被冻结；若窗口内源租户完成了一次密钥轮换，设备版本前进，
随后的接受以 `device_version_mismatch` 失败；接受时轮换仍 pending 则随转移原子中止。

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
| POST | `/admin/challenges` | 管理员签发挑战 |
| POST | `/devices/register` | 设备注册（幂等） |
| GET  | `/devices/{id}` | 查询设备 |
| GET  | `/devices/{id}/ownership` | 查询归属链、各次转移决定与密钥版本变化 |
| POST | `/devices/{id}/rotations` | 发起密钥轮换 |
| POST | `/devices/{id}/authenticate` | 认证校验（成功 204） |
| POST | `/devices/{id}/disable` | 管理员禁用设备 |
| GET  | `/rotations/{id}` | 查询轮换单（惰性结算超时） |
| POST | `/rotations/{id}/confirm` | 提交旧/新钥确认（可一次或分次） |
| POST | `/rotations/{id}/cancel` | 当前钥取消轮换 |
| POST | `/admin/rotations/sweep` | 显式结算所有超时轮换 |
| POST | `/devices/{id}/transfers` | 源租户发起设备转移（需转移号） |
| GET  | `/transfers/{id}` | 查询转移单（惰性结算过期；不返回凭据/证明） |
| POST | `/transfers/{id}/accept` | 目标租户提交凭据 + 新公钥 + 证明接受 |
| POST | `/transfers/{id}/cancel` | 源租户冻结钥签名取消 |
| POST | `/admin/transfers/sweep` | 显式结算所有过期转移 |

错误响应统一为 `{"code": "...", "message": "..."}`，错误码到 HTTP 状态码的映射：

| 错误码 | 状态码 |
| --- | --- |
| `invalid_argument` | 400 |
| `challenge_not_found` / `device_not_found` / `rotation_not_found` / `key_version_not_found` / `transfer_not_found` | 404 |
| `challenge_secret_mismatch` / `attestation_failed` / `signature_invalid` / `transfer_credential_mismatch` | 401 |
| `device_disabled` / `tenant_mismatch` | 403 |
| `challenge_expired` / `transfer_expired` | 410 |
| `challenge_consumed` / `challenge_attribute_mismatch` / `idempotency_conflict` / `key_version_invalid` / `rotation_in_progress` / `rotation_closed` / `transfer_in_progress` / `transfer_closed` / `device_version_mismatch` | 409 |

## 典型调用流程

### 1. 管理员签发挑战

```jsonc
// POST /admin/challenges
{
  "external_id": "sn-0001",
  "tenant_id":   "tenant-a",     // 设备注册后的初始归属租户
  "attributes":  "bW9kZWwtQQ",  // base64("model-A")
  "ttl":         "5m"           // 可选，缺省用服务默认 15m
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

设备对业务报文用当前私钥签名，请求中带上当前 `key_version`：

```jsonc
// POST /devices/{id}/authenticate
{"key_version": 1, "message": "<base64>", "signature": "<base64>"}
```

### 4. 密钥轮换

1. `POST /devices/{id}/rotations`，body 为新公钥与**当前钥**对
   `ROTATION_BEGIN|<deviceID>|<newPublicKey>`（`RotationBeginMessage`）的签名，得到轮换单。
2. 旧钥与新钥分别对
   `ROTATION_CONFIRM|<deviceID>|<rotationID>|<oldVersion>|<newVersion>`
   （`RotationConfirmMessage`）签名，调用 `/rotations/{id}/confirm`
   （可在一次请求的 `confirmations` 里给齐两个，也可分两次）。
3. 两侧齐备即完成：返回 `confirmed`，此后旧版本立即不能认证。
4. 需要放弃时，当前钥对 `RotationCancelMessage` 签名调用 `/rotations/{id}/cancel`；
   超过窗口未完成则变为 `timed_out`（查询时惰性结算，也可由管理员调 sweep 批量结算）。

### 5. 禁用

`POST /devices/{id}/disable`：设备变 `disabled`、所有密钥失效、打开的轮换变 `aborted`，
随后任何认证都返回 403。

### 6. 跨租户转移

1. **源租户发起**（冻结当前身份/密钥版本/设备版本 + 目标租户，并得到一次性凭据）：

   ```jsonc
   // POST /devices/{id}/transfers
   {
     "source_tenant_id": "tenant-a",
     "target_tenant_id": "tenant-b",
     "idempotency_key":  "tx-2026-001",   // 源租户转移号
     "ttl":              "15m"            // 可选，缺省默认 15m
   }
   // 201 -> {"id": "T...", "credential": "k..."}   // credential 只出现这一次
   ```

2. **目标租户接受**（凭据、新公钥、证明同时提交；证明由**新私钥**对
   `TRANSFER_ACCEPT|<transferID>|<deviceID>|<sourceTenantID>|<targetTenantID>|<newPublicKey>`
   （`TransferAcceptMessage`）签名）：

   ```jsonc
   // POST /transfers/{id}/accept
   {
     "credential":       "k...",
     "target_tenant_id": "tenant-b",
     "new_public_key":   "<base64 ed25519 公钥>",
     "attestation":      "<base64 签名>"
   }
   ```

   接受成功即在同一原子变更内完成归属切换、新钥 v(N+1) 生效、旧钥全部失效，
   并追加归属链；证明/凭据/设备版本任一不匹配整单失败，设备与转移单不变。

3. **取消**：源租户用发起时冻结的当前钥对
   `TRANSFER_CANCEL|<deviceID>|<transferID>`（`TransferCancelMessage`）签名，
   调用 `/transfers/{id}/cancel`；凭据过期则 `pending → expired`（查询时惰性结算，
   也可 `POST /admin/transfers/sweep` 批量结算）。
4. **归属链查询** `GET /devices/{id}/ownership`：展示每站归属、关联转移单的
   源端（requested/cancelled/aborted）与目标端决定（none/accepted）及密钥版本变化，
   不含凭据、盐、摘要、公钥或证明签名。

## 作为库使用

```go
svc, err := deviceenrollment.New(deviceenrollment.Config{
    Store:          deviceenrollment.NewFileStore("data/state.json"), // 或 NewMemoryStore()
    Clock:          deviceenrollment.SystemClock(),
    ChallengeTTL:   15 * time.Minute,
    RotationWindow: 10 * time.Minute,
    TransferTTL:    15 * time.Minute,
})

ch, err := svc.IssueChallenge("sn-0001", "tenant-a", []byte("model-A"), 5*time.Minute)

dev, err := svc.Register(deviceenrollment.RegisterRequest{
    ChallengeID: ch.ID,
    Secret:      ch.Secret,
    ExternalID:  "sn-0001",
    Attributes:  []byte("model-A"),
    PublicKey:   pub,
    Attestation: attestationSig,
})
```

跨租户转移（库调用）：

```go
// 源租户发起
tr, err := svc.BeginTransfer(deviceenrollment.BeginTransferRequest{
    DeviceID: dev.ID, SourceTenantID: "tenant-a", TargetTenantID: "tenant-b",
    IdempotencyKey: "tx-2026-001",
})
// tr.Credential 通过带外渠道交给目标租户，仅此一次

// 目标租户接受：新私钥对 TransferAcceptMessage 签名
att := ed25519.Sign(newPriv, deviceenrollment.TransferAcceptMessage(
    tr.ID, dev.ID, "tenant-a", "tenant-b", newPub))
view, err := svc.AcceptTransfer(deviceenrollment.AcceptTransferRequest{
    TransferID: tr.ID, Credential: tr.Credential, TargetTenantID: "tenant-b",
    NewPublicKey: newPub, Attestation: att,
})
```

启动 HTTP 服务：

```sh
go run ./cmd/server -addr :8080 -state data/state.json
```

## 安全边界说明

- **秘密只存摘要**：注册挑战秘密与转移接收凭据都使用每单独立随机盐 + HMAC-SHA256
  存储，明文与摘要均不落日志/快照；比较一律使用恒定时间比较。凭据明文只在发起响应中
  出现一次，幂等重放不再展示；凭据丢失只能由源租户取消后重新发起。
- **证明绑定完整上下文**：注册证明绑定挑战号/外部号/属性/公钥；转移接受证明绑定
  转移单号/设备/源租户/目标租户/新公钥。凭据无法被重放到别的设备、别的租户或替换成
  别的公钥。
- **转移接受的原子性**：凭据、目标租户、设备版本、证明全部校验通过之前不写任何状态；
  通过后归属切换、新钥启用、旧钥全部失效、归属链追加在同一次快照原子写内完成，
  不存在「归属已变但新密钥未生效」的中间态。
- **旧租户资格即时、单向失效**：接受成功后设备此前所有密钥版本一律 `invalidated`，
  旧租户的迟到认证得到 `key_version_invalid`，迟到的轮换确认得到 `rotation_closed`，
  都无法覆盖新归属；新归属钥生效前设备仍属于源租户，转移可由源租户取消或自然过期。
- **终态唯一与防重放**：转移 `pending` 只迁出一次，接受/取消/过期/禁用竞争只产生一个
  终态；凭据一次性使用，目标租户不能重复接收同一设备。转移发起要求设备 active、
  无未终态轮换、无活动转移。
- **租户身份边界**：源/目标租户身份是请求的显式参数，服务校验「发起方=当前归属租户」
  「接受方=冻结的目标租户」「取消方=源租户 + 冻结钥签名」。示例 HTTP 服务**没有**
  租户身份认证/授权中间件——部署方必须在边界处认证调用方租户身份并与请求体核对，
  不能让调用方自行声明租户。
- **信息暴露边界**：设备视图只返回当前公钥；转移单与归属链视图不返回凭据、凭据摘要/
  盐、证明签名，也不返回历史公钥。
- **传输与管理面**：示例服务未包含管理员鉴权中间件与传输层安全，生产部署应在
  `/admin/*` 前加鉴权、全部链路使用 TLS，并通过带外安全渠道向目标租户转交接收凭据。

## 运行测试

    go test ./...            # 全套单元 + 并发竞态 + HTTP 端到端 + 持久化重启测试
    go test -race ./...      # 带竞态检测

测试覆盖：挑战摘要存储/过期/属性绑定/证明失败；注册幂等、同号异内容冲突、
32 路并发单挑战；轮换正常完成（含旧钥即时失效、迟到旧版本认证被拒）、
确认原子性、取消、超时（含 deadline 边界与惰性结算）、确认/取消/超时 20 轮混跑竞争；
禁用级联中止；快照落盘与重启恢复。

转移新增覆盖：凭据摘要存储且不入快照明文；发起守卫（禁用/未终态轮换/活动转移/
非属主/同租户）；接受成功路径（归属、设备版本、新钥版本、旧钥全失效、防重复接收）；
凭据/租户/证明/公钥/设备版本各类不匹配的零副作用；接受时原子中止 pending 轮换且
迟到确认被拒；源租户取消（签名与租户校验、取消后凭据失效）；过期的 deadline 边界、
惰性结算与 sweep；接受/双接受/取消/过期 25 轮混跑竞争终态唯一；禁用中止活动转移；
转移号幂等同内容返回首次、异内容冲突、按源租户隔离；多跳归属链与旧租户认证失效；
视图不含凭据/证明等敏感字段；持久化重启恢复；HTTP 端到端（含 401/403/409/410）。
