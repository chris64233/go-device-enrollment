# go-device-enrollment

基于一次性挑战（challenge）的设备注册服务，并支持注册后的密钥轮换、禁用与认证校验。
纯 Go 标准库实现，无第三方依赖。

开发环境：Go 1.23.0。

## 能力概览

- **挑战签发（管理员）**：挑战短期有效，绑定预期的外部注册号与设备属性；数据库只保存
  挑战秘密的加盐 HMAC-SHA256 摘要，明文秘密仅在签发响应中出现一次。
- **设备注册**：设备携带 ed25519 公钥及私钥对注册报文的证明（attestation）完成注册。
  - 外部注册号与注册内容（属性 + 公钥）都相同的重复调用幂等返回原设备身份；
  - 同号异内容返回 `idempotency_conflict`，且不会覆盖既有设备；
  - 挑战只能被成功消费一次，并发使用同一挑战只有一个注册成功。
- **密钥轮换**：
  - 由当前密钥签名发起，登记一把 `pending` 新钥并打开有限确认窗口（默认 10 分钟）；
  - 旧钥与新钥在窗口内分别对同一轮换报文签名确认，两侧齐备的瞬间轮换原子完成，
    旧钥立即失效、新钥生效；
  - 支持当前钥取消、窗口超时（惰性 + 显式 sweep）、管理员禁用中止；
  - 确认、取消、超时、中止互相竞争，轮换只产生一个终态，迟到操作一律被拒绝。
- **认证**：请求必须携带设备当前有效的密钥版本号并以对应私钥签名。
  使用旧版本密钥的迟到请求得到 `key_version_invalid`，无法覆盖新状态。
- **禁用（管理员）**：在同一个持久化快照变更中终止设备注册有效性、失效全部密钥，
  并把待处理轮换原子中止（`aborted`）。禁用幂等，可重复调用。
- **统一时钟**：挑战过期与轮换窗口判断都经由可替换的 `Clock` 接口，生产用 UTC 墙钟，
  测试用可推进的固定时钟。

## 数据模型与状态

```
ChallengeRecord  id, salt, secret_digest, external_id, attributes,
                 expires_at, consumed, consumed_at, consumed_by_device

DeviceRecord     id, external_id, attributes, content_hash,
                 status(active|disabled), current_key_version, keys[]{version,state}

KeyRecord        version, public_key, state(active|pending|invalidated)

RotationRecord   id, device_id, old_version, new_version,
                 old_key_confirmed, new_key_confirmed,
                 status(pending|confirmed|cancelled|timed_out|aborted),
                 deadline, created_at, completed_at
```

轮换状态机（`pending` 只允许迁出一次）：

```
                 ┌── confirmed（旧新钥都确认；旧钥失效，新钥生效）
pending ─────────┼── cancelled（当前钥取消；pending 新钥失效）
                 ├── timed_out（超过确认窗口；pending 新钥失效）
                 └── aborted  （设备被禁用；pending 新钥失效）
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
| POST | `/admin/challenges` | 管理员签发挑战 |
| POST | `/devices/register` | 设备注册（幂等） |
| GET  | `/devices/{id}` | 查询设备 |
| POST | `/devices/{id}/rotations` | 发起密钥轮换 |
| POST | `/devices/{id}/authenticate` | 认证校验（成功 204） |
| POST | `/devices/{id}/disable` | 管理员禁用设备 |
| GET  | `/rotations/{id}` | 查询轮换单（惰性结算超时） |
| POST | `/rotations/{id}/confirm` | 提交旧/新钥确认（可一次或分次） |
| POST | `/rotations/{id}/cancel` | 当前钥取消轮换 |
| POST | `/admin/rotations/sweep` | 显式结算所有超时轮换 |

错误响应统一为 `{"code": "...", "message": "..."}`，错误码到 HTTP 状态码的映射：

| 错误码 | 状态码 |
| --- | --- |
| `invalid_argument` | 400 |
| `challenge_not_found` / `device_not_found` / `rotation_not_found` / `key_version_not_found` | 404 |
| `challenge_secret_mismatch` / `attestation_failed` / `signature_invalid` | 401 |
| `device_disabled` | 403 |
| `challenge_expired` | 410 |
| `challenge_consumed` / `challenge_attribute_mismatch` / `idempotency_conflict` / `key_version_invalid` / `rotation_in_progress` / `rotation_closed` | 409 |

## 典型调用流程

### 1. 管理员签发挑战

```jsonc
// POST /admin/challenges
{
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

## 作为库使用

```go
svc, err := deviceenrollment.New(deviceenrollment.Config{
    Store:          deviceenrollment.NewFileStore("data/state.json"), // 或 NewMemoryStore()
    Clock:          deviceenrollment.SystemClock(),
    ChallengeTTL:   15 * time.Minute,
    RotationWindow: 10 * time.Minute,
})

ch, err := svc.IssueChallenge("sn-0001", []byte("model-A"), 5*time.Minute)

dev, err := svc.Register(deviceenrollment.RegisterRequest{
    ChallengeID: ch.ID,
    Secret:      ch.Secret,
    ExternalID:  "sn-0001",
    Attributes:  []byte("model-A"),
    PublicKey:   pub,
    Attestation: attestationSig,
})
```

启动 HTTP 服务：

```sh
go run ./cmd/server -addr :8080 -state data/state.json
```

## 安全说明

- 挑战秘密使用每挑战独立随机盐 + HMAC-SHA256 存储，明文与摘要均不落日志/快照；
  秘密比较使用恒定时间比较。
- 注册证明把挑战号、外部号、属性、公钥绑定在同一份签名报文里，防止属性/公钥替换。
- 轮换的发起、确认、取消分别要求对应私钥签名，且完成与旧钥失效在同一原子变更内发生。
- 示例服务未包含管理员鉴权中间件与传输层安全，生产部署应在 `/admin/*` 前加鉴权并使用 TLS。

## 运行测试

    go test ./...            # 全套单元 + 并发竞态 + HTTP 端到端 + 持久化重启测试
    go test -race ./...      # 带竞态检测

测试覆盖：挑战摘要存储/过期/属性绑定/证明失败；注册幂等、同号异内容冲突、
32 路并发单挑战；轮换正常完成（含旧钥即时失效、迟到旧版本认证被拒）、
确认原子性、取消、超时（含 deadline 边界与惰性结算）、确认/取消/超时 20 轮混跑竞争；
禁用级联中止；快照落盘与重启恢复。
