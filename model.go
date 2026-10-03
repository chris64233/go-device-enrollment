package deviceenrollment

import "time"

// 设备状态。
const (
	// DeviceStatusActive 设备已注册且有效。
	DeviceStatusActive = "active"
	// DeviceStatusDisabled 设备已被管理员禁用，注册有效性终止。
	DeviceStatusDisabled = "disabled"
)

// 密钥版本状态。
const (
	// KeyStateActive 当前生效密钥，可用于认证与发起状态变更。
	KeyStateActive = "active"
	// KeyStatePending 轮换中预分配的新密钥，尚未生效，仅可参与本次轮换确认。
	KeyStatePending = "pending"
	// KeyStateInvalidated 已失效密钥：轮换完成后的旧钥、终止轮换对应的新钥、禁用设备上的全部密钥。
	KeyStateInvalidated = "invalidated"
)

// 轮换终态机：pending -> confirmed | cancelled | timed_out | aborted。
// 任意时刻只允许从 pending 迁移一次，因此确认、取消、超时、禁用竞争时只有一个终态。
const (
	RotationPending   = "pending"
	RotationConfirmed = "confirmed"
	RotationCancelled = "cancelled"
	RotationTimedOut  = "timed_out"
	RotationAborted   = "aborted"
)

// 转移终态机：pending -> accepted | cancelled | expired | aborted。
// 接受、源租户取消、凭据过期、设备禁用互相竞争，但 pending 只允许迁出一次。
const (
	TransferPending   = "pending"
	TransferAccepted  = "accepted"
	TransferCancelled = "cancelled"
	TransferExpired   = "expired"
	TransferAborted   = "aborted"
)

// 转移两端的决定取值。
const (
	SourceDecisionRequested = "requested"
	SourceDecisionCancelled = "cancelled"
	SourceDecisionAborted   = "aborted"
	TargetDecisionNone      = "none"
	TargetDecisionAccepted  = "accepted"
)

// ChallengeRecord 是挑战的持久化记录。
// 明文秘密绝不落盘，只保存盐值与加盐摘要。
type ChallengeRecord struct {
	ID           string `json:"id"`
	Salt         []byte `json:"salt"`
	SecretDigest []byte `json:"secret_digest"`
	// ExternalID 与 Attributes 是管理员绑定期望设备属性：
	// 注册时的外部注册号与属性必须与之完全一致。
	ExternalID string `json:"external_id"`
	Attributes []byte `json:"attributes"`
	// TenantID 是注册完成后设备的初始归属租户。
	TenantID  string    `json:"tenant_id"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`

	Consumed         bool       `json:"consumed"`
	ConsumedAt       *time.Time `json:"consumed_at,omitempty"`
	ConsumedByDevice string     `json:"consumed_by_device,omitempty"`
}

// KeyRecord 描述某一版本的设备公钥。
type KeyRecord struct {
	Version   int       `json:"version"`
	PublicKey []byte    `json:"public_key"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
}

// DeviceRecord 是设备聚合根的持久化形态。
type DeviceRecord struct {
	ID         string `json:"id"`
	ExternalID string `json:"external_id"`
	Attributes []byte `json:"attributes"`
	// ContentHash 覆盖幂等判定所需的注册内容（属性 + 初始公钥）。
	ContentHash string `json:"content_hash"`

	// TenantID 是设备当前归属租户；每次成功转移在同一原子变更内切换。
	TenantID string `json:"tenant_id"`
	// Version 是设备版本，随每次改变密钥版本或归属的操作单调递增；
	// 转移发起时冻结该值，接受时必须与之严格匹配。
	Version int `json:"version"`

	Status            string             `json:"status"`
	CurrentKeyVersion int                `json:"current_key_version"`
	NextKeyVersion    int                `json:"next_key_version"`
	Keys              map[int]*KeyRecord `json:"keys"`
	CreatedAt         time.Time          `json:"created_at"`
}

// OwnershipEvent 记录归属链上的一站：由哪个租户转入、经由哪张转移单、密钥版本如何变化。
type OwnershipEvent struct {
	// Seq 是归属链内单调递增的序号（从 1 开始，1 即注册）。
	Seq int `json:"seq"`
	// TenantID 是该站生效后的归属租户。
	TenantID string `json:"tenant_id"`
	// TransferID 关联的转移单；注册初始归属时为空。
	TransferID string `json:"transfer_id,omitempty"`
	// FromVersion / ToVersion 是本站前后的设备当前密钥版本；注册时 FromVersion 为 0。
	FromVersion int       `json:"from_version"`
	ToVersion   int       `json:"to_version"`
	At          time.Time `json:"at"`
}

// TransferRecord 是一次跨租户设备转移的持久化记录。
// 凭据明文绝不落盘，只保存盐值与加盐摘要；证明签名也不持久化。
type TransferRecord struct {
	// IdempotencyKey 是源租户提供的转移号；同一 (源租户, 转移号) 只对应一张转移单。
	IdempotencyKey string `json:"idempotency_key"`
	// ContentHash 覆盖幂等判定所需的发起内容，用于同号异内容冲突。
	ContentHash string `json:"content_hash"`

	ID       string `json:"id"`
	DeviceID string `json:"device_id"`

	// 发起时冻结的两端与设备快照。
	SourceTenantID string `json:"source_tenant_id"`
	TargetTenantID string `json:"target_tenant_id"`
	// FrozenKeyVersion 是发起时设备当前密钥版本；接受后旧租户的该版本全部资格失效。
	FrozenKeyVersion int `json:"frozen_key_version"`
	// FrozenDeviceVersion 是发起时的设备版本；接受时必须与之匹配。
	FrozenDeviceVersion int `json:"frozen_device_version"`

	// 一次性接收凭据：只存盐与加盐 HMAC 摘要。
	CredentialSalt   []byte `json:"credential_salt"`
	CredentialDigest []byte `json:"credential_digest"`

	Status     string     `json:"status"`
	Deadline   time.Time  `json:"deadline"`
	CreatedAt  time.Time  `json:"created_at"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`

	// 两端决定与密钥版本变化（终态时落定）。
	SourceDecision string `json:"source_decision"`
	TargetDecision string `json:"target_decision"`
	// AcceptedNewKeyVersion 是接受后生效的新密钥版本；仅 accepted 时有值。
	AcceptedNewKeyVersion int `json:"accepted_new_key_version,omitempty"`
}

// Transfer 是发起转移时返回给源租户的明文视图。
// Credential 只在首次发起的响应中出现一次；幂等重放只返回转移单 ID，不再展示凭据。
type Transfer struct {
	ID         string `json:"id"`
	Credential string `json:"credential"`
}

// TransferView 是转移单的只读视图，不含凭据摘要、盐或任何证明材料。
type TransferView struct {
	ID                  string `json:"id"`
	IdempotencyKey      string `json:"idempotency_key"`
	DeviceID            string `json:"device_id"`
	SourceTenantID      string `json:"source_tenant_id"`
	TargetTenantID      string `json:"target_tenant_id"`
	FrozenKeyVersion    int    `json:"frozen_key_version"`
	FrozenDeviceVersion int    `json:"frozen_device_version"`
	Status              string `json:"status"`
	SourceDecision      string `json:"source_decision"`
	TargetDecision      string `json:"target_decision"`
	NewKeyVersion       int    `json:"new_key_version,omitempty"`

	Deadline   time.Time  `json:"deadline"`
	CreatedAt  time.Time  `json:"created_at"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
}

// OwnershipChainView 是设备归属链查询结果。
type OwnershipChainView struct {
	DeviceID  string           `json:"device_id"`
	Current   OwnershipEvent   `json:"current"`
	History   []OwnershipEvent `json:"history"`
	Transfers []TransferView   `json:"transfers"`
}

// RotationRecord 是一次密钥轮换的持久化记录。
type RotationRecord struct {
	ID       string `json:"id"`
	DeviceID string `json:"device_id"`

	OldVersion int `json:"old_version"`
	NewVersion int `json:"new_version"`

	// 新旧两把钥匙分别独立确认；二者齐备时轮换在同一事务内完成。
	OldKeyConfirmed bool `json:"old_key_confirmed"`
	NewKeyConfirmed bool `json:"new_key_confirmed"`

	Status      string     `json:"status"`
	Deadline    time.Time  `json:"deadline"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// Challenge 是签发挑战时返回给管理员的明文视图。Secret 仅在本次响应中出现。
type Challenge struct {
	ID     string `json:"id"`
	Secret string `json:"secret"`
}

// DeviceView 是设备身份的只读视图。
type DeviceView struct {
	ID                string    `json:"id"`
	ExternalID        string    `json:"external_id"`
	TenantID          string    `json:"tenant_id"`
	Version           int       `json:"version"`
	Attributes        []byte    `json:"attributes"`
	Status            string    `json:"status"`
	CurrentKeyVersion int       `json:"current_key_version"`
	PublicKey         []byte    `json:"public_key"`
	CreatedAt         time.Time `json:"created_at"`
}

// RotationView 是轮换单的只读视图。
type RotationView struct {
	ID       string `json:"id"`
	DeviceID string `json:"device_id"`

	OldVersion      int    `json:"old_version"`
	NewVersion      int    `json:"new_version"`
	OldKeyConfirmed bool   `json:"old_key_confirmed"`
	NewKeyConfirmed bool   `json:"new_key_confirmed"`
	Status          string `json:"status"`

	Deadline    time.Time  `json:"deadline"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

func deviceView(d *DeviceRecord) *DeviceView {
	v := &DeviceView{
		ID:                d.ID,
		ExternalID:        d.ExternalID,
		TenantID:          d.TenantID,
		Version:           d.Version,
		Attributes:        append([]byte(nil), d.Attributes...),
		Status:            d.Status,
		CurrentKeyVersion: d.CurrentKeyVersion,
		CreatedAt:         d.CreatedAt,
	}
	if k := d.Keys[d.CurrentKeyVersion]; k != nil {
		v.PublicKey = append([]byte(nil), k.PublicKey...)
	}
	return v
}

func rotationView(r *RotationRecord) *RotationView {
	return &RotationView{
		ID:              r.ID,
		DeviceID:        r.DeviceID,
		OldVersion:      r.OldVersion,
		NewVersion:      r.NewVersion,
		OldKeyConfirmed: r.OldKeyConfirmed,
		NewKeyConfirmed: r.NewKeyConfirmed,
		Status:          r.Status,
		Deadline:        r.Deadline,
		CreatedAt:       r.CreatedAt,
		CompletedAt:     r.CompletedAt,
	}
}

func transferView(t *TransferRecord) *TransferView {
	return &TransferView{
		ID:                  t.ID,
		IdempotencyKey:      t.IdempotencyKey,
		DeviceID:            t.DeviceID,
		SourceTenantID:      t.SourceTenantID,
		TargetTenantID:      t.TargetTenantID,
		FrozenKeyVersion:    t.FrozenKeyVersion,
		FrozenDeviceVersion: t.FrozenDeviceVersion,
		Status:              t.Status,
		SourceDecision:      t.SourceDecision,
		TargetDecision:      t.TargetDecision,
		NewKeyVersion:       t.AcceptedNewKeyVersion,
		Deadline:            t.Deadline,
		CreatedAt:           t.CreatedAt,
		ResolvedAt:          t.ResolvedAt,
	}
}
