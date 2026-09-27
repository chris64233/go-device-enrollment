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

// ChallengeRecord 是挑战的持久化记录。
// 明文秘密绝不落盘，只保存盐值与加盐摘要。
type ChallengeRecord struct {
	ID           string `json:"id"`
	Salt         []byte `json:"salt"`
	SecretDigest []byte `json:"secret_digest"`
	// ExternalID 与 Attributes 是管理员绑定期望设备属性：
	// 注册时的外部注册号与属性必须与之完全一致。
	ExternalID string    `json:"external_id"`
	Attributes []byte    `json:"attributes"`
	ExpiresAt  time.Time `json:"expires_at"`
	CreatedAt  time.Time `json:"created_at"`

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

	Status            string             `json:"status"`
	CurrentKeyVersion int                `json:"current_key_version"`
	NextKeyVersion    int                `json:"next_key_version"`
	Keys              map[int]*KeyRecord `json:"keys"`
	CreatedAt         time.Time          `json:"created_at"`
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
