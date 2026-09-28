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
// 与轮换一致，pending 只允许迁出一次，接收、源租户取消、凭据过期、设备禁用竞争时
// 只产生一个终态。
const (
	TransferPending   = "pending"
	TransferAccepted  = "accepted"
	TransferCancelled = "cancelled"
	TransferExpired   = "expired"
	TransferAborted   = "aborted"
)

// ChallengeRecord 是挑战的持久化记录。
// 明文秘密绝不落盘，只保存盐值与加盐摘要。
type ChallengeRecord struct {
	ID           string `json:"id"`
	Salt         []byte `json:"salt"`
	SecretDigest []byte `json:"secret_digest"`
	// TenantID 是签发挑战的租户；设备注册成功后即其初始归属租户。
	TenantID string `json:"tenant_id"`
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

	// TenantID 是设备当前归属租户。设备转移成功时在同一原子变更内切换。
	TenantID string `json:"tenant_id"`
	// Ownership 记录完整归属链，按时间顺序：注册时建立首个链接，每次成功转移追加新链接。
	// 只记录租户、转移单号与密钥版本，绝不包含凭据或证明原文。
	Ownership []OwnershipLink `json:"ownership"`

	Status            string             `json:"status"`
	CurrentKeyVersion int                `json:"current_key_version"`
	NextKeyVersion    int                `json:"next_key_version"`
	Keys              map[int]*KeyRecord `json:"keys"`
	CreatedAt         time.Time          `json:"created_at"`
}

// OwnershipLink 是归属链上的一环：设备在某段时间归属某租户，以某密钥版本为生效版本。
type OwnershipLink struct {
	TenantID   string     `json:"tenant_id"`
	TransferID string     `json:"transfer_id,omitempty"` // 注册首环为空；转移环记录对应转移单号
	KeyVersion int        `json:"key_version"`
	StartedAt  time.Time  `json:"started_at"`
	EndedAt    *time.Time `json:"ended_at,omitempty"`
}

// TransferRecord 是一次跨租户设备转移的持久化记录。
// 明文接收凭据绝不落盘，只保存盐值与加盐摘要；新公钥与其证明只在接收请求期间存在，
// 成功后公钥进入设备密钥集，证明本身不持久化。
type TransferRecord struct {
	ID       string `json:"id"`
	DeviceID string `json:"device_id"`

	// 发起时冻结的身份三要素。
	SourceTenant string `json:"source_tenant"`
	TargetTenant string `json:"target_tenant"`
	// FrozenVersion 冻结设备当前密钥版本；接收时设备当前版本必须仍等于它。
	FrozenVersion int `json:"frozen_version"`

	// 一次性接收凭据的盐值与加盐摘要，明文不落盘。
	CredentialSalt   []byte `json:"credential_salt"`
	CredentialDigest []byte `json:"credential_digest"`

	Status      string     `json:"status"`
	Deadline    time.Time  `json:"deadline"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`

	// 幂等：源租户发起转移的请求号。同号同内容重放返回首次创建的转移单；同号异内容冲突。
	RequestID string `json:"request_id,omitempty"`
	// ContentHash 覆盖发起内容（设备 + 源/目标租户 + 冻结版本），用于同号异内容冲突判定。
	ContentHash string `json:"content_hash,omitempty"`
	// AcceptHash 覆盖接收内容（目标租户 + 冻结版本 + 新公钥），接收成功后保存，
	// 供同号同内容重放返回首次结果、同号异内容冲突判定。不含证明签名原文。
	AcceptHash string `json:"accept_hash,omitempty"`
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
	TenantID          string    `json:"tenant_id"`
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
		TenantID:          d.TenantID,
		Status:            d.Status,
		CurrentKeyVersion: d.CurrentKeyVersion,
		CreatedAt:         d.CreatedAt,
	}
	if k := d.Keys[d.CurrentKeyVersion]; k != nil {
		v.PublicKey = append([]byte(nil), k.PublicKey...)
	}
	return v
}

// TransferView 是转移单的只读视图：不含凭据摘要/盐值，也不含新公钥与证明原文。
type TransferView struct {
	ID       string `json:"id"`
	DeviceID string `json:"device_id"`

	SourceTenant  string `json:"source_tenant"`
	TargetTenant  string `json:"target_tenant"`
	FrozenVersion int    `json:"frozen_version"`
	Status        string `json:"status"`

	Deadline    time.Time  `json:"deadline"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// OwnershipLinkView 是归属链单环的只读视图。
type OwnershipLinkView struct {
	TenantID   string     `json:"tenant_id"`
	TransferID string     `json:"transfer_id,omitempty"`
	KeyVersion int        `json:"key_version"`
	StartedAt  time.Time  `json:"started_at"`
	EndedAt    *time.Time `json:"ended_at,omitempty"`
}

// TransferHistoryEntry 记录一次转移的两端决定与密钥版本变化（不含凭据与证明敏感内容）。
type TransferHistoryEntry struct {
	TransferID string `json:"transfer_id"`
	// FromTenant/ToTenant 是这次转移的两端。
	FromTenant string `json:"from_tenant"`
	ToTenant   string `json:"to_tenant"`
	// FrozenVersion 是发起时冻结的旧版本；NewVersion 是接收成功后生效的新版本。
	// 非 accepted 终态时 NewVersion 为 0。
	FrozenVersion int        `json:"frozen_version"`
	NewVersion    int        `json:"new_version,omitempty"`
	Status        string     `json:"status"`
	CreatedAt     time.Time  `json:"created_at"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
}

// OwnershipHistory 是设备归属查询结果：当前归属、完整归属链与每次转移的决定/版本变化。
type OwnershipHistory struct {
	DeviceID  string                 `json:"device_id"`
	TenantID  string                 `json:"tenant_id"`
	Chain     []OwnershipLinkView    `json:"chain"`
	Transfers []TransferHistoryEntry `json:"transfers,omitempty"`
}

func transferView(t *TransferRecord) *TransferView {
	return &TransferView{
		ID:            t.ID,
		DeviceID:      t.DeviceID,
		SourceTenant:  t.SourceTenant,
		TargetTenant:  t.TargetTenant,
		FrozenVersion: t.FrozenVersion,
		Status:        t.Status,
		Deadline:      t.Deadline,
		CreatedAt:     t.CreatedAt,
		CompletedAt:   t.CompletedAt,
	}
}

func ownershipHistory(d *DeviceRecord, transfers []*TransferRecord) *OwnershipHistory {
	h := &OwnershipHistory{
		DeviceID:  d.ID,
		TenantID:  d.TenantID,
		Chain:     make([]OwnershipLinkView, 0, len(d.Ownership)),
		Transfers: make([]TransferHistoryEntry, 0, len(transfers)),
	}
	for _, l := range d.Ownership {
		h.Chain = append(h.Chain, OwnershipLinkView{
			TenantID:   l.TenantID,
			TransferID: l.TransferID,
			KeyVersion: l.KeyVersion,
			StartedAt:  l.StartedAt,
			EndedAt:    l.EndedAt,
		})
	}
	for _, t := range transfers {
		e := TransferHistoryEntry{
			TransferID:    t.ID,
			FromTenant:    t.SourceTenant,
			ToTenant:      t.TargetTenant,
			FrozenVersion: t.FrozenVersion,
			Status:        t.Status,
			CreatedAt:     t.CreatedAt,
			CompletedAt:   t.CompletedAt,
		}
		if t.Status == TransferAccepted {
			// 接收成功时新版本即归属链最新一环的版本。
			if link := lastLinkForTransfer(d, t.ID); link != nil {
				e.NewVersion = link.KeyVersion
			}
		}
		h.Transfers = append(h.Transfers, e)
	}
	return h
}

// lastLinkForTransfer 返回归属链上由指定转移单建立的链接（accepted 转移对应唯一新环）。
func lastLinkForTransfer(d *DeviceRecord, transferID string) *OwnershipLink {
	for i := range d.Ownership {
		if d.Ownership[i].TransferID == transferID {
			return &d.Ownership[i]
		}
	}
	return nil
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
