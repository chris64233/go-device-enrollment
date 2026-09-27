package deviceenrollment

import (
	"crypto/ed25519"
	"time"
)

// DeviceAttributes 描述挑战绑定的预期设备属性。
// 注册时设备上报的属性必须与挑战签发时登记的完全一致。
type DeviceAttributes struct {
	Model  string
	Serial string
}

// Challenge 是管理员签发的一次性注册挑战。
// 数据库中只保存挑战秘密的安全摘要（SHA-256），绝不保存明文秘密。
type Challenge struct {
	ID         string
	SecretHash [32]byte
	Attributes DeviceAttributes
	ExpiresAt  time.Time
	Consumed   bool
	ConsumedAt time.Time
	CreatedAt  time.Time
}

// DeviceStatus 表示设备的注册状态。
type DeviceStatus string

const (
	DeviceStatusActive   DeviceStatus = "active"
	DeviceStatusDisabled DeviceStatus = "disabled"
)

// Device 是已注册设备的身份记录。
type Device struct {
	ID                string
	ExternalID        string // 外部注册号，幂等键
	Attributes        DeviceAttributes
	Status            DeviceStatus
	CurrentKeyVersion int
	EnrollmentHash    string // 注册内容指纹，用于幂等重放识别与冲突检测
	CreatedAt         time.Time
	DisabledAt        time.Time
}

// KeyStatus 表示一个密钥版本的生命周期状态。
type KeyStatus string

const (
	KeyStatusActive     KeyStatus = "active"
	KeyStatusSuperseded KeyStatus = "superseded" // 被轮换取代
	KeyStatusRevoked    KeyStatus = "revoked"    // 随设备禁用而吊销
)

// KeyVersion 是设备某一版本的公钥记录。
type KeyVersion struct {
	DeviceID  string
	Version   int
	PublicKey ed25519.PublicKey
	Status    KeyStatus
	CreatedAt time.Time
}

// RotationState 是密钥轮换的状态机取值。
// pending 为唯一非终态；confirmed / cancelled / expired 均为终态，
// 确认、取消与超时竞争时只允许进入其中一个。
type RotationState string

const (
	RotationPending   RotationState = "pending"
	RotationConfirmed RotationState = "confirmed"
	RotationCancelled RotationState = "cancelled"
	RotationExpired   RotationState = "expired"
)

// Rotation 是一次进行中的密钥轮换。
// 旧钥与新钥必须在 ExpiresAt 之前共同完成确认，逾期轮换进入 expired 终态。
type Rotation struct {
	ID           string
	DeviceID     string
	OldVersion   int
	NewVersion   int
	NewPublicKey ed25519.PublicKey
	State        RotationState
	ExpiresAt    time.Time
	CreatedAt    time.Time
}
