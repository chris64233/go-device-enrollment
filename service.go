package deviceenrollment

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Config 控制挑战与轮换的生命周期参数。
type Config struct {
	// ChallengeTTL 是挑战的有效期；<= 0 时使用默认值。
	ChallengeTTL time.Duration
	// RotationWindow 是轮换的确认窗口；<= 0 时使用默认值。
	RotationWindow time.Duration
}

const (
	defaultChallengeTTL   = 5 * time.Minute
	defaultRotationWindow = 10 * time.Minute
)

func (c Config) withDefaults() Config {
	if c.ChallengeTTL <= 0 {
		c.ChallengeTTL = defaultChallengeTTL
	}
	if c.RotationWindow <= 0 {
		c.RotationWindow = defaultRotationWindow
	}
	return c
}

// Service 提供挑战签发、设备注册、密钥轮换、禁用与认证校验。
// 所有状态变更在单个互斥锁下完成“检查-写入”，保证并发下
// 挑战只被消费一次、轮换只产生一个终态、禁用是原子的。
type Service struct {
	mu    sync.Mutex
	store Store
	clock Clock
	cfg   Config
}

// NewService 创建一个服务实例。clock 是所有过期判断的统一时间来源。
func NewService(store Store, clock Clock, cfg Config) *Service {
	return &Service{store: store, clock: clock, cfg: cfg.withDefaults()}
}

// ---- 待签名消息构造（客户端用对应私钥签名，服务端验签） ----

// EnrollmentMessage 是注册证明的待签名消息。
func EnrollmentMessage(challengeID, externalID string) []byte {
	return []byte("enroll\x00" + challengeID + "\x00" + externalID)
}

// RotationMessage 是轮换确认的待签名消息，旧钥与新钥都需对其签名。
func RotationMessage(rotationID string) []byte {
	return []byte("rotate\x00" + rotationID)
}

// AuthMessage 是认证请求的待签名消息。
func AuthMessage(deviceID, nonce string) []byte {
	return []byte("auth\x00" + deviceID + "\x00" + nonce)
}

// ---- 挑战签发 ----

// IssueChallenge 由管理员调用，为预期设备属性签发一个短期有效的一次性挑战。
// 明文秘密只通过返回值交给调用方，存储层仅保存其 SHA-256 摘要。
func (s *Service) IssueChallenge(attrs DeviceAttributes) (challengeID, secret string, err error) {
	id, err := randomHex(16)
	if err != nil {
		return "", "", err
	}
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return "", "", err
	}
	secret = hex.EncodeToString(secretBytes)

	now := s.clock.Now()
	s.store.PutChallenge(Challenge{
		ID:         id,
		SecretHash: sha256.Sum256([]byte(secret)),
		Attributes: attrs,
		ExpiresAt:  now.Add(s.cfg.ChallengeTTL),
		CreatedAt:  now,
	})
	return id, secret, nil
}

// ---- 设备注册 ----

// EnrollRequest 是设备注册请求。
type EnrollRequest struct {
	ChallengeID string
	Secret      string            // 挑战明文秘密，仅用于与摘要比对
	ExternalID  string            // 外部注册号（幂等键）
	Attributes  DeviceAttributes  // 必须与挑战绑定的预期属性一致
	PublicKey   ed25519.PublicKey // 设备初始公钥，成为密钥版本 1
	Attestation []byte            // 设备私钥对 EnrollmentMessage 的签名
}

// Enroll 完成设备注册并原子消费挑战。
//
// 幂等语义：同一 ExternalID 且注册内容完全相同的重复调用返回原设备身份；
// 同一 ExternalID 携带不同内容返回 ErrEnrollmentConflict；
// 并发使用同一挑战时只有一个注册能成功，其余得到 ErrChallengeAlreadyConsumed。
func (s *Service) Enroll(req EnrollRequest) (*Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock.Now()

	fingerprint := enrollmentFingerprint(req)
	if existing, ok := s.store.GetDeviceByExternalID(req.ExternalID); ok {
		if existing.EnrollmentHash == fingerprint {
			d := existing
			return &d, nil
		}
		return nil, ErrEnrollmentConflict
	}

	ch, ok := s.store.GetChallenge(req.ChallengeID)
	if !ok {
		return nil, ErrChallengeNotFound
	}
	if ch.Consumed {
		return nil, ErrChallengeAlreadyConsumed
	}
	if !now.Before(ch.ExpiresAt) {
		return nil, ErrChallengeExpired
	}
	if sha256.Sum256([]byte(req.Secret)) != ch.SecretHash {
		return nil, ErrChallengeSecretMismatch
	}
	if ch.Attributes != req.Attributes {
		return nil, ErrChallengeAttributeMismatch
	}
	if !ed25519.Verify(req.PublicKey, EnrollmentMessage(req.ChallengeID, req.ExternalID), req.Attestation) {
		return nil, ErrAttestationInvalid
	}

	deviceID, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	device := Device{
		ID:                deviceID,
		ExternalID:        req.ExternalID,
		Attributes:        req.Attributes,
		Status:            DeviceStatusActive,
		CurrentKeyVersion: 1,
		EnrollmentHash:    fingerprint,
		CreatedAt:         now,
	}
	// 原子提交：消费挑战 + 写入设备 + 写入初始密钥版本。
	ch.Consumed = true
	ch.ConsumedAt = now
	s.store.PutChallenge(ch)
	s.store.PutDevice(device)
	s.store.PutKeyVersion(KeyVersion{
		DeviceID:  deviceID,
		Version:   1,
		PublicKey: req.PublicKey,
		Status:    KeyStatusActive,
		CreatedAt: now,
	})
	return &device, nil
}

// ---- 密钥轮换 ----

// StartRotation 为已注册且未禁用的设备开启一次密钥轮换。
// 同一设备同一时间只允许一个待确认轮换；已超窗口的轮换会先被判定为 expired。
func (s *Service) StartRotation(deviceID string, newPublicKey ed25519.PublicKey) (*Rotation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock.Now()

	dev, ok := s.store.GetDevice(deviceID)
	if !ok {
		return nil, ErrDeviceNotFound
	}
	if dev.Status != DeviceStatusActive {
		return nil, ErrDeviceDisabled
	}
	for _, r := range s.store.ListRotations(deviceID) {
		if r.State != RotationPending {
			continue
		}
		if now.Before(r.ExpiresAt) {
			return nil, ErrRotationPendingExists
		}
		r.State = RotationExpired
		s.store.PutRotation(r)
	}

	id, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	rot := Rotation{
		ID:           id,
		DeviceID:     deviceID,
		OldVersion:   dev.CurrentKeyVersion,
		NewVersion:   dev.CurrentKeyVersion + 1,
		NewPublicKey: append([]byte(nil), newPublicKey...),
		State:        RotationPending,
		ExpiresAt:    now.Add(s.cfg.RotationWindow),
		CreatedAt:    now,
	}
	s.store.PutRotation(rot)
	return &rot, nil
}

// ConfirmRotation 在确认窗口内用旧钥与新钥的签名共同确认轮换。
// 成功后设备当前密钥版本立即切换，旧钥立即失效。
// 与取消、超时竞争时，只有最先到达的状态迁移生效。
func (s *Service) ConfirmRotation(rotationID string, oldSig, newSig []byte) (*Rotation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock.Now()

	rot, ok := s.store.GetRotation(rotationID)
	if !ok {
		return nil, ErrRotationNotFound
	}
	dev, ok := s.store.GetDevice(rot.DeviceID)
	if !ok {
		return nil, ErrDeviceNotFound
	}
	if dev.Status != DeviceStatusActive {
		return nil, ErrDeviceDisabled
	}
	if rot.State != RotationPending {
		return nil, fmt.Errorf("%w: %s", ErrRotationFinalized, rot.State)
	}
	if !now.Before(rot.ExpiresAt) {
		rot.State = RotationExpired
		s.store.PutRotation(rot)
		return nil, ErrRotationWindowExpired
	}

	oldKey, ok := s.store.GetKeyVersion(dev.ID, rot.OldVersion)
	if !ok {
		return nil, ErrUnknownKeyVersion
	}
	msg := RotationMessage(rot.ID)
	if !ed25519.Verify(oldKey.PublicKey, msg, oldSig) {
		return nil, ErrAttestationInvalid
	}
	if !ed25519.Verify(rot.NewPublicKey, msg, newSig) {
		return nil, ErrAttestationInvalid
	}

	// 原子提交：旧版本作废、新版本生效、设备指针前移、轮换进入终态。
	oldKey.Status = KeyStatusSuperseded
	s.store.PutKeyVersion(oldKey)
	s.store.PutKeyVersion(KeyVersion{
		DeviceID:  dev.ID,
		Version:   rot.NewVersion,
		PublicKey: rot.NewPublicKey,
		Status:    KeyStatusActive,
		CreatedAt: now,
	})
	dev.CurrentKeyVersion = rot.NewVersion
	s.store.PutDevice(dev)
	rot.State = RotationConfirmed
	s.store.PutRotation(rot)
	return &rot, nil
}

// CancelRotation 取消一个待确认的轮换。已超窗口的轮换转为 expired 而非 cancelled。
func (s *Service) CancelRotation(rotationID string) (*Rotation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock.Now()

	rot, ok := s.store.GetRotation(rotationID)
	if !ok {
		return nil, ErrRotationNotFound
	}
	if rot.State != RotationPending {
		return nil, fmt.Errorf("%w: %s", ErrRotationFinalized, rot.State)
	}
	if !now.Before(rot.ExpiresAt) {
		rot.State = RotationExpired
		s.store.PutRotation(rot)
		return nil, ErrRotationWindowExpired
	}
	rot.State = RotationCancelled
	s.store.PutRotation(rot)
	return &rot, nil
}

// ---- 禁用 ----

// DisableDevice 原子地终止设备的注册有效性及其全部待处理轮换：
// 设备置为 disabled、所有密钥版本吊销、所有 pending 轮换进入 cancelled 终态。
// 对已禁用的设备重复调用是幂等的。
func (s *Service) DisableDevice(deviceID string) (*Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock.Now()

	dev, ok := s.store.GetDevice(deviceID)
	if !ok {
		return nil, ErrDeviceNotFound
	}
	if dev.Status == DeviceStatusDisabled {
		return &dev, nil
	}
	dev.Status = DeviceStatusDisabled
	dev.DisabledAt = now
	s.store.PutDevice(dev)

	for _, kv := range s.store.ListKeyVersions(deviceID) {
		if kv.Status != KeyStatusRevoked {
			kv.Status = KeyStatusRevoked
			s.store.PutKeyVersion(kv)
		}
	}
	for _, r := range s.store.ListRotations(deviceID) {
		if r.State == RotationPending {
			r.State = RotationCancelled
			s.store.PutRotation(r)
		}
	}
	return &dev, nil
}

// ---- 认证校验 ----

// Authenticate 校验一次绑定密钥版本的认证请求。
// 请求必须携带设备当前有效的密钥版本；携带旧版本的迟到请求
// 返回 ErrStaleKeyVersion，不会覆盖或回滚任何新状态。
func (s *Service) Authenticate(deviceID string, keyVersion int, nonce string, sig []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	dev, ok := s.store.GetDevice(deviceID)
	if !ok {
		return ErrDeviceNotFound
	}
	if dev.Status != DeviceStatusActive {
		return ErrDeviceDisabled
	}
	if keyVersion != dev.CurrentKeyVersion {
		return ErrStaleKeyVersion
	}
	kv, ok := s.store.GetKeyVersion(deviceID, keyVersion)
	if !ok {
		return ErrUnknownKeyVersion
	}
	if kv.Status != KeyStatusActive {
		return ErrAuthenticationFailed
	}
	if !ed25519.Verify(kv.PublicKey, AuthMessage(deviceID, nonce), sig) {
		return ErrAuthenticationFailed
	}
	return nil
}

// GetDevice 返回设备的当前快照，供查询与测试断言使用。
func (s *Service) GetDevice(deviceID string) (Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dev, ok := s.store.GetDevice(deviceID)
	if !ok {
		return Device{}, ErrDeviceNotFound
	}
	return dev, nil
}

// GetRotation 返回轮换的当前快照。
func (s *Service) GetRotation(rotationID string) (Rotation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rot, ok := s.store.GetRotation(rotationID)
	if !ok {
		return Rotation{}, ErrRotationNotFound
	}
	return rot, nil
}

// ---- 内部工具 ----

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// enrollmentFingerprint 计算注册内容指纹：同一外部注册号重放时，
// 指纹一致视为幂等重放，不一致视为冲突。
func enrollmentFingerprint(req EnrollRequest) string {
	h := sha256.New()
	h.Write([]byte(req.ExternalID))
	h.Write([]byte{0})
	h.Write([]byte(req.ChallengeID))
	h.Write([]byte{0})
	h.Write([]byte(req.Attributes.Model))
	h.Write([]byte{0})
	h.Write([]byte(req.Attributes.Serial))
	h.Write([]byte{0})
	h.Write(req.PublicKey)
	return hex.EncodeToString(h.Sum(nil))
}
