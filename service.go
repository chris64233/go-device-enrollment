package deviceenrollment

import (
	"bytes"
	"crypto/ed25519"
	"strconv"
	"sync"
	"time"
)

// 默认时效参数。
const (
	DefaultChallengeTTL   = 15 * time.Minute
	DefaultRotationWindow = 10 * time.Minute
	// DefaultTransferTTL 是跨租户转移一次性接收凭据的默认有效期。
	DefaultTransferTTL = 15 * time.Minute
)

// Config 构造服务所需的配置。
type Config struct {
	// Store 持久化目标；为 nil 时使用纯内存存储。
	Store *Store
	// Clock 统一当前时间来源；为 nil 时使用系统 UTC 时钟。
	Clock Clock
	// ChallengeTTL 管理员签发挑战的默认有效期；<=0 时使用默认值。
	ChallengeTTL time.Duration
	// RotationWindow 密钥轮换的确认窗口；<=0 时使用默认值。
	RotationWindow time.Duration
	// TransferTTL 跨租户转移接收凭据的默认有效期；<=0 时使用默认值。
	TransferTTL time.Duration
}

// Service 是设备注册与密钥生命周期管理服务。
// 所有状态变更都在同一把互斥锁内完成并整体落盘：
// 挑战一次性消费、轮换单一终态、禁用级联终止都由这把锁与快照原子写保证。
type Service struct {
	mu    sync.Mutex
	store *Store
	snap  *snapshot
	clock Clock

	challengeTTL   time.Duration
	rotationWindow time.Duration
	transferTTL    time.Duration
}

// New 加载持久化状态并返回服务实例。
func New(cfg Config) (*Service, error) {
	store := cfg.Store
	if store == nil {
		store = NewMemoryStore()
	}
	clock := cfg.Clock
	if clock == nil {
		clock = SystemClock()
	}
	snap, err := store.Load()
	if err != nil {
		return nil, err
	}
	ttl := cfg.ChallengeTTL
	if ttl <= 0 {
		ttl = DefaultChallengeTTL
	}
	window := cfg.RotationWindow
	if window <= 0 {
		window = DefaultRotationWindow
	}
	ttlTransfer := cfg.TransferTTL
	if ttlTransfer <= 0 {
		ttlTransfer = DefaultTransferTTL
	}
	return &Service{
		store:          store,
		snap:           snap,
		clock:          clock,
		challengeTTL:   ttl,
		rotationWindow: window,
		transferTTL:    ttlTransfer,
	}, nil
}

// saveLocked 必须在持有 mu 时调用。
func (s *Service) saveLocked() error {
	return s.store.Save(s.snap)
}

// IssueChallenge 由管理员调用，为指定租户签发一次性注册挑战。
// externalID 与 attributes 绑定预期设备：注册时必须原样带回。
// ttl <=0 时使用配置的默认有效期。返回值中的明文 Secret 仅此一次出现。
func (s *Service) IssueChallenge(tenantID, externalID string, attributes []byte, ttl time.Duration) (*Challenge, error) {
	if tenantID == "" {
		return nil, newError(ErrCodeInvalidArgument, "tenant id is required")
	}
	if externalID == "" {
		return nil, newError(ErrCodeInvalidArgument, "external id is required")
	}
	if ttl <= 0 {
		ttl = s.challengeTTL
	}
	now := s.clock.Now()

	secret := randomSecret()
	salt := randomBytes(16)
	rec := &ChallengeRecord{
		ID:           randomID(),
		Salt:         salt,
		SecretDigest: digestSecret(salt, secret),
		TenantID:     tenantID,
		ExternalID:   externalID,
		Attributes:   append([]byte(nil), attributes...),
		ExpiresAt:    now.Add(ttl),
		CreatedAt:    now,
	}

	s.mu.Lock()
	s.snap.Challenges[rec.ID] = rec
	err := s.saveLocked()
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return &Challenge{ID: rec.ID, Secret: secret}, nil
}

// RegisterRequest 是设备注册请求。
type RegisterRequest struct {
	// ChallengeID 与 Secret 标识并解锁管理员签发的挑战。
	ChallengeID string
	Secret      string
	// ExternalID 与 Attributes 必须与挑战绑定的预期设备属性一致。
	ExternalID string
	Attributes []byte
	// PublicKey 是设备初始公钥（ed25519）。
	PublicKey []byte
	// Attestation 是设备用对应私钥对注册报文的签名，见 EnrollAttestationMessage。
	Attestation []byte
}

// Register 完成设备注册。
//
// 语义：
//   - 外部注册号与注册内容均与既有设备相同：幂等返回原设备身份；
//   - 外部注册号相同但内容不同：返回 ErrCodeConflict；
//   - 同一挑战并发注册：只有一个能创建设备，其余按上述两条处理。
func (s *Service) Register(req RegisterRequest) (*DeviceView, error) {
	if req.ChallengeID == "" || req.Secret == "" || req.ExternalID == "" {
		return nil, newError(ErrCodeInvalidArgument, "challenge id, secret and external id are required")
	}
	if len(req.PublicKey) != ed25519.PublicKeySize {
		return nil, newError(ErrCodeInvalidArgument, "public key must be ed25519 (%d bytes)", ed25519.PublicKeySize)
	}
	now := s.clock.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	ch, ok := s.snap.Challenges[req.ChallengeID]
	if !ok {
		return nil, newError(ErrCodeChallengeNotFound, "challenge %q", req.ChallengeID)
	}
	if !secretMatches(ch, req.Secret) {
		return nil, newError(ErrCodeChallengeSecretMismatch, "challenge secret does not match")
	}

	if ch.Consumed {
		// 挑战只能成功消费一次；之后的请求只允许幂等重放原身份。
		return s.replayLocked(ch, req)
	}

	if !now.Before(ch.ExpiresAt) {
		return nil, newError(ErrCodeChallengeExpired, "challenge expired at %s", ch.ExpiresAt.Format(time.RFC3339Nano))
	}
	if req.ExternalID != ch.ExternalID || !bytes.Equal(req.Attributes, ch.Attributes) {
		return nil, newError(ErrCodeChallengeAttributeMismatch,
			"registration payload does not match challenge-bound device attributes")
	}

	if devID, ok := s.snap.ByExternal[req.ExternalID]; ok {
		existing := s.snap.Devices[devID]
		if existing.ContentHash == contentHash(req.Attributes, req.PublicKey) {
			// 另一把挑战带来了同号同内容的注册：直接返回既有身份，本挑战不被消费。
			return deviceView(existing), nil
		}
		return nil, newError(ErrCodeConflict,
			"external id %q already enrolled with different content", req.ExternalID)
	}

	if !verifyAttestation(ch.ID, req.ExternalID, req.Attributes, req.PublicKey, req.Attestation) {
		return nil, newError(ErrCodeAttestationFailed, "attestation signature is invalid")
	}

	device := &DeviceRecord{
		ID:                randomID(),
		ExternalID:        req.ExternalID,
		Attributes:        append([]byte(nil), req.Attributes...),
		ContentHash:       contentHash(req.Attributes, req.PublicKey),
		TenantID:          ch.TenantID,
		Status:            DeviceStatusActive,
		CurrentKeyVersion: 1,
		NextKeyVersion:    1,
		Keys: map[int]*KeyRecord{
			1: {
				Version:   1,
				PublicKey: append([]byte(nil), req.PublicKey...),
				State:     KeyStateActive,
				CreatedAt: now,
			},
		},
		// 归属链首环：注册租户，密钥版本 1。
		Ownership: []OwnershipLink{{
			TenantID:   ch.TenantID,
			KeyVersion: 1,
			StartedAt:  now,
		}},
		CreatedAt: now,
	}

	ch.Consumed = true
	ch.ConsumedAt = &now
	ch.ConsumedByDevice = device.ID
	s.snap.Devices[device.ID] = device
	s.snap.ByExternal[device.ExternalID] = device.ID
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	return deviceView(device), nil
}

// replayLocked 处理已消费挑战的幂等重放与冲突。调用方已校验秘密。
func (s *Service) replayLocked(ch *ChallengeRecord, req RegisterRequest) (*DeviceView, error) {
	if req.ExternalID != ch.ExternalID || !bytes.Equal(req.Attributes, ch.Attributes) {
		return nil, newError(ErrCodeChallengeAttributeMismatch,
			"registration payload does not match challenge-bound device attributes")
	}
	device := s.snap.Devices[ch.ConsumedByDevice]
	if device == nil {
		// 理论上不可达：消费记录与设备在同一快照内创建。
		return nil, newError(ErrCodeChallengeConsumed, "challenge has already been consumed")
	}
	if device.ContentHash != contentHash(req.Attributes, req.PublicKey) {
		return nil, newError(ErrCodeConflict,
			"external id %q already enrolled with different content", req.ExternalID)
	}
	if !verifyAttestation(ch.ID, req.ExternalID, req.Attributes, req.PublicKey, req.Attestation) {
		return nil, newError(ErrCodeAttestationFailed, "attestation signature is invalid")
	}
	return deviceView(device), nil
}

// BeginRotation 由当前密钥持有者发起轮换：登记一把 pending 新钥并打开确认窗口。
// initiatorSignature 必须是当前私钥对 RotationBeginMessage 的签名。
func (s *Service) BeginRotation(deviceID string, newPublicKey, initiatorSignature []byte) (*RotationView, error) {
	if deviceID == "" {
		return nil, newError(ErrCodeInvalidArgument, "device id is required")
	}
	if len(newPublicKey) != ed25519.PublicKeySize {
		return nil, newError(ErrCodeInvalidArgument, "public key must be ed25519 (%d bytes)", ed25519.PublicKeySize)
	}
	now := s.clock.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	device, err := s.activeDeviceLocked(deviceID)
	if err != nil {
		return nil, err
	}
	if rid, ok := s.snap.OpenRotation[deviceID]; ok {
		// 既有轮换可能已超时：惰性结算后才允许重新发起。
		s.sweepRotationLocked(s.snap.Rotations[rid], now)
		if _, stillOpen := s.snap.OpenRotation[deviceID]; stillOpen {
			return nil, newError(ErrCodeRotationInProgress, "device %q has an open rotation %q", deviceID, rid)
		}
	}
	// 设备已有活动转移时不得发起轮换：转移已冻结当前密钥版本，直到接收/取消/过期。
	if tid, ok := s.snap.OpenTransfer[deviceID]; ok {
		s.sweepTransferLocked(s.snap.Transfers[tid], now)
		if _, stillOpen := s.snap.OpenTransfer[deviceID]; stillOpen {
			return nil, newError(ErrCodeTransferInProgress,
				"device %q has an active transfer %q; rotation is forbidden until it closes", deviceID, tid)
		}
	}

	current := device.Keys[device.CurrentKeyVersion]
	if !verifyMessage(current.PublicKey, RotationBeginMessage(deviceID, newPublicKey), initiatorSignature) {
		return nil, newError(ErrCodeSignatureInvalid, "rotation must be initiated by the current key")
	}
	if bytes.Equal(current.PublicKey, newPublicKey) {
		return nil, newError(ErrCodeInvalidArgument, "new public key must differ from the current key")
	}

	newVersion := device.NextKeyVersion + 1
	device.NextKeyVersion = newVersion
	device.Keys[newVersion] = &KeyRecord{
		Version:   newVersion,
		PublicKey: append([]byte(nil), newPublicKey...),
		State:     KeyStatePending,
		CreatedAt: now,
	}
	rotation := &RotationRecord{
		ID:         randomID(),
		DeviceID:   deviceID,
		OldVersion: device.CurrentKeyVersion,
		NewVersion: newVersion,
		Status:     RotationPending,
		Deadline:   now.Add(s.rotationWindow),
		CreatedAt:  now,
	}
	s.snap.Rotations[rotation.ID] = rotation
	s.snap.OpenRotation[deviceID] = rotation.ID
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	return rotationView(rotation), nil
}

// KeyConfirmation 是一侧密钥对轮换的确认。
type KeyConfirmation struct {
	// KeyVersion 必须与轮换单中的旧版本或新版本一致。
	KeyVersion int
	// Signature 是该版本私钥对 RotationConfirmMessage 的签名。
	Signature []byte
}

// ConfirmRotation 提交旧钥/新钥确认。两侧可以在同一请求中一次给齐，也可以分别提交；
// 两侧齐备的瞬间轮换在同一事务内完成：新钥生效、旧钥立即失效。
// 任一侧签名非法时整个请求失败且不产生部分确认。
func (s *Service) ConfirmRotation(rotationID string, confirmations ...KeyConfirmation) (*RotationView, error) {
	if rotationID == "" {
		return nil, newError(ErrCodeInvalidArgument, "rotation id is required")
	}
	if len(confirmations) == 0 {
		return nil, newError(ErrCodeInvalidArgument, "at least one confirmation is required")
	}
	now := s.clock.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	rotation, err := s.openRotationLocked(rotationID, now)
	if err != nil {
		return nil, err
	}
	device := s.snap.Devices[rotation.DeviceID]

	// 先校验全部输入，再落状态，避免部分确认。
	oldSeen, newSeen := rotation.OldKeyConfirmed, rotation.NewKeyConfirmed
	for _, c := range confirmations {
		var key *KeyRecord
		switch c.KeyVersion {
		case rotation.OldVersion:
			key = device.Keys[rotation.OldVersion]
			if !verifyMessage(key.PublicKey,
				RotationConfirmMessage(rotation.DeviceID, rotation.ID, rotation.OldVersion, rotation.NewVersion),
				c.Signature) {
				return nil, newError(ErrCodeSignatureInvalid, "old-key confirmation signature is invalid")
			}
			oldSeen = true
		case rotation.NewVersion:
			key = device.Keys[rotation.NewVersion]
			if key.State != KeyStatePending {
				return nil, newError(ErrCodeKeyVersionInvalid, "new key %d is not pending", c.KeyVersion)
			}
			if !verifyMessage(key.PublicKey,
				RotationConfirmMessage(rotation.DeviceID, rotation.ID, rotation.OldVersion, rotation.NewVersion),
				c.Signature) {
				return nil, newError(ErrCodeSignatureInvalid, "new-key confirmation signature is invalid")
			}
			newSeen = true
		default:
			return nil, newError(ErrCodeKeyVersionInvalid,
				"key version %d is not part of rotation %q", c.KeyVersion, rotationID)
		}
	}

	rotation.OldKeyConfirmed = oldSeen
	rotation.NewKeyConfirmed = newSeen
	if oldSeen && newSeen {
		// 轮换完成：与清理解除挂单、旧钥失效在同一临界区/同一次落盘中发生。
		device.Keys[rotation.OldVersion].State = KeyStateInvalidated
		newKey := device.Keys[rotation.NewVersion]
		newKey.State = KeyStateActive
		device.CurrentKeyVersion = rotation.NewVersion
		rotation.Status = RotationConfirmed
		rotation.CompletedAt = &now
		delete(s.snap.OpenRotation, device.ID)
	}
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	return rotationView(rotation), nil
}

// CancelRotation 由当前（旧）密钥持有者取消轮换。pending 新钥随即失效。
// cancelSignature 必须是旧版本私钥对 RotationCancelMessage 的签名。
func (s *Service) CancelRotation(rotationID string, cancelSignature []byte) (*RotationView, error) {
	if rotationID == "" {
		return nil, newError(ErrCodeInvalidArgument, "rotation id is required")
	}
	now := s.clock.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	rotation, err := s.openRotationLocked(rotationID, now)
	if err != nil {
		return nil, err
	}
	device := s.snap.Devices[rotation.DeviceID]
	oldKey := device.Keys[rotation.OldVersion]
	if !verifyMessage(oldKey.PublicKey,
		RotationCancelMessage(rotation.DeviceID, rotation.ID, rotation.OldVersion, rotation.NewVersion),
		cancelSignature) {
		return nil, newError(ErrCodeSignatureInvalid, "rotation must be cancelled by the current (old) key")
	}

	device.Keys[rotation.NewVersion].State = KeyStateInvalidated
	rotation.Status = RotationCancelled
	rotation.CompletedAt = &now
	delete(s.snap.OpenRotation, device.ID)
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	return rotationView(rotation), nil
}

// SweepExpiredRotations 显式结算所有已超出确认窗口的 pending 轮换。
// 超时同样采用惰性结算：访问轮换单时也会自动触发。
func (s *Service) SweepExpiredRotations() (int, error) {
	now := s.clock.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	n := 0
	for _, rid := range s.snap.OpenRotation {
		if s.sweepRotationLocked(s.snap.Rotations[rid], now) {
			n++
		}
	}
	if n > 0 {
		if err := s.saveLocked(); err != nil {
			return 0, err
		}
	}
	return n, nil
}

// sweepRotationLocked 在超时发生时把轮换推进到 timed_out 终态并失效 pending 新钥。
// 返回是否发生了状态迁移。pending -> 终态只可能发生一次。
func (s *Service) sweepRotationLocked(r *RotationRecord, now time.Time) bool {
	if r == nil || r.Status != RotationPending {
		return false
	}
	if now.Before(r.Deadline) || now.Equal(r.Deadline) {
		return false
	}
	device := s.snap.Devices[r.DeviceID]
	if device != nil {
		if k := device.Keys[r.NewVersion]; k != nil && k.State == KeyStatePending {
			k.State = KeyStateInvalidated
		}
	}
	completed := now
	r.Status = RotationTimedOut
	r.CompletedAt = &completed
	delete(s.snap.OpenRotation, r.DeviceID)
	return true
}

// AuthRequest 是一次设备认证请求。KeyVersion 绑定设备当前有效的密钥版本。
type AuthRequest struct {
	DeviceID string
	// TenantID 是发起认证的租户，必须与设备当前归属一致。
	// 设备转移后源租户不再匹配，其全部认证资格立即失效。
	TenantID   string
	KeyVersion int
	Message    []byte
	Signature  []byte
}

// Authenticate 校验认证请求。
// 使用已失效的旧密钥版本（例如轮换完成或设备转移后迟到的请求）会得到
// ErrCodeKeyVersionInvalid；设备已转移到新租户后，源租户的迟到认证得到
// ErrCodeTransferTenantMismatch，旧状态绝不可能借迟到请求覆盖新状态。
func (s *Service) Authenticate(req AuthRequest) error {
	if req.DeviceID == "" || req.TenantID == "" || req.KeyVersion <= 0 {
		return newError(ErrCodeInvalidArgument, "device id, tenant id and positive key version are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	device, ok := s.snap.Devices[req.DeviceID]
	if !ok {
		return newError(ErrCodeDeviceNotFound, "device %q", req.DeviceID)
	}
	if device.Status != DeviceStatusActive {
		return newError(ErrCodeDeviceDisabled, "device %q is disabled", req.DeviceID)
	}
	if device.TenantID != req.TenantID {
		return newError(ErrCodeTransferTenantMismatch,
			"device %q is no longer owned by tenant %q", req.DeviceID, req.TenantID)
	}
	key, ok := device.Keys[req.KeyVersion]
	if !ok {
		return newError(ErrCodeKeyVersionNotFound, "key version %d", req.KeyVersion)
	}
	if req.KeyVersion != device.CurrentKeyVersion || key.State != KeyStateActive {
		return newError(ErrCodeKeyVersionInvalid,
			"key version %d is not the current active version (%d)", req.KeyVersion, device.CurrentKeyVersion)
	}
	if !verifyMessage(key.PublicKey, req.Message, req.Signature) {
		return newError(ErrCodeSignatureInvalid, "authentication signature is invalid")
	}
	return nil
}

// DisableDevice 由管理员禁用设备：在同一快照变更中终止注册有效性、
// 失效全部密钥，并把待处理轮换中止（aborted）。重复禁用幂等成功。
func (s *Service) DisableDevice(deviceID string) (*DeviceView, error) {
	if deviceID == "" {
		return nil, newError(ErrCodeInvalidArgument, "device id is required")
	}
	now := s.clock.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	device, ok := s.snap.Devices[deviceID]
	if !ok {
		return nil, newError(ErrCodeDeviceNotFound, "device %q", deviceID)
	}
	if device.Status == DeviceStatusDisabled {
		return deviceView(device), nil
	}

	device.Status = DeviceStatusDisabled
	for _, k := range device.Keys {
		k.State = KeyStateInvalidated
	}
	if rid, ok := s.snap.OpenRotation[deviceID]; ok {
		if r := s.snap.Rotations[rid]; r != nil && r.Status == RotationPending {
			r.Status = RotationAborted
			r.CompletedAt = &now
		}
		delete(s.snap.OpenRotation, deviceID)
	}
	// 活动转移一并原子中止：禁用的设备不能再被接收。
	s.abortTransferForDeviceLocked(deviceID, now)
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	return deviceView(device), nil
}

// GetDevice 返回设备只读视图。
func (s *Service) GetDevice(deviceID string) (*DeviceView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	device, ok := s.snap.Devices[deviceID]
	if !ok {
		return nil, newError(ErrCodeDeviceNotFound, "device %q", deviceID)
	}
	return deviceView(device), nil
}

// GetRotation 返回轮换单只读视图；若其确认窗口已过，会先惰性结算超时。
func (s *Service) GetRotation(rotationID string) (*RotationView, error) {
	now := s.clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	rotation, ok := s.snap.Rotations[rotationID]
	if !ok {
		return nil, newError(ErrCodeRotationNotFound, "rotation %q", rotationID)
	}
	if s.sweepRotationLocked(rotation, now) {
		if err := s.saveLocked(); err != nil {
			return nil, err
		}
	}
	return rotationView(rotation), nil
}

func (s *Service) activeDeviceLocked(deviceID string) (*DeviceRecord, error) {
	device, ok := s.snap.Devices[deviceID]
	if !ok {
		return nil, newError(ErrCodeDeviceNotFound, "device %q", deviceID)
	}
	if device.Status != DeviceStatusActive {
		return nil, newError(ErrCodeDeviceDisabled, "device %q is disabled", deviceID)
	}
	return device, nil
}

// openRotationLocked 定位仍处于 pending 的轮换单，并先与超时/并发终态竞争结算。
func (s *Service) openRotationLocked(rotationID string, now time.Time) (*RotationRecord, error) {
	rotation, ok := s.snap.Rotations[rotationID]
	if !ok {
		return nil, newError(ErrCodeRotationNotFound, "rotation %q", rotationID)
	}
	s.sweepRotationLocked(rotation, now)
	if rotation.Status != RotationPending {
		return nil, newError(ErrCodeRotationClosed, "rotation %q is already %s", rotationID, rotation.Status)
	}
	return rotation, nil
}

// ---- 客户端侧规范报文 ----

func joinFields(fields ...[]byte) []byte {
	msg := make([]byte, 0)
	for i, f := range fields {
		if i > 0 {
			msg = append(msg, '|')
		}
		msg = append(msg, f...)
	}
	return msg
}

// EnrollAttestationMessage 返回注册证明的规范待签名报文：
// "ENROLL|<challengeID>|<externalID>|<attributes>|<publicKey>"。
func EnrollAttestationMessage(challengeID, externalID string, attributes, publicKey []byte) []byte {
	return attestationMessage(challengeID, externalID, attributes, publicKey)
}

// RotationBeginMessage 返回发起轮换的规范待签名报文。
func RotationBeginMessage(deviceID string, newPublicKey []byte) []byte {
	return joinFields([]byte("ROTATION_BEGIN"), []byte(deviceID), newPublicKey)
}

// RotationConfirmMessage 返回轮换确认的规范待签名报文，新旧钥都对同一报文签名。
func RotationConfirmMessage(deviceID, rotationID string, oldVersion, newVersion int) []byte {
	return joinFields(
		[]byte("ROTATION_CONFIRM"),
		[]byte(deviceID),
		[]byte(rotationID),
		[]byte(strconv.Itoa(oldVersion)),
		[]byte(strconv.Itoa(newVersion)),
	)
}

// RotationCancelMessage 返回取消轮换的规范待签名报文。
func RotationCancelMessage(deviceID, rotationID string, oldVersion, newVersion int) []byte {
	return joinFields(
		[]byte("ROTATION_CANCEL"),
		[]byte(deviceID),
		[]byte(rotationID),
		[]byte(strconv.Itoa(oldVersion)),
		[]byte(strconv.Itoa(newVersion)),
	)
}
