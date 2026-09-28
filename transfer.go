package deviceenrollment

import (
	"crypto/ed25519"
	"crypto/subtle"
	"strconv"
	"time"
)

// BeginTransfer 由源租户发起跨租户受控转移。
//
// 发起瞬间冻结设备身份（deviceID）、当前密钥版本与目标租户，并生成短期有效的一次性
// 接收凭据；持久化只保存凭据的加盐摘要，明文仅在本次返回值中出现。
//
// 发起前置条件（任一不满足即拒绝）：
//   - 设备存在且未禁用，且当前归属恰为 sourceTenant；
//   - 设备没有未完成（pending）的密钥轮换；
//   - 设备没有活动（pending）的转移。
//
// requestID 是源租户提供的幂等号：同号且发起内容（设备/源租户/目标租户）一致时
// 返回首次创建的同一张转移单；同号异内容返回 ErrCodeConflict。
// 重放不会再次返回凭据明文（明文在任何情况下都只出现一次）。
//
// 返回值为转移单只读视图与一次性凭据明文（首次创建时非空，重放时为空）。
func (s *Service) BeginTransfer(requestID, deviceID, sourceTenant, targetTenant string, ttl time.Duration) (*TransferView, string, error) {
	if requestID == "" {
		return nil, "", newError(ErrCodeInvalidArgument, "request id is required")
	}
	if deviceID == "" || sourceTenant == "" || targetTenant == "" {
		return nil, "", newError(ErrCodeInvalidArgument, "device id, source tenant and target tenant are required")
	}
	if sourceTenant == targetTenant {
		return nil, "", newError(ErrCodeInvalidArgument, "target tenant must differ from source tenant")
	}
	if ttl <= 0 {
		ttl = s.transferTTL
	}
	now := s.clock.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	// 幂等：同号同内容返回首张单，同号异内容冲突。
	if tid, ok := s.snap.TransferRequests[requestID]; ok {
		existing := s.snap.Transfers[tid]
		s.sweepTransferLocked(existing, now)
		wantHash := beginTransferContentHash(deviceID, sourceTenant, targetTenant)
		if existing.ContentHash != wantHash {
			return nil, "", newError(ErrCodeConflict,
				"transfer request id %q already used with different content", requestID)
		}
		v := transferView(existing)
		if err := s.saveLocked(); err != nil {
			return nil, "", err
		}
		return v, "", nil
	}

	device, err := s.activeDeviceLocked(deviceID)
	if err != nil {
		return nil, "", err
	}
	if device.TenantID != sourceTenant {
		return nil, "", newError(ErrCodeTransferTenantMismatch,
			"device %q is not owned by tenant %q", deviceID, sourceTenant)
	}

	// 未完成轮换不得发起转移；先惰性结算可能已超时的轮换。
	if rid, ok := s.snap.OpenRotation[deviceID]; ok {
		s.sweepRotationLocked(s.snap.Rotations[rid], now)
		if _, stillOpen := s.snap.OpenRotation[deviceID]; stillOpen {
			return nil, "", newError(ErrCodeRotationInProgress,
				"device %q has an open rotation %q; transfer is forbidden until it closes", deviceID, rid)
		}
	}
	// 活动转移不得重复发起；先惰性过期。
	if tid, ok := s.snap.OpenTransfer[deviceID]; ok {
		s.sweepTransferLocked(s.snap.Transfers[tid], now)
		if _, stillOpen := s.snap.OpenTransfer[deviceID]; stillOpen {
			return nil, "", newError(ErrCodeTransferInProgress,
				"device %q already has an active transfer %q", deviceID, tid)
		}
	}

	secret := randomSecret()
	salt := randomBytes(16)
	rec := &TransferRecord{
		ID:               randomID(),
		DeviceID:         deviceID,
		SourceTenant:     sourceTenant,
		TargetTenant:     targetTenant,
		FrozenVersion:    device.CurrentKeyVersion,
		CredentialSalt:   salt,
		CredentialDigest: digestSecret(salt, secret),
		Status:           TransferPending,
		Deadline:         now.Add(ttl),
		CreatedAt:        now,
		RequestID:        requestID,
		ContentHash:      beginTransferContentHash(deviceID, sourceTenant, targetTenant),
	}

	s.snap.Transfers[rec.ID] = rec
	s.snap.OpenTransfer[deviceID] = rec.ID
	s.snap.TransferRequests[requestID] = rec.ID
	s.snap.DeviceTransfers[deviceID] = append(s.snap.DeviceTransfers[deviceID], rec.ID)
	if err := s.saveLocked(); err != nil {
		return nil, "", err
	}
	return transferView(rec), secret, nil
}

// AcceptTransferRequest 是目标租户接收设备的请求。
type AcceptTransferRequest struct {
	// TransferID 是源租户下发的转移单号。
	TransferID string
	// Credential 是一次性接收凭据明文。
	Credential string
	// TargetTenant 必须与发起时冻结的目标租户一致。
	TargetTenant string
	// NewPublicKey 是目标租户为设备设定的新 ed25519 公钥。
	NewPublicKey []byte
	// Attestation 是新私钥对 TransferAcceptMessage 的签名，证明新私钥持有与接收意图。
	Attestation []byte
}

// AcceptTransfer 由目标租户接收设备。
//
// 成功时在同一原子变更内：切换设备归属到目标租户、启用新的密钥版本、失效源租户的
// 全部既有密钥（源租户认证资格立即终止）、追加归属链。
//
// 证明、凭据或冻结的设备版本任一不匹配都会整体失败，绝不留下“归属已变但新密钥未生效”
// 的中间状态。接收、源租户取消与凭据过期可能并发，终态唯一：
//   - 已 accepted 后，同内容重放返回首次结果；异内容重放返回 ErrCodeTransferClosed；
//   - cancelled/aborted 返回 ErrCodeTransferClosed；expired 返回 ErrCodeCredentialExpired。
func (s *Service) AcceptTransfer(req AcceptTransferRequest) (*TransferView, error) {
	if req.TransferID == "" || req.TargetTenant == "" {
		return nil, newError(ErrCodeInvalidArgument, "transfer id and target tenant are required")
	}
	if len(req.NewPublicKey) != ed25519.PublicKeySize {
		return nil, newError(ErrCodeInvalidArgument, "public key must be ed25519 (%d bytes)", ed25519.PublicKeySize)
	}
	now := s.clock.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	transfer, ok := s.snap.Transfers[req.TransferID]
	if !ok {
		return nil, newError(ErrCodeTransferNotFound, "transfer %q", req.TransferID)
	}
	s.sweepTransferLocked(transfer, now)

	if transfer.Status != TransferPending {
		return s.replayAcceptedOrRejectLocked(transfer, req)
	}

	if req.TargetTenant != transfer.TargetTenant {
		return nil, newError(ErrCodeTransferTenantMismatch,
			"transfer %q is not addressed to tenant %q", req.TransferID, req.TargetTenant)
	}
	if !credentialMatches(transfer, req.Credential) {
		return nil, newError(ErrCodeCredentialMismatch, "one-time credential does not match")
	}
	if !now.Before(transfer.Deadline) {
		// 理论上 sweep 已结算；双保险，绝不接受过期凭据。
		s.sweepTransferLocked(transfer, now)
		if transfer.Status == TransferExpired {
			return nil, newError(ErrCodeCredentialExpired, "credential expired at %s", transfer.Deadline.Format(time.RFC3339Nano))
		}
	}

	device := s.snap.Devices[transfer.DeviceID]
	if device == nil {
		// 不可达：设备与转移在同一快照内。
		return nil, newError(ErrCodeDeviceNotFound, "device %q", transfer.DeviceID)
	}
	if device.Status != DeviceStatusActive {
		// 禁用会把转移推进 aborted，此处仅作防御。
		return nil, newError(ErrCodeDeviceDisabled, "device %q is disabled", device.ID)
	}
	if device.CurrentKeyVersion != transfer.FrozenVersion {
		return nil, newError(ErrCodeTransferVersionMismatch,
			"device key version %d no longer matches frozen version %d",
			device.CurrentKeyVersion, transfer.FrozenVersion)
	}

	// 证明把转移单、设备、目标租户、冻结版本与新公钥绑定在同一报文里。
	if !verifyMessage(req.NewPublicKey,
		TransferAcceptMessage(transfer.ID, device.ID, req.TargetTenant, transfer.FrozenVersion, req.NewPublicKey),
		req.Attestation) {
		return nil, newError(ErrCodeAttestationFailed, "transfer attestation signature is invalid")
	}

	// 全部校验通过后才开始落状态，且所有步骤在同一临界区/同一次落盘内完成。
	newVersion := device.NextKeyVersion + 1
	for _, k := range device.Keys {
		// 源租户的全部密钥（含历史失效钥与任何 pending 钥）立即失去认证资格。
		k.State = KeyStateInvalidated
	}
	device.Keys[newVersion] = &KeyRecord{
		Version:   newVersion,
		PublicKey: append([]byte(nil), req.NewPublicKey...),
		State:     KeyStateActive,
		CreatedAt: now,
	}
	device.NextKeyVersion = newVersion
	device.CurrentKeyVersion = newVersion
	device.TenantID = transfer.TargetTenant
	if n := len(device.Ownership); n > 0 {
		ended := now
		device.Ownership[n-1].EndedAt = &ended
	}
	device.Ownership = append(device.Ownership, OwnershipLink{
		TenantID:   transfer.TargetTenant,
		TransferID: transfer.ID,
		KeyVersion: newVersion,
		StartedAt:  now,
	})

	transfer.Status = TransferAccepted
	transfer.CompletedAt = &now
	transfer.AcceptHash = acceptTransferContentHash(req.TargetTenant, req.NewPublicKey)
	delete(s.snap.OpenTransfer, device.ID)
	// 防御性：与转移互斥的轮换本不应存在；若存在则一同原子中止，新钥版本仍然连续。
	if rid, open := s.snap.OpenRotation[device.ID]; open {
		if r := s.snap.Rotations[rid]; r != nil && r.Status == RotationPending {
			r.Status = RotationAborted
			r.CompletedAt = &now
		}
		delete(s.snap.OpenRotation, device.ID)
	}

	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	return transferView(transfer), nil
}

// replayAcceptedOrRejectLocked 处理已到终态的转移：accepted 支持同内容幂等重放，
// 其余终态拒绝迟到接收。重放不再要求一次性凭据（凭据首次交付后即应被丢弃），
// 改由“目标租户 + 新公钥 + 新私钥证明一致”来确认是同一笔接收；内容不同则拒绝，
// 保证设备不会被第二次接收。
func (s *Service) replayAcceptedOrRejectLocked(transfer *TransferRecord, req AcceptTransferRequest) (*TransferView, error) {
	if transfer.Status == TransferAccepted {
		sameContent := req.TargetTenant == transfer.TargetTenant &&
			transfer.AcceptHash == acceptTransferContentHash(req.TargetTenant, req.NewPublicKey)
		sameAttestation := sameContent && verifyMessage(req.NewPublicKey,
			TransferAcceptMessage(transfer.ID, transfer.DeviceID, transfer.TargetTenant,
				transfer.FrozenVersion, req.NewPublicKey),
			req.Attestation)
		if sameContent && sameAttestation {
			return transferView(transfer), nil
		}
		return nil, newError(ErrCodeTransferClosed,
			"transfer %q is already accepted; a device can be received only once", req.TransferID)
	}
	if transfer.Status == TransferExpired {
		return nil, newError(ErrCodeCredentialExpired, "credential for transfer %q has expired", req.TransferID)
	}
	return nil, newError(ErrCodeTransferClosed, "transfer %q is already %s", req.TransferID, transfer.Status)
}

// CancelTransfer 由源租户在接收前取消活动转移。取消后目标租户不能再接收。
// 只有发起时记载的源租户可以取消。
func (s *Service) CancelTransfer(transferID, sourceTenant string) (*TransferView, error) {
	if transferID == "" || sourceTenant == "" {
		return nil, newError(ErrCodeInvalidArgument, "transfer id and source tenant are required")
	}
	now := s.clock.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	transfer, err := s.openTransferLocked(transferID, now)
	if err != nil {
		return nil, err
	}
	if sourceTenant != transfer.SourceTenant {
		return nil, newError(ErrCodeTransferTenantMismatch,
			"transfer %q can only be cancelled by its source tenant %q", transferID, transfer.SourceTenant)
	}

	transfer.Status = TransferCancelled
	transfer.CompletedAt = &now
	delete(s.snap.OpenTransfer, transfer.DeviceID)
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	return transferView(transfer), nil
}

// SweepExpiredTransfers 显式结算所有已超过接收窗口的 pending 转移。
// 过期同样惰性结算：访问转移单/设备时自动触发。
func (s *Service) SweepExpiredTransfers() (int, error) {
	now := s.clock.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	n := 0
	for _, tid := range s.snap.OpenTransfer {
		if s.sweepTransferLocked(s.snap.Transfers[tid], now) {
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

// sweepTransferLocked 在凭据过期时把转移推进到 expired 终态。返回是否发生迁移。
// pending -> 终态只可能发生一次，因此接收/取消/过期竞争只产生一个终态。
// 过期不改动设备归属与密钥：设备仍属源租户，源密钥继续有效。
func (s *Service) sweepTransferLocked(t *TransferRecord, now time.Time) bool {
	if t == nil || t.Status != TransferPending {
		return false
	}
	if now.Before(t.Deadline) || now.Equal(t.Deadline) {
		return false
	}
	completed := now
	t.Status = TransferExpired
	t.CompletedAt = &completed
	delete(s.snap.OpenTransfer, t.DeviceID)
	return true
}

// abortTransferForDeviceLocked 在设备被禁用时原子中止其活动转移。
func (s *Service) abortTransferForDeviceLocked(deviceID string, now time.Time) {
	tid, open := s.snap.OpenTransfer[deviceID]
	if !open {
		return
	}
	if t := s.snap.Transfers[tid]; t != nil && t.Status == TransferPending {
		t.Status = TransferAborted
		t.CompletedAt = &now
	}
	delete(s.snap.OpenTransfer, deviceID)
}

// GetTransfer 返回转移单只读视图（不含凭据/公钥/证明敏感内容）；窗口已过则惰性结算。
func (s *Service) GetTransfer(transferID string) (*TransferView, error) {
	now := s.clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	transfer, ok := s.snap.Transfers[transferID]
	if !ok {
		return nil, newError(ErrCodeTransferNotFound, "transfer %q", transferID)
	}
	if s.sweepTransferLocked(transfer, now) {
		if err := s.saveLocked(); err != nil {
			return nil, err
		}
	}
	return transferView(transfer), nil
}

// GetOwnershipHistory 返回设备当前归属、完整归属链与每次转移的两端决定和密钥版本变化。
// 结果不包含凭据、公钥或证明等敏感内容。
func (s *Service) GetOwnershipHistory(deviceID string) (*OwnershipHistory, error) {
	now := s.clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	device, ok := s.snap.Devices[deviceID]
	if !ok {
		return nil, newError(ErrCodeDeviceNotFound, "device %q", deviceID)
	}
	// 查询时顺带结算可能已过期的活动转移，使历史反映当前终态。
	if tid, open := s.snap.OpenTransfer[deviceID]; open {
		if s.sweepTransferLocked(s.snap.Transfers[tid], now) {
			if err := s.saveLocked(); err != nil {
				return nil, err
			}
		}
	}
	ids := s.snap.DeviceTransfers[deviceID]
	transfers := make([]*TransferRecord, 0, len(ids))
	for _, id := range ids {
		if t := s.snap.Transfers[id]; t != nil {
			transfers = append(transfers, t)
		}
	}
	return ownershipHistory(device, transfers), nil
}

// openTransferLocked 定位仍 pending 的转移单，并先与过期/并发终态竞争结算。
func (s *Service) openTransferLocked(transferID string, now time.Time) (*TransferRecord, error) {
	transfer, ok := s.snap.Transfers[transferID]
	if !ok {
		return nil, newError(ErrCodeTransferNotFound, "transfer %q", transferID)
	}
	s.sweepTransferLocked(transfer, now)
	if transfer.Status != TransferPending {
		return nil, newError(ErrCodeTransferClosed, "transfer %q is already %s", transferID, transfer.Status)
	}
	return transfer, nil
}

func beginTransferContentHash(deviceID, sourceTenant, targetTenant string) string {
	return hashFields("TBEGIN",
		[]byte(deviceID), []byte(sourceTenant), []byte(targetTenant))
}

func acceptTransferContentHash(targetTenant string, newPublicKey []byte) string {
	return hashFields("TACCEPT", []byte(targetTenant), newPublicKey)
}

func credentialMatches(t *TransferRecord, secret string) bool {
	return subtle.ConstantTimeCompare(t.CredentialDigest, digestSecret(t.CredentialSalt, secret)) == 1
}

// ---- 客户端侧规范报文 ----

// TransferAcceptMessage 返回目标租户接收设备时，新私钥需要签名的规范报文：
// "TRANSFER_ACCEPT|<transferID>|<deviceID>|<targetTenant>|<frozenVersion>|<newPublicKey>"。
func TransferAcceptMessage(transferID, deviceID, targetTenant string, frozenVersion int, newPublicKey []byte) []byte {
	return joinFields(
		[]byte("TRANSFER_ACCEPT"),
		[]byte(transferID),
		[]byte(deviceID),
		[]byte(targetTenant),
		[]byte(strconv.Itoa(frozenVersion)),
		newPublicKey,
	)
}
