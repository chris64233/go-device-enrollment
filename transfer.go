package deviceenrollment

import (
	"bytes"
	"crypto/ed25519"
	"sort"
	"time"
)

// DefaultTransferTTL 是接收凭据的默认有效期。
const DefaultTransferTTL = 15 * time.Minute

// BeginTransferRequest 是源租户发起设备转移的请求。
type BeginTransferRequest struct {
	DeviceID       string
	SourceTenantID string
	TargetTenantID string
	// IdempotencyKey 是源租户提供的转移号：同号同内容返回首次结果，同号异内容冲突。
	IdempotencyKey string
	// TTL <=0 时使用配置的默认接收窗口。
	TTL time.Duration
}

// AcceptTransferRequest 是目标租户接受转移的请求：新公钥与对端证明必须同时提交。
type AcceptTransferRequest struct {
	TransferID string
	// Credential 是发起响应中一次性返回的接收凭据明文。
	Credential     string
	TargetTenantID string
	NewPublicKey   []byte
	// Attestation 是新私钥对 TransferAcceptMessage 的签名。
	Attestation []byte
}

// BeginTransfer 由源租户发起转移：冻结设备当前身份、密钥版本、设备版本与目标租户，
// 并生成短期有效的一次性接收凭据。持久化只保存凭据的盐与加盐摘要，明文仅此一次返回。
//
// 禁用设备、存在未终态密钥轮换、已有活动转移时不得发起。
// 同一 (源租户, 转移号) 同内容重放返回首次转移单 ID（凭据无法再次展示，只会出现一次）；
// 同号异内容返回 ErrCodeConflict。
func (s *Service) BeginTransfer(req BeginTransferRequest) (*Transfer, error) {
	if req.DeviceID == "" || req.SourceTenantID == "" || req.TargetTenantID == "" {
		return nil, newError(ErrCodeInvalidArgument, "device id, source tenant and target tenant are required")
	}
	if req.IdempotencyKey == "" {
		return nil, newError(ErrCodeInvalidArgument, "idempotency key is required")
	}
	if req.SourceTenantID == req.TargetTenantID {
		return nil, newError(ErrCodeInvalidArgument, "target tenant must differ from source tenant")
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = s.transferTTL
	}
	now := s.clock.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	// 幂等：同号先看首次转移单。
	idemKey := transferIdemKey(req.SourceTenantID, req.IdempotencyKey)
	if firstID, ok := s.snap.TransferByKey[idemKey]; ok {
		first := s.snap.Transfers[firstID]
		if first.ContentHash != transferContentHash(req.DeviceID, req.TargetTenantID) {
			return nil, newError(ErrCodeConflict,
				"idempotency key %q already used with different transfer content", req.IdempotencyKey)
		}
		// 凭据明文只在首次响应中出现，重放只返回同一转移单身份。
		return &Transfer{ID: first.ID}, nil
	}

	device, err := s.activeDeviceLocked(req.DeviceID)
	if err != nil {
		return nil, err
	}
	if device.TenantID != req.SourceTenantID {
		return nil, newError(ErrCodeTenantMismatch,
			"device %q is not owned by tenant %q", req.DeviceID, req.SourceTenantID)
	}
	// 未终态轮换未结算前不得发起（先惰性结算超时轮换）。
	if rid, ok := s.snap.OpenRotation[req.DeviceID]; ok {
		s.sweepRotationLocked(s.snap.Rotations[rid], now)
		if _, stillOpen := s.snap.OpenRotation[req.DeviceID]; stillOpen {
			return nil, newError(ErrCodeRotationInProgress,
				"device %q has an open rotation %q", req.DeviceID, rid)
		}
	}
	// 已有活动转移不得发起（先惰性结算过期转移）。
	if tid, ok := s.snap.OpenTransfer[req.DeviceID]; ok {
		s.sweepTransferLocked(s.snap.Transfers[tid], now)
		if _, stillOpen := s.snap.OpenTransfer[req.DeviceID]; stillOpen {
			return nil, newError(ErrCodeTransferInProgress,
				"device %q has an open transfer %q", req.DeviceID, tid)
		}
	}

	credential := randomSecret()
	salt := randomBytes(16)
	rec := &TransferRecord{
		IdempotencyKey:      req.IdempotencyKey,
		ContentHash:         transferContentHash(req.DeviceID, req.TargetTenantID),
		ID:                  randomID(),
		DeviceID:            req.DeviceID,
		SourceTenantID:      req.SourceTenantID,
		TargetTenantID:      req.TargetTenantID,
		FrozenKeyVersion:    device.CurrentKeyVersion,
		FrozenDeviceVersion: device.Version,
		CredentialSalt:      salt,
		CredentialDigest:    digestSecret(salt, credential),
		Status:              TransferPending,
		Deadline:            now.Add(ttl),
		CreatedAt:           now,
		SourceDecision:      SourceDecisionRequested,
		TargetDecision:      TargetDecisionNone,
	}
	s.snap.Transfers[rec.ID] = rec
	s.snap.OpenTransfer[req.DeviceID] = rec.ID
	s.snap.TransferByKey[idemKey] = rec.ID
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	return &Transfer{ID: rec.ID, Credential: credential}, nil
}

// AcceptTransfer 由目标租户接受转移。
//
// 证明（新私钥签名）、接收凭据、发起时冻结的设备版本三者必须同时匹配，
// 任一不匹配都整单失败，不做任何部分修改——绝不会出现归属已变但新密钥未生效的中间态。
// 全部校验通过后在同一个快照变更内：切换归属到目标租户、登记并启用新密钥版本、
// 失效设备此前的全部密钥（源租户认证资格立即终止）、追加归属链并把转移推为 accepted。
func (s *Service) AcceptTransfer(req AcceptTransferRequest) (*TransferView, error) {
	if req.TransferID == "" || req.Credential == "" || req.TargetTenantID == "" {
		return nil, newError(ErrCodeInvalidArgument, "transfer id, credential and target tenant are required")
	}
	if len(req.NewPublicKey) != ed25519.PublicKeySize {
		return nil, newError(ErrCodeInvalidArgument, "public key must be ed25519 (%d bytes)", ed25519.PublicKeySize)
	}
	now := s.clock.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	tr, err := s.openTransferLocked(req.TransferID, now)
	if err != nil {
		return nil, err
	}
	// 以下校验全部先于任何状态修改，保证失败时无副作用。
	if !credentialMatches(tr, req.Credential) {
		return nil, newError(ErrCodeTransferCredentialMismatch, "transfer credential does not match")
	}
	if req.TargetTenantID != tr.TargetTenantID {
		return nil, newError(ErrCodeTenantMismatch,
			"transfer %q is not addressed to tenant %q", req.TransferID, req.TargetTenantID)
	}
	device, ok := s.snap.Devices[tr.DeviceID]
	if !ok {
		// 理论上不可达：设备与活动转移在同一快照内。
		return nil, newError(ErrCodeDeviceNotFound, "device %q", tr.DeviceID)
	}
	if device.Version != tr.FrozenDeviceVersion {
		return nil, newError(ErrCodeDeviceVersionMismatch,
			"device version changed since transfer began: frozen %d, current %d",
			tr.FrozenDeviceVersion, device.Version)
	}
	current := device.Keys[device.CurrentKeyVersion]
	if current == nil || bytes.Equal(current.PublicKey, req.NewPublicKey) {
		return nil, newError(ErrCodeInvalidArgument, "new public key must differ from the current key")
	}
	if !verifyTransferAttestation(tr.ID, tr.DeviceID, tr.SourceTenantID, tr.TargetTenantID,
		req.NewPublicKey, req.Attestation) {
		return nil, newError(ErrCodeAttestationFailed, "transfer attestation signature is invalid")
	}

	// 全部通过：原子切换。
	// 转移发起后源租户可能又开过轮换：若轮换尚未完成，则随本次接受一并中止，
	// 这样其迟到的双侧确认只会得到 rotation_closed，绝不可能把当前密钥改回旧租户的版本。
	if rid, open := s.snap.OpenRotation[device.ID]; open {
		if r := s.snap.Rotations[rid]; r != nil && r.Status == RotationPending {
			if k := device.Keys[r.NewVersion]; k != nil && k.State == KeyStatePending {
				k.State = KeyStateInvalidated
			}
			r.Status = RotationAborted
			r.CompletedAt = &now
		}
		delete(s.snap.OpenRotation, device.ID)
	}
	newVersion := device.NextKeyVersion + 1
	for _, k := range device.Keys {
		// 源租户在本设备上的全部密钥资格（含历史版本）立即失效。
		k.State = KeyStateInvalidated
	}
	device.Keys[newVersion] = &KeyRecord{
		Version:   newVersion,
		PublicKey: append([]byte(nil), req.NewPublicKey...),
		State:     KeyStateActive,
		CreatedAt: now,
	}
	device.NextKeyVersion = newVersion
	oldKeyVersion := device.CurrentKeyVersion
	device.CurrentKeyVersion = newVersion
	device.TenantID = tr.TargetTenantID
	device.Version++

	tr.Status = TransferAccepted
	tr.SourceDecision = SourceDecisionRequested
	tr.TargetDecision = TargetDecisionAccepted
	tr.AcceptedNewKeyVersion = newVersion
	tr.ResolvedAt = &now
	delete(s.snap.OpenTransfer, device.ID)

	chain := s.snap.Ownership[device.ID]
	s.snap.Ownership[device.ID] = append(chain, &OwnershipEvent{
		Seq:         len(chain) + 1,
		TenantID:    tr.TargetTenantID,
		TransferID:  tr.ID,
		FromVersion: oldKeyVersion,
		ToVersion:   newVersion,
		At:          now,
	})

	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	return transferView(tr), nil
}

// CancelTransfer 由源租户在接收窗口内取消活动转移。
// cancelSignature 必须是发起时冻结的当前密钥对 TransferCancelMessage 的签名；
// 取消与接受/过期竞争时只有一个终态。
func (s *Service) CancelTransfer(transferID, sourceTenantID string, cancelSignature []byte) (*TransferView, error) {
	if transferID == "" || sourceTenantID == "" {
		return nil, newError(ErrCodeInvalidArgument, "transfer id and source tenant are required")
	}
	now := s.clock.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	tr, err := s.openTransferLocked(transferID, now)
	if err != nil {
		return nil, err
	}
	if sourceTenantID != tr.SourceTenantID {
		return nil, newError(ErrCodeTenantMismatch,
			"transfer %q was not initiated by tenant %q", transferID, sourceTenantID)
	}
	device := s.snap.Devices[tr.DeviceID]
	key := device.Keys[tr.FrozenKeyVersion]
	if key == nil || !verifyMessage(key.PublicKey, TransferCancelMessage(tr.DeviceID, tr.ID), cancelSignature) {
		return nil, newError(ErrCodeSignatureInvalid, "transfer must be cancelled by the frozen current key")
	}

	tr.Status = TransferCancelled
	tr.SourceDecision = SourceDecisionCancelled
	tr.ResolvedAt = &now
	delete(s.snap.OpenTransfer, tr.DeviceID)
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	return transferView(tr), nil
}

// SweepExpiredTransfers 显式结算所有已超过接收窗口的 pending 转移（凭据过期）。
// 过期同样是惰性的：查询、接受、取消、发起时都会自动触发。
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

// sweepTransferLocked 在接收窗口关闭时把转移推进到 expired 终态。
// pending -> 终态只可能发生一次，因此接受/取消/过期/禁用竞争只产生一个终态。
func (s *Service) sweepTransferLocked(t *TransferRecord, now time.Time) bool {
	if t == nil || t.Status != TransferPending {
		return false
	}
	if now.Before(t.Deadline) || now.Equal(t.Deadline) {
		return false
	}
	t.Status = TransferExpired
	t.ResolvedAt = &now
	delete(s.snap.OpenTransfer, t.DeviceID)
	return true
}

// abortTransferLocked 在设备被禁用时把活动转移推进到 aborted 终态。
func (s *Service) abortTransferLocked(deviceID string, now time.Time) {
	tid, ok := s.snap.OpenTransfer[deviceID]
	if !ok {
		return
	}
	t := s.snap.Transfers[tid]
	if t == nil || t.Status != TransferPending {
		delete(s.snap.OpenTransfer, deviceID)
		return
	}
	t.Status = TransferAborted
	t.SourceDecision = SourceDecisionAborted
	t.ResolvedAt = &now
	delete(s.snap.OpenTransfer, deviceID)
}

// GetTransfer 返回转移单只读视图（不含凭据、盐、摘要与证明材料）；
// 若接收窗口已过，会先惰性结算过期。
func (s *Service) GetTransfer(transferID string) (*TransferView, error) {
	now := s.clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	tr, ok := s.snap.Transfers[transferID]
	if !ok {
		return nil, newError(ErrCodeTransferNotFound, "transfer %q", transferID)
	}
	if s.sweepTransferLocked(tr, now) {
		if err := s.saveLocked(); err != nil {
			return nil, err
		}
	}
	return transferView(tr), nil
}

// GetOwnershipChain 返回设备归属链：每一站归属、关联转移单与密钥版本变化。
// 视图中只包含转移元数据与决定，绝不包含凭据、公钥证明等敏感内容。
func (s *Service) GetOwnershipChain(deviceID string) (*OwnershipChainView, error) {
	now := s.clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.snap.Devices[deviceID]; !ok {
		return nil, newError(ErrCodeDeviceNotFound, "device %q", deviceID)
	}
	// 结算可能刚过期的活动转移，使链上视图保持最新。
	if tid, open := s.snap.OpenTransfer[deviceID]; open {
		if s.sweepTransferLocked(s.snap.Transfers[tid], now) {
			if err := s.saveLocked(); err != nil {
				return nil, err
			}
		}
	}

	events := s.snap.Ownership[deviceID]
	history := make([]OwnershipEvent, 0, len(events))
	for _, e := range events {
		history = append(history, *e)
	}
	sort.SliceStable(history, func(i, j int) bool { return history[i].Seq < history[j].Seq })

	var current OwnershipEvent
	if len(history) > 0 {
		current = history[len(history)-1]
	}

	transfers := make([]TransferView, 0)
	for _, tr := range s.snap.Transfers {
		if tr.DeviceID == deviceID {
			transfers = append(transfers, *transferView(tr))
		}
	}
	sort.SliceStable(transfers, func(i, j int) bool {
		if !transfers[i].CreatedAt.Equal(transfers[j].CreatedAt) {
			return transfers[i].CreatedAt.Before(transfers[j].CreatedAt)
		}
		return transfers[i].ID < transfers[j].ID
	})

	return &OwnershipChainView{
		DeviceID:  deviceID,
		Current:   current,
		History:   history,
		Transfers: transfers,
	}, nil
}

// openTransferLocked 定位仍处于 pending 的转移单，并先与过期/并发终态竞争结算。
func (s *Service) openTransferLocked(transferID string, now time.Time) (*TransferRecord, error) {
	tr, ok := s.snap.Transfers[transferID]
	if !ok {
		return nil, newError(ErrCodeTransferNotFound, "transfer %q", transferID)
	}
	if s.sweepTransferLocked(tr, now) {
		return nil, newError(ErrCodeTransferExpired, "transfer %q credential expired at %s",
			transferID, tr.Deadline.Format(time.RFC3339Nano))
	}
	if tr.Status != TransferPending {
		return nil, newError(ErrCodeTransferClosed, "transfer %q is already %s", transferID, tr.Status)
	}
	return tr, nil
}

func transferIdemKey(sourceTenantID, idempotencyKey string) string {
	return sourceTenantID + "\x00" + idempotencyKey
}

// ---- 客户端侧规范报文 ----

// TransferAcceptMessage 返回目标租户接受转移时，新私钥需要签名的规范报文：
// "TRANSFER_ACCEPT|<transferID>|<deviceID>|<sourceTenantID>|<targetTenantID>|<newPublicKey>"。
func TransferAcceptMessage(transferID, deviceID, sourceTenantID, targetTenantID string, newPublicKey []byte) []byte {
	return joinFields(
		[]byte("TRANSFER_ACCEPT"),
		[]byte(transferID),
		[]byte(deviceID),
		[]byte(sourceTenantID),
		[]byte(targetTenantID),
		newPublicKey,
	)
}

// TransferCancelMessage 返回源租户取消转移的规范待签名报文，由发起时冻结的当前密钥签名。
func TransferCancelMessage(deviceID, transferID string) []byte {
	return joinFields(
		[]byte("TRANSFER_CANCEL"),
		[]byte(deviceID),
		[]byte(transferID),
	)
}
