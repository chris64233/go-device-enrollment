package deviceenrollment

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

const (
	tenantA = "tenant-a"
	tenantB = "tenant-b"
	tenantC = "tenant-c"
)

type transferFixture struct {
	env      *testEnv
	dev      *DeviceView
	oldK     deviceKey
	external string
}

func setupTransferableDevice(t *testing.T, transferTTL time.Duration) *transferFixture {
	t.Helper()
	env := newTestEnv(t, time.Minute, 10*time.Minute)
	if transferTTL > 0 {
		env.svc.transferTTL = transferTTL
	}
	oldK := mustKey(t)
	external := "dev-transfer-" + t.Name()
	ch := env.issue(t, external, tenantA, []byte("attr"), 0)
	dev := mustRegister(t, env, ch, external, []byte("attr"), oldK)
	return &transferFixture{env: env, dev: dev, oldK: oldK, external: external}
}

func beginTransferFor(t *testing.T, f *transferFixture, target string, ttl time.Duration) (*Transfer, *TransferRecord) {
	t.Helper()
	tr, err := f.env.svc.BeginTransfer(BeginTransferRequest{
		DeviceID:       f.dev.ID,
		SourceTenantID: tenantA,
		TargetTenantID: target,
		IdempotencyKey: "idem-" + randomID(),
		TTL:            ttl,
	})
	if err != nil {
		t.Fatalf("BeginTransfer: %v", err)
	}
	rec := f.env.svc.snap.Transfers[tr.ID]
	return tr, rec
}

func acceptSig(priv ed25519.PrivateKey, rec *TransferRecord, newPub ed25519.PublicKey) []byte {
	return signMessage(priv,
		TransferAcceptMessage(rec.ID, rec.DeviceID, rec.SourceTenantID, rec.TargetTenantID, newPub))
}

func acceptOK(t *testing.T, f *transferFixture, tr *Transfer, target string, newK deviceKey) *TransferView {
	t.Helper()
	rec := f.env.svc.snap.Transfers[tr.ID]
	view, err := f.env.svc.AcceptTransfer(AcceptTransferRequest{
		TransferID:     tr.ID,
		Credential:     tr.Credential,
		TargetTenantID: target,
		NewPublicKey:   newK.pub,
		Attestation:    acceptSig(newK.priv, rec, newK.pub),
	})
	if err != nil {
		t.Fatalf("AcceptTransfer: %v", err)
	}
	return view
}

// ---- 发起 ----

func TestTransfer_Begin_StoresCredentialDigestOnly(t *testing.T) {
	f := setupTransferableDevice(t, 0)
	tr, rec := beginTransferFor(t, f, tenantB, 5*time.Minute)

	if tr.ID == "" || tr.Credential == "" {
		t.Fatal("transfer id/credential empty")
	}
	if rec.ID != tr.ID {
		t.Fatal("view id does not match record")
	}
	if len(rec.CredentialSalt) == 0 || len(rec.CredentialDigest) == 0 {
		t.Fatal("credential salt/digest missing")
	}
	if bytes.Contains(rec.CredentialDigest, []byte(tr.Credential)) {
		t.Fatal("plaintext credential leaked into digest storage")
	}
	if bytes.Equal(rec.CredentialDigest, []byte(tr.Credential)) {
		t.Fatal("digest equals plaintext credential")
	}
	if rec.SourceTenantID != tenantA || rec.TargetTenantID != tenantB ||
		rec.FrozenKeyVersion != 1 || rec.FrozenDeviceVersion != 1 {
		t.Fatalf("frozen snapshot wrong: %+v", rec)
	}
	if rec.Status != TransferPending || rec.TargetDecision != TargetDecisionNone {
		t.Fatalf("unexpected initial state: %+v", rec)
	}
	if !rec.Deadline.Equal(f.env.clock.Now().Add(5 * time.Minute)) {
		t.Fatalf("deadline = %v", rec.Deadline)
	}
	if f.env.svc.snap.OpenTransfer[f.dev.ID] != tr.ID {
		t.Fatal("open transfer not indexed")
	}

	// 落盘文件中也不得出现明文凭据。
	data := mustMarshalSnapshot(t, f.env.svc.snap)
	if bytes.Contains(data, []byte(tr.Credential)) {
		t.Fatal("plaintext credential present in persisted snapshot")
	}
}

func TestTransfer_BeginGuards(t *testing.T) {
	f := setupTransferableDevice(t, 0)

	cases := []struct {
		name string
		req  BeginTransferRequest
		want ErrorCode
	}{
		{"missing device", BeginTransferRequest{SourceTenantID: tenantA, TargetTenantID: tenantB, IdempotencyKey: "k"}, ErrCodeInvalidArgument},
		{"missing source", BeginTransferRequest{DeviceID: f.dev.ID, TargetTenantID: tenantB, IdempotencyKey: "k"}, ErrCodeInvalidArgument},
		{"missing target", BeginTransferRequest{DeviceID: f.dev.ID, SourceTenantID: tenantA, IdempotencyKey: "k"}, ErrCodeInvalidArgument},
		{"missing idem key", BeginTransferRequest{DeviceID: f.dev.ID, SourceTenantID: tenantA, TargetTenantID: tenantB}, ErrCodeInvalidArgument},
		{"same tenant", BeginTransferRequest{DeviceID: f.dev.ID, SourceTenantID: tenantA, TargetTenantID: tenantA, IdempotencyKey: "k"}, ErrCodeInvalidArgument},
		{"not owner", BeginTransferRequest{DeviceID: f.dev.ID, SourceTenantID: tenantB, TargetTenantID: tenantC, IdempotencyKey: "k"}, ErrCodeTenantMismatch},
		{"unknown device", BeginTransferRequest{DeviceID: "ghost", SourceTenantID: tenantA, TargetTenantID: tenantB, IdempotencyKey: "k"}, ErrCodeDeviceNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := f.env.svc.BeginTransfer(tc.req); ErrorCodeOf(err) != tc.want {
				t.Fatalf("want %s, got %v", tc.want, err)
			}
		})
	}

	// 禁用设备不能发起。
	if _, err := f.env.svc.DisableDevice(f.dev.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.env.svc.BeginTransfer(BeginTransferRequest{
		DeviceID: f.dev.ID, SourceTenantID: tenantA, TargetTenantID: tenantB, IdempotencyKey: "k2",
	}); ErrorCodeOf(err) != ErrCodeDeviceDisabled {
		t.Fatalf("want disabled, got %v", err)
	}

	// 有未终态轮换时不能发起。
	f2 := setupTransferableDevice(t, 0)
	newK := mustKey(t)
	beginRotation(t, f2.env, f2.dev, f2.oldK, newK)
	if _, err := f2.env.svc.BeginTransfer(BeginTransferRequest{
		DeviceID: f2.dev.ID, SourceTenantID: tenantA, TargetTenantID: tenantB, IdempotencyKey: "k3",
	}); ErrorCodeOf(err) != ErrCodeRotationInProgress {
		t.Fatalf("want rotation in progress, got %v", err)
	}

	// 已有活动转移时不能重复发起（即使换了目标租户）。
	f3 := setupTransferableDevice(t, 0)
	beginTransferFor(t, f3, tenantB, 0)
	if _, err := f3.env.svc.BeginTransfer(BeginTransferRequest{
		DeviceID: f3.dev.ID, SourceTenantID: tenantA, TargetTenantID: tenantC, IdempotencyKey: "other",
	}); ErrorCodeOf(err) != ErrCodeTransferInProgress {
		t.Fatalf("want transfer in progress, got %v", err)
	}

	// 活动转移过期后，惰性结算，允许重新发起。
	f3.env.clock.Advance(DefaultTransferTTL + time.Nanosecond)
	if _, err := f3.env.svc.BeginTransfer(BeginTransferRequest{
		DeviceID: f3.dev.ID, SourceTenantID: tenantA, TargetTenantID: tenantC, IdempotencyKey: "other2",
	}); err != nil {
		t.Fatalf("begin after lazy expiry: %v", err)
	}
}

// ---- 接受：成功路径 ----

func TestTransfer_Accept_HappyPath(t *testing.T) {
	f := setupTransferableDevice(t, 0)
	tr, rec := beginTransferFor(t, f, tenantB, 0)
	newK := mustKey(t)

	view := acceptOK(t, f, tr, tenantB, newK)
	if view.Status != TransferAccepted || view.ResolvedAt == nil {
		t.Fatalf("status = %s", view.Status)
	}
	if view.NewKeyVersion != 2 || view.SourceDecision != SourceDecisionRequested ||
		view.TargetDecision != TargetDecisionAccepted {
		t.Fatalf("accepted view wrong: %+v", view)
	}

	// 原子切换：归属、设备版本、当前密钥版本。
	dev, err := f.env.svc.GetDevice(f.dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	if dev.TenantID != tenantB || dev.Version != 2 || dev.CurrentKeyVersion != 2 {
		t.Fatalf("device after accept: %+v", dev)
	}
	if !bytes.Equal(dev.PublicKey, newK.pub) {
		t.Fatal("current public key is not the target's new key")
	}

	// 源租户全部密钥资格立即失效：旧版本认证被拒。
	if err := f.env.svc.Authenticate(AuthRequest{
		DeviceID: dev.ID, KeyVersion: 1, Message: []byte("late"),
		Signature: signMessage(f.oldK.priv, []byte("late")),
	}); ErrorCodeOf(err) != ErrCodeKeyVersionInvalid {
		t.Fatalf("want key version invalid for old tenant, got %v", err)
	}
	// 新密钥认证成功。
	mustAuth(t, f.env.svc, dev, newK, []byte("new tenant"))

	// 转移单已离开活动索引；凭据被一次性消费，重复接受被拒。
	if _, open := f.env.svc.snap.OpenTransfer[dev.ID]; open {
		t.Fatal("accepted transfer still indexed as open")
	}
	if _, err := f.env.svc.AcceptTransfer(AcceptTransferRequest{
		TransferID: tr.ID, Credential: tr.Credential, TargetTenantID: tenantB,
		NewPublicKey: newK.pub, Attestation: acceptSig(newK.priv, rec, newK.pub),
	}); ErrorCodeOf(err) != ErrCodeTransferClosed {
		t.Fatalf("want closed on double accept, got %v", err)
	}
}

// ---- 接受：三要素任一不匹配都不得产生中间态 ----

func TestTransfer_Accept_MismatchesChangeNothing(t *testing.T) {
	// 凭据错误 / 租户错误 / 证明错误 / 公钥相同：转移保持 pending，设备保持原归属。
	check := func(t *testing.T, mutate func(*AcceptTransferRequest, *TransferRecord, deviceKey, deviceKey), want ErrorCode) {
		f := setupTransferableDevice(t, 0)
		tr, rec := beginTransferFor(t, f, tenantB, 0)
		newK := mustKey(t)
		req := AcceptTransferRequest{
			TransferID:     tr.ID,
			Credential:     tr.Credential,
			TargetTenantID: tenantB,
			NewPublicKey:   newK.pub,
			Attestation:    acceptSig(newK.priv, rec, newK.pub),
		}
		mutate(&req, rec, f.oldK, newK)
		if _, err := f.env.svc.AcceptTransfer(req); ErrorCodeOf(err) != want {
			t.Fatalf("want %s, got %v", want, err)
		}
		stored := f.env.svc.snap.Transfers[tr.ID]
		if stored.Status != TransferPending || stored.TargetDecision != TargetDecisionNone {
			t.Fatalf("failed accept mutated transfer: %+v", stored)
		}
		dev := f.env.svc.snap.Devices[f.dev.ID]
		if dev.TenantID != tenantA || dev.Version != 1 || dev.CurrentKeyVersion != 1 {
			t.Fatalf("failed accept mutated device: tenant=%s version=%d key=%d",
				dev.TenantID, dev.Version, dev.CurrentKeyVersion)
		}
		if _, open := f.env.svc.snap.OpenTransfer[f.dev.ID]; !open {
			t.Fatal("failed accept must leave transfer open")
		}
	}

	t.Run("bad credential", func(t *testing.T) {
		check(t, func(req *AcceptTransferRequest, _ *TransferRecord, _, _ deviceKey) {
			req.Credential = "wrong"
		}, ErrCodeTransferCredentialMismatch)
	})
	t.Run("missing credential", func(t *testing.T) {
		check(t, func(req *AcceptTransferRequest, _ *TransferRecord, _, _ deviceKey) {
			req.Credential = ""
		}, ErrCodeInvalidArgument)
	})
	t.Run("wrong target tenant", func(t *testing.T) {
		check(t, func(req *AcceptTransferRequest, _ *TransferRecord, _, _ deviceKey) {
			req.TargetTenantID = tenantC
		}, ErrCodeTenantMismatch)
	})
	t.Run("bad attestation", func(t *testing.T) {
		check(t, func(req *AcceptTransferRequest, _ *TransferRecord, _, _ deviceKey) {
			req.Attestation = make([]byte, ed25519.SignatureSize)
		}, ErrCodeAttestationFailed)
	})
	t.Run("attestation from a different key", func(t *testing.T) {
		check(t, func(req *AcceptTransferRequest, rec *TransferRecord, _, newK deviceKey) {
			other := mustKey(t)
			req.Attestation = acceptSig(other.priv, rec, newK.pub)
		}, ErrCodeAttestationFailed)
	})
	t.Run("attestation bound to other transfer", func(t *testing.T) {
		f := setupTransferableDevice(t, 0)
		tr1, rec1 := beginTransferFor(t, f, tenantB, 0)
		// 第二张转移单（先取消第一张）。
		if _, err := f.env.svc.CancelTransfer(tr1.ID, tenantA,
			signMessage(f.oldK.priv, TransferCancelMessage(f.dev.ID, tr1.ID))); err != nil {
			t.Fatal(err)
		}
		tr2, rec2 := beginTransferFor(t, f, tenantB, 0)
		newK := mustKey(t)
		// 用第一张单的上下文做证明，对第二张单无效。
		wrongAtt := acceptSig(newK.priv, rec1, newK.pub)
		_ = rec2
		if _, err := f.env.svc.AcceptTransfer(AcceptTransferRequest{
			TransferID: tr2.ID, Credential: tr2.Credential, TargetTenantID: tenantB,
			NewPublicKey: newK.pub, Attestation: wrongAtt,
		}); ErrorCodeOf(err) != ErrCodeAttestationFailed {
			t.Fatalf("want attestation failed, got %v", err)
		}
	})
	t.Run("same key as current", func(t *testing.T) {
		check(t, func(req *AcceptTransferRequest, rec *TransferRecord, oldK, _ deviceKey) {
			req.NewPublicKey = oldK.pub
			req.Attestation = acceptSig(oldK.priv, rec, oldK.pub)
		}, ErrCodeInvalidArgument)
	})
	t.Run("unknown transfer", func(t *testing.T) {
		f := setupTransferableDevice(t, 0)
		newK := mustKey(t)
		if _, err := f.env.svc.AcceptTransfer(AcceptTransferRequest{
			TransferID: "ghost", Credential: "x", TargetTenantID: tenantB,
			NewPublicKey: newK.pub, Attestation: []byte("x"),
		}); ErrorCodeOf(err) != ErrCodeTransferNotFound {
			t.Fatalf("want not found, got %v", err)
		}
	})
}

// 失败的接受尝试是零副作用的：凭据仍然一次性、可在修正请求后继续使用；
// 一旦接受成功，凭据立即作废，重复接收被终态拒绝。
func TestTransfer_Accept_FailedAttemptThenSuccessConsumesCredentialOnce(t *testing.T) {
	f := setupTransferableDevice(t, 0)
	tr, rec := beginTransferFor(t, f, tenantB, 0)

	// 第一次用错误凭据：整单失败、零副作用（已由 MismatchesChangeNothing 覆盖状态不变），
	// 这里进一步验证凭据并未被“预消费”。
	targetK := mustKey(t)
	goodAtt := acceptSig(targetK.priv, rec, targetK.pub)
	if _, err := f.env.svc.AcceptTransfer(AcceptTransferRequest{
		TransferID: tr.ID, Credential: "not-the-credential", TargetTenantID: tenantB,
		NewPublicKey: targetK.pub, Attestation: goodAtt,
	}); ErrorCodeOf(err) != ErrCodeTransferCredentialMismatch {
		t.Fatalf("want credential mismatch, got %v", err)
	}

	// 证明错误再来一次，凭据依旧可用。
	if _, err := f.env.svc.AcceptTransfer(AcceptTransferRequest{
		TransferID: tr.ID, Credential: tr.Credential, TargetTenantID: tenantB,
		NewPublicKey: targetK.pub, Attestation: make([]byte, ed25519.SignatureSize),
	}); ErrorCodeOf(err) != ErrCodeAttestationFailed {
		t.Fatalf("want attestation failed, got %v", err)
	}

	// 修正请求后接受成功，凭据在成功的这一刻才被一次性消费。
	view, err := f.env.svc.AcceptTransfer(AcceptTransferRequest{
		TransferID: tr.ID, Credential: tr.Credential, TargetTenantID: tenantB,
		NewPublicKey: targetK.pub, Attestation: goodAtt,
	})
	if err != nil {
		t.Fatalf("accept after failed attempts: %v", err)
	}
	if view.Status != TransferAccepted {
		t.Fatalf("status = %s", view.Status)
	}

	// 同一凭据不可再次接收同一设备（即使换一把新公钥与证明）。
	otherK := mustKey(t)
	if _, err := f.env.svc.AcceptTransfer(AcceptTransferRequest{
		TransferID: tr.ID, Credential: tr.Credential, TargetTenantID: tenantB,
		NewPublicKey: otherK.pub, Attestation: acceptSig(otherK.priv, rec, otherK.pub),
	}); ErrorCodeOf(err) != ErrCodeTransferClosed {
		t.Fatalf("want closed on credential reuse, got %v", err)
	}
}

// 设备版本不匹配：发起后完成了轮换，接受必须失败且归属保持不变。
func TestTransfer_Accept_DeviceVersionMismatch(t *testing.T) {
	f := setupTransferableDevice(t, 0)
	tr, _ := beginTransferFor(t, f, tenantB, 0)

	// 源租户在窗口内完成轮换（v1 -> v2），设备版本前进到 2。
	newK := mustKey(t)
	rot := beginRotation(t, f.env, f.dev, f.oldK, newK)
	if _, err := f.env.svc.ConfirmRotation(rot.ID,
		KeyConfirmation{1, signMessage(f.oldK.priv, confirmMsg(rot))},
		KeyConfirmation{2, signMessage(newK.priv, confirmMsg(rot))},
	); err != nil {
		t.Fatal(err)
	}

	targetK := mustKey(t)
	rec := f.env.svc.snap.Transfers[tr.ID]
	if _, err := f.env.svc.AcceptTransfer(AcceptTransferRequest{
		TransferID: tr.ID, Credential: tr.Credential, TargetTenantID: tenantB,
		NewPublicKey: targetK.pub, Attestation: acceptSig(targetK.priv, rec, targetK.pub),
	}); ErrorCodeOf(err) != ErrCodeDeviceVersionMismatch {
		t.Fatalf("want device version mismatch, got %v", err)
	}
	dev := f.env.svc.snap.Devices[f.dev.ID]
	if dev.TenantID != tenantA || dev.Version != 2 || dev.CurrentKeyVersion != 2 {
		t.Fatalf("device changed despite mismatch: %+v", dev)
	}
	if f.env.svc.snap.Transfers[tr.ID].Status != TransferPending {
		t.Fatal("transfer must remain pending after version mismatch")
	}
}

// 接受时仍 pending 的轮换被原子中止；其迟到确认不能把归属/密钥改回去。
func TestTransfer_Accept_AbortsPendingRotationAndRejectsLateConfirm(t *testing.T) {
	f := setupTransferableDevice(t, 0)
	tr, _ := beginTransferFor(t, f, tenantB, 0)

	intruderK := mustKey(t)
	rot := beginRotation(t, f.env, f.dev, f.oldK, intruderK)

	targetK := mustKey(t)
	view := acceptOK(t, f, tr, tenantB, targetK)
	if view.NewKeyVersion != 3 {
		// v2 是被中止轮换预占的版本，目标新钥应为 v3。
		t.Fatalf("new key version = %d, want 3", view.NewKeyVersion)
	}
	if f.env.svc.snap.Rotations[rot.ID].Status != RotationAborted {
		t.Fatalf("pending rotation status = %s, want aborted", f.env.svc.snap.Rotations[rot.ID].Status)
	}

	// 旧租户的迟到双侧确认被终态拒绝，当前钥仍是目标租户的 v3。
	if _, err := f.env.svc.ConfirmRotation(rot.ID,
		KeyConfirmation{1, signMessage(f.oldK.priv, confirmMsg(rot))},
		KeyConfirmation{2, signMessage(intruderK.priv, confirmMsg(rot))},
	); ErrorCodeOf(err) != ErrCodeRotationClosed {
		t.Fatalf("want rotation closed, got %v", err)
	}
	dev, _ := f.env.svc.GetDevice(f.dev.ID)
	if dev.TenantID != tenantB || dev.CurrentKeyVersion != 3 {
		t.Fatalf("late rotation confirmation overwrote new ownership: %+v", dev)
	}
	if f.env.svc.snap.Devices[f.dev.ID].Keys[2].State != KeyStateInvalidated {
		t.Fatal("aborted rotation pending key must be invalidated")
	}
}

// 转移成功后旧租户与新归属彻底脱钩：既不能再发起转移，也不能再发起轮换；
// 新租户在同一设备上的生命周期正常运转。
func TestTransfer_Accept_OldTenantFullyDetached(t *testing.T) {
	f := setupTransferableDevice(t, 0)
	tr, _ := beginTransferFor(t, f, tenantB, 0)
	keyB := mustKey(t)
	acceptOK(t, f, tr, tenantB, keyB)

	// 旧租户再发起转移：非属主。
	if _, err := f.env.svc.BeginTransfer(BeginTransferRequest{
		DeviceID: f.dev.ID, SourceTenantID: tenantA, TargetTenantID: tenantC,
		IdempotencyKey: "stale-begin",
	}); ErrorCodeOf(err) != ErrCodeTenantMismatch {
		t.Fatalf("old tenant begin transfer: want tenant mismatch, got %v", err)
	}

	// 旧租户用旧钥发起轮换：签名能验证（旧钥仍在册），但旧钥已不是当前钥，
	// 不能驱动新归属下的设备。
	intruderPub := mustKey(t).pub
	if _, err := f.env.svc.BeginRotation(f.dev.ID, intruderPub,
		signMessage(f.oldK.priv, RotationBeginMessage(f.dev.ID, intruderPub)),
	); ErrorCodeOf(err) != ErrCodeSignatureInvalid {
		t.Fatalf("old key begin rotation: want signature invalid, got %v", err)
	}
	// 旧钥在新归属下也不能认证。
	if err := f.env.svc.Authenticate(AuthRequest{
		DeviceID: f.dev.ID, KeyVersion: 1, Message: []byte("x"),
		Signature: signMessage(f.oldK.priv, []byte("x")),
	}); ErrorCodeOf(err) != ErrCodeKeyVersionInvalid {
		t.Fatalf("old key auth: want key version invalid, got %v", err)
	}

	// 新租户钥发起轮换并完成：设备版本继续前进，旧钥状态保持失效。
	keyC := mustKey(t)
	rot, err := f.env.svc.BeginRotation(f.dev.ID, keyC.pub,
		signMessage(keyB.priv, RotationBeginMessage(f.dev.ID, keyC.pub)))
	if err != nil {
		t.Fatalf("new owner begin rotation: %v", err)
	}
	if _, err := f.env.svc.ConfirmRotation(rot.ID,
		KeyConfirmation{2, signMessage(keyB.priv, confirmMsg(rot))},
		KeyConfirmation{3, signMessage(keyC.priv, confirmMsg(rot))},
	); err != nil {
		t.Fatalf("new owner confirm rotation: %v", err)
	}
	got := f.env.svc.snap.Devices[f.dev.ID]
	if got.TenantID != tenantB || got.Version != 3 || got.CurrentKeyVersion != 3 ||
		got.Keys[1].State != KeyStateInvalidated || got.Keys[2].State != KeyStateInvalidated {
		t.Fatalf("device after new-owner rotation wrong: %+v", got)
	}
	if err := f.env.svc.Authenticate(AuthRequest{
		DeviceID: f.dev.ID, KeyVersion: 3, Message: []byte("c"),
		Signature: signMessage(keyC.priv, []byte("c")),
	}); err != nil {
		t.Fatalf("new owner key v3 auth: %v", err)
	}
}

// 转移窗口内源租户完成了轮换：接受会因设备版本前进被拒；
// 源租户用发起时冻结的旧钥签名仍可取消这张已不可能被接受的转移单，
// 取消不触碰新版本密钥，设备留在源租户并以新钥继续运转。
func TestTransfer_RotationCompletedDuringWindow_CancelStillPossible(t *testing.T) {
	f := setupTransferableDevice(t, 0)
	tr, rec := beginTransferFor(t, f, tenantB, 0)

	rotK := mustKey(t)
	rot := beginRotation(t, f.env, f.dev, f.oldK, rotK)
	if _, err := f.env.svc.ConfirmRotation(rot.ID,
		KeyConfirmation{1, signMessage(f.oldK.priv, confirmMsg(rot))},
		KeyConfirmation{2, signMessage(rotK.priv, confirmMsg(rot))},
	); err != nil {
		t.Fatal(err)
	}

	// 接受：设备版本不匹配，零副作用。
	targetK := mustKey(t)
	if _, err := f.env.svc.AcceptTransfer(AcceptTransferRequest{
		TransferID: tr.ID, Credential: tr.Credential, TargetTenantID: tenantB,
		NewPublicKey: targetK.pub, Attestation: acceptSig(targetK.priv, rec, targetK.pub),
	}); ErrorCodeOf(err) != ErrCodeDeviceVersionMismatch {
		t.Fatalf("want device version mismatch, got %v", err)
	}

	// 用冻结的旧钥签名取消：成功；旧钥虽已失效，但签名密码学上仍可验证。
	view, err := f.env.svc.CancelTransfer(tr.ID, tenantA,
		signMessage(f.oldK.priv, TransferCancelMessage(f.dev.ID, tr.ID)))
	if err != nil {
		t.Fatalf("cancel with frozen key after rotation: %v", err)
	}
	if view.Status != TransferCancelled {
		t.Fatalf("status = %s", view.Status)
	}

	// 设备留在源租户，轮换后的 v2 钥保持有效，旧 v1 钥保持失效。
	dev := f.env.svc.snap.Devices[f.dev.ID]
	if dev.TenantID != tenantA || dev.Version != 2 || dev.CurrentKeyVersion != 2 ||
		dev.Keys[1].State != KeyStateInvalidated || dev.Keys[2].State != KeyStateActive {
		t.Fatalf("device after cancel wrong: %+v", dev)
	}
	mustAuth(t, f.env.svc,
		&DeviceView{ID: dev.ID, CurrentKeyVersion: 2}, rotK, []byte("still source"))

	// 取消后可就当前状态重新发起一张转移（冻结点更新到 v2）。
	tr2, err := f.env.svc.BeginTransfer(BeginTransferRequest{
		DeviceID: dev.ID, SourceTenantID: tenantA, TargetTenantID: tenantB, IdempotencyKey: "after-rot",
	})
	if err != nil {
		t.Fatalf("re-begin after rotation+cancel: %v", err)
	}
	rec2 := f.env.svc.snap.Transfers[tr2.ID]
	if rec2.FrozenKeyVersion != 2 || rec2.FrozenDeviceVersion != 2 {
		t.Fatalf("re-begin frozen snapshot = key %d dev %d, want 2/2",
			rec2.FrozenKeyVersion, rec2.FrozenDeviceVersion)
	}
}

// ---- 取消 ----

func TestTransfer_Cancel(t *testing.T) {
	f := setupTransferableDevice(t, 0)
	tr, rec := beginTransferFor(t, f, tenantB, 0)
	newK := mustKey(t)

	// 只有源租户、且用发起时冻结的当前钥签名才能取消。
	if _, err := f.env.svc.CancelTransfer(tr.ID, tenantB,
		signMessage(f.oldK.priv, TransferCancelMessage(f.dev.ID, tr.ID))); ErrorCodeOf(err) != ErrCodeTenantMismatch {
		t.Fatalf("want tenant mismatch, got %v", err)
	}
	if _, err := f.env.svc.CancelTransfer(tr.ID, tenantA,
		signMessage(newK.priv, TransferCancelMessage(f.dev.ID, tr.ID))); ErrorCodeOf(err) != ErrCodeSignatureInvalid {
		t.Fatalf("want signature invalid, got %v", err)
	}

	view, err := f.env.svc.CancelTransfer(tr.ID, tenantA,
		signMessage(f.oldK.priv, TransferCancelMessage(f.dev.ID, tr.ID)))
	if err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if view.Status != TransferCancelled || view.ResolvedAt == nil ||
		view.SourceDecision != SourceDecisionCancelled {
		t.Fatalf("cancelled view wrong: %+v", view)
	}

	// 取消后凭据立即失效：目标租户不能再接受。
	if _, err := f.env.svc.AcceptTransfer(AcceptTransferRequest{
		TransferID: tr.ID, Credential: tr.Credential, TargetTenantID: tenantB,
		NewPublicKey: newK.pub, Attestation: acceptSig(newK.priv, rec, newK.pub),
	}); ErrorCodeOf(err) != ErrCodeTransferClosed {
		t.Fatalf("want closed after cancel, got %v", err)
	}
	// 重复取消同样被拒。
	if _, err := f.env.svc.CancelTransfer(tr.ID, tenantA,
		signMessage(f.oldK.priv, TransferCancelMessage(f.dev.ID, tr.ID))); ErrorCodeOf(err) != ErrCodeTransferClosed {
		t.Fatalf("want closed on double cancel, got %v", err)
	}
	// 设备归属与密钥不变。
	dev := f.env.svc.snap.Devices[f.dev.ID]
	if dev.TenantID != tenantA || dev.CurrentKeyVersion != 1 ||
		dev.Keys[1].State != KeyStateActive {
		t.Fatalf("device changed after cancel: %+v", dev)
	}
	if _, open := f.env.svc.snap.OpenTransfer[f.dev.ID]; open {
		t.Fatal("cancelled transfer still open")
	}

	// 取消后可以重新发起。
	tr2, _ := beginTransferFor(t, f, tenantB, 0)
	if tr2.ID == tr.ID {
		t.Fatal("new transfer reused cancelled id")
	}
}

// ---- 过期 ----

func TestTransfer_Expiry_LazyAndDeadlineInclusive(t *testing.T) {
	f := setupTransferableDevice(t, 0)
	tr, _ := beginTransferFor(t, f, tenantB, 5*time.Minute)

	// 恰好到达 deadline：窗口仍开放，接受成功。
	f.env.clock.Advance(5 * time.Minute)
	newK := mustKey(t)
	rec := f.env.svc.snap.Transfers[tr.ID]
	view, err := f.env.svc.AcceptTransfer(AcceptTransferRequest{
		TransferID: tr.ID, Credential: tr.Credential, TargetTenantID: tenantB,
		NewPublicKey: newK.pub, Attestation: acceptSig(newK.priv, rec, newK.pub),
	})
	if err != nil {
		t.Fatalf("accept at exact deadline should succeed, got %v", err)
	}
	if view.Status != TransferAccepted {
		t.Fatalf("status = %s", view.Status)
	}

	// 另一张单：越过 deadline 1ns，任何终态操作都先得到 expired。
	f2 := setupTransferableDevice(t, 0)
	tr2, rec2 := beginTransferFor(t, f2, tenantB, 5*time.Minute)
	f2.env.clock.Advance(5*time.Minute + time.Nanosecond)
	targetK := mustKey(t)
	if _, err := f2.env.svc.AcceptTransfer(AcceptTransferRequest{
		TransferID: tr2.ID, Credential: tr2.Credential, TargetTenantID: tenantB,
		NewPublicKey: targetK.pub, Attestation: acceptSig(targetK.priv, rec2, targetK.pub),
	}); ErrorCodeOf(err) != ErrCodeTransferExpired {
		t.Fatalf("want expired, got %v", err)
	}
	if f2.env.svc.snap.Transfers[tr2.ID].Status != TransferExpired {
		t.Fatal("lazy expiry not settled")
	}
	// 已结算后再来的迟到操作得到 closed。
	if _, err := f2.env.svc.CancelTransfer(tr2.ID, tenantA,
		signMessage(f2.oldK.priv, TransferCancelMessage(f2.dev.ID, tr2.ID))); ErrorCodeOf(err) != ErrCodeTransferClosed {
		t.Fatalf("want closed after expiry, got %v", err)
	}

	// 显式 sweep 不重复结算。
	if n, _ := f2.env.svc.SweepExpiredTransfers(); n != 0 {
		t.Fatalf("sweep = %d, want 0", n)
	}
}

func TestTransfer_SweepExpiresOpen(t *testing.T) {
	f := setupTransferableDevice(t, 0)
	tr, _ := beginTransferFor(t, f, tenantB, time.Minute)
	f.env.clock.Advance(time.Minute + time.Nanosecond)

	n, err := f.env.svc.SweepExpiredTransfers()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("swept = %d, want 1", n)
	}
	if f.env.svc.snap.Transfers[tr.ID].Status != TransferExpired {
		t.Fatal("status not expired after sweep")
	}
	if _, open := f.env.svc.snap.OpenTransfer[f.dev.ID]; open {
		t.Fatal("expired transfer still open")
	}
}

// ---- 接受 / 取消 / 过期并发，只有一个终态 ----

func TestTransfer_AcceptCancelExpireRace_OneTerminalState(t *testing.T) {
	for iter := 0; iter < 25; iter++ {
		f := setupTransferableDevice(t, 0)
		tr, rec := beginTransferFor(t, f, tenantB, 10*time.Minute)
		targetK := mustKey(t)
		att := acceptSig(targetK.priv, rec, targetK.pub)
		cancelSig := signMessage(f.oldK.priv, TransferCancelMessage(f.dev.ID, tr.ID))
		acceptReq := AcceptTransferRequest{
			TransferID: tr.ID, Credential: tr.Credential, TargetTenantID: tenantB,
			NewPublicKey: targetK.pub, Attestation: att,
		}

		// 一部分迭代在竞争开始前越过接收窗口。
		if iter%2 == 0 {
			f.env.clock.Advance(10*time.Minute + time.Nanosecond)
		}

		var wg sync.WaitGroup
		start := make(chan struct{})
		run := func(fn func() error) {
			defer wg.Done()
			<-start
			_ = fn()
		}
		wg.Add(4)
		go run(func() error { _, err := f.env.svc.AcceptTransfer(acceptReq); return err })
		go run(func() error {
			// 第二个并发接受者：成功则说明设备被重复接收。
			_, err := f.env.svc.AcceptTransfer(acceptReq)
			return err
		})
		go run(func() error {
			_, err := f.env.svc.CancelTransfer(tr.ID, tenantA, cancelSig)
			return err
		})
		go run(func() error { _, err := f.env.svc.SweepExpiredTransfers(); return err })
		close(start)
		wg.Wait()

		final := f.env.svc.snap.Transfers[tr.ID]
		switch final.Status {
		case TransferAccepted, TransferCancelled, TransferExpired:
		default:
			t.Fatalf("iter %d: unexpected status %q", iter, final.Status)
		}
		if _, open := f.env.svc.snap.OpenTransfer[f.dev.ID]; open {
			t.Fatalf("iter %d: transfer still open", iter)
		}
		dev := f.env.svc.snap.Devices[f.dev.ID]
		switch final.Status {
		case TransferAccepted:
			if dev.TenantID != tenantB || dev.Version != 2 || dev.CurrentKeyVersion != 2 {
				t.Fatalf("iter %d: accepted but device wrong: %+v", iter, dev)
			}
			if dev.Keys[1].State != KeyStateInvalidated || dev.Keys[2].State != KeyStateActive {
				t.Fatalf("iter %d: accepted key states wrong: v1=%s v2=%s",
					iter, dev.Keys[1].State, dev.Keys[2].State)
			}
			if !bytes.Equal(dev.Keys[2].PublicKey, targetK.pub) {
				t.Fatalf("iter %d: accepted key is not target key", iter)
			}
		case TransferCancelled, TransferExpired:
			if dev.TenantID != tenantA || dev.Version != 1 || dev.CurrentKeyVersion != 1 ||
				dev.Keys[1].State != KeyStateActive {
				t.Fatalf("iter %d: %s but device changed: tenant=%s v=%d key=%d v1state=%s",
					iter, final.Status, dev.TenantID, dev.Version, dev.CurrentKeyVersion, dev.Keys[1].State)
			}
		}
	}
}

// ---- 禁用中止活动转移 ----

func TestTransfer_Disable_AbortsOpenTransfer(t *testing.T) {
	f := setupTransferableDevice(t, 0)
	tr, rec := beginTransferFor(t, f, tenantB, 0)

	if _, err := f.env.svc.DisableDevice(f.dev.ID); err != nil {
		t.Fatal(err)
	}
	final := f.env.svc.snap.Transfers[tr.ID]
	if final.Status != TransferAborted || final.ResolvedAt == nil ||
		final.SourceDecision != SourceDecisionAborted {
		t.Fatalf("status = %s", final.Status)
	}
	targetK := mustKey(t)
	if _, err := f.env.svc.AcceptTransfer(AcceptTransferRequest{
		TransferID: tr.ID, Credential: tr.Credential, TargetTenantID: tenantB,
		NewPublicKey: targetK.pub, Attestation: acceptSig(targetK.priv, rec, targetK.pub),
	}); ErrorCodeOf(err) != ErrCodeTransferClosed {
		t.Fatalf("want closed after abort, got %v", err)
	}
}

// ---- 转移号幂等 ----

func TestTransfer_Idempotency_SameKeySameContentReturnsFirst(t *testing.T) {
	f := setupTransferableDevice(t, 0)
	base := BeginTransferRequest{
		DeviceID: f.dev.ID, SourceTenantID: tenantA, TargetTenantID: tenantB, IdempotencyKey: "key-1",
	}
	first, err := f.env.svc.BeginTransfer(base)
	if err != nil {
		t.Fatal(err)
	}
	// 同号同内容重放：返回首次转移单 ID。
	replay, err := f.env.svc.BeginTransfer(base)
	if err != nil {
		t.Fatalf("idempotent replay: %v", err)
	}
	if replay.ID != first.ID {
		t.Fatalf("replay id = %s, want %s", replay.ID, first.ID)
	}
	// 安全取舍：凭据明文只在首次响应中出现，重放不再展示。
	if replay.Credential != "" {
		t.Fatal("credential must not be shown again on idempotent replay")
	}
	if len(f.env.svc.snap.Transfers) != 1 {
		t.Fatal("idempotent replay created a second transfer")
	}

	// 同号异内容（换目标租户）：冲突。
	diff := base
	diff.TargetTenantID = tenantC
	if _, err := f.env.svc.BeginTransfer(diff); ErrorCodeOf(err) != ErrCodeConflict {
		t.Fatalf("want conflict for different target, got %v", err)
	}
	// 同号异内容（换设备）：冲突。
	other := mustKey(t)
	ch := f.env.issue(t, f.external+"-2", tenantA, nil, 0)
	dev2 := mustRegister(t, f.env, ch, f.external+"-2", nil, other)
	diff2 := base
	diff2.DeviceID = dev2.ID
	if _, err := f.env.svc.BeginTransfer(diff2); ErrorCodeOf(err) != ErrCodeConflict {
		t.Fatalf("want conflict for different device, got %v", err)
	}
	// 同一转移号由另一源租户使用互不影响（幂等域为 (源租户, 转移号)）。
	ch3 := f.env.issue(t, f.external+"-3", tenantB, nil, 0)
	dev3 := mustRegister(t, f.env, ch3, f.external+"-3", nil, mustKey(t))
	if _, err := f.env.svc.BeginTransfer(BeginTransferRequest{
		DeviceID: dev3.ID, SourceTenantID: tenantB, TargetTenantID: tenantC, IdempotencyKey: "key-1",
	}); err != nil {
		t.Fatalf("same key under different source tenant should be independent: %v", err)
	}
}

// 转移号的幂等语义在终态之后仍然成立：同号同内容始终返回首次转移单；
// 同号异内容（哪怕首次单早已取消或过期）一律冲突。
func TestTransfer_Idempotency_HoldsAcrossTerminalStates(t *testing.T) {
	// 取消后：重放返回首单，换内容冲突；需要新转移必须换新转移号。
	f := setupTransferableDevice(t, 0)
	req := BeginTransferRequest{
		DeviceID: f.dev.ID, SourceTenantID: tenantA, TargetTenantID: tenantB, IdempotencyKey: "idem-cancel",
	}
	first, err := f.env.svc.BeginTransfer(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.env.svc.CancelTransfer(first.ID, tenantA,
		signMessage(f.oldK.priv, TransferCancelMessage(f.dev.ID, first.ID))); err != nil {
		t.Fatal(err)
	}
	replay, err := f.env.svc.BeginTransfer(req)
	if err != nil {
		t.Fatalf("replay after cancel: %v", err)
	}
	if replay.ID != first.ID || replay.Credential != "" {
		t.Fatalf("replay = %+v, want first id without credential", replay)
	}
	diff := req
	diff.TargetTenantID = tenantC
	if _, err := f.env.svc.BeginTransfer(diff); ErrorCodeOf(err) != ErrCodeConflict {
		t.Fatalf("different content with same key after cancel: want conflict, got %v", err)
	}
	next := req
	next.IdempotencyKey = "idem-cancel-2"
	next2, err := f.env.svc.BeginTransfer(next)
	if err != nil {
		t.Fatalf("fresh key after cancel should open a new transfer: %v", err)
	}
	if next2.ID == first.ID {
		t.Fatal("new transfer reused cancelled id")
	}

	// 过期后：同样的幂等语义。
	f2 := setupTransferableDevice(t, time.Minute)
	req2 := BeginTransferRequest{
		DeviceID: f2.dev.ID, SourceTenantID: tenantA, TargetTenantID: tenantB, IdempotencyKey: "idem-expire",
	}
	exp, err := f2.env.svc.BeginTransfer(req2)
	if err != nil {
		t.Fatal(err)
	}
	f2.env.clock.Advance(time.Minute + time.Nanosecond)
	if n, _ := f2.env.svc.SweepExpiredTransfers(); n != 1 {
		t.Fatalf("sweep = %d, want 1", n)
	}
	replay2, err := f2.env.svc.BeginTransfer(req2)
	if err != nil {
		t.Fatalf("replay after expiry: %v", err)
	}
	if replay2.ID != exp.ID {
		t.Fatalf("replay id = %s, want %s", replay2.ID, exp.ID)
	}

	// 接受后：原属主不再拥有设备，同号同内容重放仍先命中幂等记录返回首单，
	// 不会再产生第二张单；同号异内容同样冲突。
	f3 := setupTransferableDevice(t, 0)
	req3 := BeginTransferRequest{
		DeviceID: f3.dev.ID, SourceTenantID: tenantA, TargetTenantID: tenantB, IdempotencyKey: "idem-accept",
	}
	acc, err := f3.env.svc.BeginTransfer(req3)
	if err != nil {
		t.Fatal(err)
	}
	keyB := mustKey(t)
	acceptOK(t, f3, acc, tenantB, keyB)
	replay3, err := f3.env.svc.BeginTransfer(req3)
	if err != nil {
		t.Fatalf("replay after accept: %v", err)
	}
	if replay3.ID != acc.ID || replay3.Credential != "" {
		t.Fatalf("replay = %+v, want first id without credential", replay3)
	}
	if len(f3.env.svc.snap.Transfers) != 1 {
		t.Fatal("replay after accept created another transfer")
	}
	diff3 := req3
	diff3.TargetTenantID = tenantC
	if _, err := f3.env.svc.BeginTransfer(diff3); ErrorCodeOf(err) != ErrCodeConflict {
		t.Fatalf("different content with same key after accept: want conflict, got %v", err)
	}
}

// ---- 归属链与多跳转移 ----

// 并发使用同一 (源租户, 转移号) 发起：只能建立一张转移单，全部调用返回同一 ID。
func TestTransfer_Idempotency_ConcurrentSameKey(t *testing.T) {
	f := setupTransferableDevice(t, 0)
	req := BeginTransferRequest{
		DeviceID: f.dev.ID, SourceTenantID: tenantA, TargetTenantID: tenantB, IdempotencyKey: "idem-race",
	}

	const n = 32
	results := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			tr, err := f.env.svc.BeginTransfer(req)
			if err == nil {
				results[i] = tr.ID
			}
			errs[i] = err
		}(i)
	}
	close(start)
	wg.Wait()

	var first string
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("concurrent begin %d: %v", i, errs[i])
		}
		if results[i] == "" {
			t.Fatalf("concurrent begin %d returned empty id", i)
		}
		if first == "" {
			first = results[i]
		} else if results[i] != first {
			t.Fatalf("concurrent begin %d id = %q, want %q", i, results[i], first)
		}
	}
	if len(f.env.svc.snap.Transfers) != 1 {
		t.Fatalf("transfers = %d, want exactly 1", len(f.env.svc.snap.Transfers))
	}
	if f.env.svc.snap.OpenTransfer[f.dev.ID] != first {
		t.Fatal("open transfer index does not point to the unique record")
	}
}

func TestTransfer_OwnershipChain_MultipleHops(t *testing.T) {
	f := setupTransferableDevice(t, 0)

	// tenant-a -> tenant-b（v1 -> v2）。
	tr1, _ := beginTransferFor(t, f, tenantB, 0)
	keyB := mustKey(t)
	acceptOK(t, f, tr1, tenantB, keyB)
	dev2, _ := f.env.svc.GetDevice(f.dev.ID)

	// tenant-b -> tenant-c（v2 -> v3）。
	cr, err := f.env.svc.BeginTransfer(BeginTransferRequest{
		DeviceID: dev2.ID, SourceTenantID: tenantB, TargetTenantID: tenantC,
		IdempotencyKey: "hop-2",
	})
	if err != nil {
		t.Fatal(err)
	}
	// 旧租户（a）不能替新租户发起取消。
	if _, err := f.env.svc.CancelTransfer(cr.ID, tenantA,
		signMessage(f.oldK.priv, TransferCancelMessage(dev2.ID, cr.ID))); ErrorCodeOf(err) != ErrCodeTenantMismatch {
		t.Fatalf("want tenant mismatch, got %v", err)
	}
	keyC := mustKey(t)
	acceptOK(t, f, cr, tenantC, keyC)

	chain, err := f.env.svc.GetOwnershipChain(f.dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain.History) != 3 {
		t.Fatalf("history len = %d, want 3", len(chain.History))
	}
	wantSeq := []struct {
		tenant      string
		fromV, toV  int
		hasTransfer bool
	}{
		{tenantA, 0, 1, false},
		{tenantB, 1, 2, true},
		{tenantC, 2, 3, true},
	}
	for i, w := range wantSeq {
		got := chain.History[i]
		if got.Seq != i+1 || got.TenantID != w.tenant || got.FromVersion != w.fromV || got.ToVersion != w.toV ||
			(got.TransferID != "") != w.hasTransfer {
			t.Fatalf("event %d = %+v, want %+v", i, got, w)
		}
	}
	if chain.Current.TenantID != tenantC || chain.Current.ToVersion != 3 {
		t.Fatalf("current = %+v", chain.Current)
	}
	if len(chain.Transfers) != 2 {
		t.Fatalf("transfers = %d, want 2", len(chain.Transfers))
	}
	for _, tv := range chain.Transfers {
		if tv.Status != TransferAccepted {
			t.Fatalf("chain transfer status = %s", tv.Status)
		}
	}

	// 前两任租户的密钥都已失效，只有最新钥可认证。
	dev3, _ := f.env.svc.GetDevice(f.dev.ID)
	if dev3.TenantID != tenantC || dev3.CurrentKeyVersion != 3 {
		t.Fatalf("final device: %+v", dev3)
	}
	for v, k := range map[int]deviceKey{1: f.oldK, 2: keyB} {
		if err := f.env.svc.Authenticate(AuthRequest{
			DeviceID: dev3.ID, KeyVersion: v, Message: []byte("old"),
			Signature: signMessage(k.priv, []byte("old")),
		}); ErrorCodeOf(err) != ErrCodeKeyVersionInvalid {
			t.Fatalf("key v%d auth: want key version invalid, got %v", v, err)
		}
	}
	mustAuth(t, f.env.svc, dev3, keyC, []byte("tenant c"))

	if _, err := f.env.svc.GetOwnershipChain("ghost"); ErrorCodeOf(err) != ErrCodeDeviceNotFound {
		t.Fatalf("want not found, got %v", err)
	}
}

// 归属链除 accepted 多跳外，还应逐单展示取消/过期等非接受终态的两端决定与
// 冻结/未变化的密钥版本；非接受转移不得产生新的归属站。
func TestTransfer_OwnershipChain_RecordsCancelledAndExpiredDecisions(t *testing.T) {
	f := setupTransferableDevice(t, 0)

	// 第一张：取消。
	cancelled, _ := beginTransferFor(t, f, tenantB, 0)
	if _, err := f.env.svc.CancelTransfer(cancelled.ID, tenantA,
		signMessage(f.oldK.priv, TransferCancelMessage(f.dev.ID, cancelled.ID))); err != nil {
		t.Fatal(err)
	}

	// 第二张：过期。
	expired, _ := beginTransferFor(t, f, tenantB, time.Minute)
	f.env.clock.Advance(time.Minute + time.Nanosecond)
	if n, err := f.env.svc.SweepExpiredTransfers(); err != nil || n != 1 {
		t.Fatalf("sweep = (%d, %v), want 1", n, err)
	}

	// 第三张：接受（v1 -> v2）。
	accepted, _ := beginTransferFor(t, f, tenantB, 0)
	keyB := mustKey(t)
	acceptOK(t, f, accepted, tenantB, keyB)

	chain, err := f.env.svc.GetOwnershipChain(f.dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	// 取消与过期没有改变归属，归属站仍只有注册 + 接受两站。
	if len(chain.History) != 2 {
		t.Fatalf("history len = %d, want 2", len(chain.History))
	}
	if chain.Current.TenantID != tenantB || chain.Current.FromVersion != 1 || chain.Current.ToVersion != 2 {
		t.Fatalf("current = %+v", chain.Current)
	}
	if len(chain.Transfers) != 3 {
		t.Fatalf("transfers = %d, want 3", len(chain.Transfers))
	}

	byID := map[string]TransferView{}
	for _, tv := range chain.Transfers {
		byID[tv.ID] = tv
	}
	cv := byID[cancelled.ID]
	if cv.Status != TransferCancelled || cv.SourceDecision != SourceDecisionCancelled ||
		cv.TargetDecision != TargetDecisionNone || cv.NewKeyVersion != 0 ||
		cv.FrozenKeyVersion != 1 || cv.FrozenDeviceVersion != 1 {
		t.Fatalf("cancelled view wrong: %+v", cv)
	}
	ev := byID[expired.ID]
	if ev.Status != TransferExpired || ev.SourceDecision != SourceDecisionRequested ||
		ev.TargetDecision != TargetDecisionNone || ev.NewKeyVersion != 0 {
		t.Fatalf("expired view wrong: %+v", ev)
	}
	av := byID[accepted.ID]
	if av.Status != TransferAccepted || av.SourceDecision != SourceDecisionRequested ||
		av.TargetDecision != TargetDecisionAccepted || av.NewKeyVersion != 2 {
		t.Fatalf("accepted view wrong: %+v", av)
	}

	// 单查接口与链上视图一致，且同样不暴露敏感材料。
	got, err := f.env.svc.GetTransfer(cancelled.ID)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(got)
	for _, banned := range []string{"credential", "salt", "digest", "attestation", "public_key"} {
		if bytes.Contains(bytes.ToLower(raw), []byte(banned)) {
			t.Fatalf("GetTransfer leaked %q: %s", banned, raw)
		}
	}
}

func TestTransfer_Views_NeverExposeSensitiveMaterial(t *testing.T) {
	f := setupTransferableDevice(t, 0)
	tr, _ := beginTransferFor(t, f, tenantB, 0)
	newK := mustKey(t)
	view := acceptOK(t, f, tr, tenantB, newK)

	raw, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"credential", "salt", "digest", "attestation", "public_key"} {
		if bytes.Contains(bytes.ToLower(raw), []byte(banned)) {
			t.Fatalf("transfer view JSON contains banned field %q: %s", banned, raw)
		}
	}
	chain, err := f.env.svc.GetOwnershipChain(f.dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	craw, err := json.Marshal(chain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(craw, []byte(tr.Credential)) {
		t.Fatal("ownership chain leaked credential")
	}
	if bytes.Contains(bytes.ToLower(craw), []byte("attestation")) {
		t.Fatal("ownership chain leaked attestation")
	}
}

// ---- 持久化 ----

func TestTransfer_PersistenceRoundtrip(t *testing.T) {
	// 复用主测试文件中的文件存储往返模式。
	path := t.TempDir() + "/state.json"
	clock := NewFixedClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	svc, err := New(Config{Store: NewFileStore(path), Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	oldK := mustKey(t)
	ch, err := svc.IssueChallenge("dev-persist", tenantA, []byte("attr"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dev, err := svc.Register(RegisterRequest{
		ChallengeID: ch.ID, Secret: ch.Secret, ExternalID: "dev-persist",
		Attributes: []byte("attr"), PublicKey: oldK.pub,
		Attestation: signAttestation(oldK.priv, ch.ID, "dev-persist", []byte("attr")),
	})
	if err != nil {
		t.Fatal(err)
	}
	tr, err := svc.BeginTransfer(BeginTransferRequest{
		DeviceID: dev.ID, SourceTenantID: tenantA, TargetTenantID: tenantB, IdempotencyKey: "persist-1",
	})
	if err != nil {
		t.Fatal(err)
	}

	// 重载后活动转移完整恢复并可被接受。
	svc2, err := New(Config{Store: NewFileStore(path), Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	newK := mustKey(t)
	rec2 := svc2.snap.Transfers[tr.ID]
	view, err := svc2.AcceptTransfer(AcceptTransferRequest{
		TransferID: tr.ID, Credential: tr.Credential, TargetTenantID: tenantB,
		NewPublicKey: newK.pub, Attestation: acceptSig(newK.priv, rec2, newK.pub),
	})
	if err != nil {
		t.Fatalf("accept after reload: %v", err)
	}
	if view.Status != TransferAccepted {
		t.Fatalf("status = %s", view.Status)
	}

	// 再次加载：归属、版本与归属链都保留。
	svc3, err := New(Config{Store: NewFileStore(path), Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	got, err := svc3.GetDevice(dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.TenantID != tenantB || got.Version != 2 || got.CurrentKeyVersion != 2 {
		t.Fatalf("reloaded device wrong: %+v", got)
	}
	if err := svc3.Authenticate(AuthRequest{DeviceID: dev.ID, KeyVersion: 2,
		Message: []byte("after-restart"), Signature: signMessage(newK.priv, []byte("after-restart"))}); err != nil {
		t.Fatalf("new tenant auth after restart: %v", err)
	}
	chain, err := svc3.GetOwnershipChain(dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain.History) != 2 || chain.Current.TenantID != tenantB {
		t.Fatalf("reloaded ownership chain wrong: %+v", chain)
	}

	// 同号重放在重载后仍然幂等：同内容返回同一 ID。
	same, err := svc3.BeginTransfer(BeginTransferRequest{
		DeviceID: dev.ID, SourceTenantID: tenantA, TargetTenantID: tenantB, IdempotencyKey: "persist-1",
	})
	if err != nil {
		t.Fatalf("idempotent replay after reload: %v", err)
	}
	if same.ID != tr.ID {
		t.Fatalf("replay id = %s, want %s", same.ID, tr.ID)
	}
	// 旧租户用新转移号发起则因不再拥有设备而被拒。
	if _, err := svc3.BeginTransfer(BeginTransferRequest{
		DeviceID: dev.ID, SourceTenantID: tenantA, TargetTenantID: tenantC, IdempotencyKey: "persist-2",
	}); ErrorCodeOf(err) != ErrCodeTenantMismatch {
		t.Fatalf("old tenant begin after transfer: want tenant mismatch, got %v", err)
	}
}

// ---- HTTP 端到端 ----

func TestHTTPHandler_TransferEndToEnd(t *testing.T) {
	env := newTestEnv(t, time.Minute, 10*time.Minute)
	h := NewHandler(env.svc)
	srv := httptest.NewServer(h)
	defer srv.Close()

	oldK := mustKey(t)
	var ch Challenge
	doJSON(t, http.MethodPost, srv.URL+"/admin/challenges", http.StatusCreated, map[string]string{
		"external_id": "dev-http-transfer",
		"tenant_id":   tenantA,
		"attributes":  EncodeBase64([]byte("attr")),
	}, &ch)
	var dev DeviceView
	doJSON(t, http.MethodPost, srv.URL+"/devices/register", http.StatusOK, map[string]string{
		"challenge_id": ch.ID,
		"secret":       ch.Secret,
		"external_id":  "dev-http-transfer",
		"attributes":   EncodeBase64([]byte("attr")),
		"public_key":   EncodeBase64(oldK.pub),
		"attestation":  EncodeBase64(signAttestation(oldK.priv, ch.ID, "dev-http-transfer", []byte("attr"))),
	}, &dev)

	// 发起转移。
	var tr Transfer
	doJSON(t, http.MethodPost, srv.URL+"/devices/"+dev.ID+"/transfers", http.StatusCreated, map[string]string{
		"source_tenant_id": tenantA,
		"target_tenant_id": tenantB,
		"idempotency_key":  "http-1",
	}, &tr)
	if tr.ID == "" || tr.Credential == "" {
		t.Fatal("transfer response missing id/credential")
	}

	// 非所有者发起 -> 403（源租户必须是当前归属租户）。
	doJSON(t, http.MethodPost, srv.URL+"/devices/"+dev.ID+"/transfers", http.StatusForbidden, map[string]string{
		"source_tenant_id": tenantC,
		"target_tenant_id": tenantB,
		"idempotency_key":  "http-1-not-owner",
	}, nil)

	// 转移未终态前源租户重复发起另一张单 -> 409。
	doJSON(t, http.MethodPost, srv.URL+"/devices/"+dev.ID+"/transfers", http.StatusConflict, map[string]string{
		"source_tenant_id": tenantA,
		"target_tenant_id": tenantC,
		"idempotency_key":  "http-1-another",
	}, nil)

	// 同号同内容重放 -> 201 且返回首次转移单。
	var replay Transfer
	doJSON(t, http.MethodPost, srv.URL+"/devices/"+dev.ID+"/transfers", http.StatusCreated, map[string]string{
		"source_tenant_id": tenantA,
		"target_tenant_id": tenantB,
		"idempotency_key":  "http-1",
	}, &replay)
	if replay.ID != tr.ID {
		t.Fatalf("idempotent replay returned %s, want %s", replay.ID, tr.ID)
	}
	// 同号异内容 -> 409。
	doJSON(t, http.MethodPost, srv.URL+"/devices/"+dev.ID+"/transfers", http.StatusConflict, map[string]string{
		"source_tenant_id": tenantA,
		"target_tenant_id": tenantC,
		"idempotency_key":  "http-1",
	}, nil)

	// 查询转移单（视图无敏感字段）。
	var tv TransferView
	doJSON(t, http.MethodGet, srv.URL+"/transfers/"+tr.ID, http.StatusOK, struct{}{}, &tv)
	if tv.Status != TransferPending || tv.SourceTenantID != tenantA {
		t.Fatalf("transfer view wrong: %+v", tv)
	}

	// 错误凭据 -> 401。
	newK := mustKey(t)
	rec := env.svc.snap.Transfers[tr.ID]
	doJSON(t, http.MethodPost, srv.URL+"/transfers/"+tr.ID+"/accept", http.StatusUnauthorized, map[string]string{
		"credential":       "wrong",
		"target_tenant_id": tenantB,
		"new_public_key":   EncodeBase64(newK.pub),
		"attestation":      EncodeBase64(acceptSig(newK.priv, rec, newK.pub)),
	}, nil)

	// 正确接受 -> 200。
	doJSON(t, http.MethodPost, srv.URL+"/transfers/"+tr.ID+"/accept", http.StatusOK, map[string]string{
		"credential":       tr.Credential,
		"target_tenant_id": tenantB,
		"new_public_key":   EncodeBase64(newK.pub),
		"attestation":      EncodeBase64(acceptSig(newK.priv, rec, newK.pub)),
	}, &tv)
	if tv.Status != TransferAccepted || tv.NewKeyVersion != 2 {
		t.Fatalf("accepted view wrong: %+v", tv)
	}

	// 重复接受 -> 409。
	doJSON(t, http.MethodPost, srv.URL+"/transfers/"+tr.ID+"/accept", http.StatusConflict, map[string]string{
		"credential":       tr.Credential,
		"target_tenant_id": tenantB,
		"new_public_key":   EncodeBase64(newK.pub),
		"attestation":      EncodeBase64(acceptSig(newK.priv, rec, newK.pub)),
	}, nil)

	// 旧租户密钥认证 -> 409 key_version_invalid。
	doJSON(t, http.MethodPost, srv.URL+"/devices/"+dev.ID+"/authenticate", http.StatusConflict, map[string]any{
		"key_version": 1,
		"message":     EncodeBase64([]byte("late")),
		"signature":   EncodeBase64(signMessage(oldK.priv, []byte("late"))),
	}, nil)

	// 归属链查询。
	var chain OwnershipChainView
	doJSON(t, http.MethodGet, srv.URL+"/devices/"+dev.ID+"/ownership", http.StatusOK, struct{}{}, &chain)
	if len(chain.History) != 2 || chain.Current.TenantID != tenantB || len(chain.Transfers) != 1 {
		t.Fatalf("chain wrong: %+v", chain)
	}

	// 转移取消端点：第二跳由 tenant-b 发起再取消。
	var tr2 Transfer
	doJSON(t, http.MethodPost, srv.URL+"/devices/"+dev.ID+"/transfers", http.StatusCreated, map[string]string{
		"source_tenant_id": tenantB,
		"target_tenant_id": tenantC,
		"idempotency_key":  "http-2",
	}, &tr2)
	doJSON(t, http.MethodPost, srv.URL+"/transfers/"+tr2.ID+"/cancel", http.StatusOK, map[string]string{
		"source_tenant_id": tenantB,
		"signature":        EncodeBase64(signMessage(newK.priv, TransferCancelMessage(dev.ID, tr2.ID))),
	}, &tv)
	if tv.Status != TransferCancelled {
		t.Fatalf("cancel status = %s", tv.Status)
	}

	// 过期结算：410。
	var tr3 Transfer
	doJSON(t, http.MethodPost, srv.URL+"/devices/"+dev.ID+"/transfers", http.StatusCreated, map[string]any{
		"source_tenant_id": tenantB,
		"target_tenant_id": tenantC,
		"idempotency_key":  "http-3",
		"ttl":              "1m",
	}, &tr3)
	env.clock.Advance(time.Minute + time.Nanosecond)
	doJSON(t, http.MethodPost, srv.URL+"/transfers/"+tr3.ID+"/accept", http.StatusGone, map[string]string{
		"credential":       tr3.Credential,
		"target_tenant_id": tenantC,
		"new_public_key":   EncodeBase64(mustKey(t).pub),
		"attestation":      EncodeBase64(make([]byte, 64)),
	}, nil)
}

// ---- 测试辅助 ----

func mustMarshalSnapshot(t *testing.T, snap *snapshot) []byte {
	t.Helper()
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
