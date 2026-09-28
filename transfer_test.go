package deviceenrollment

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"
)

const (
	tenantB = "tenant-b"
	tenantC = "tenant-c"
)

// registeredDevice 在指定租户下注册一台设备并返回其视图与初始密钥。
func registeredDevice(t *testing.T, env *testEnv, tenant, external string, k deviceKey) *DeviceView {
	t.Helper()
	ch, err := env.svc.IssueChallenge(tenant, external, []byte("attr"), 0)
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	dev, err := env.svc.Register(RegisterRequest{
		ChallengeID: ch.ID,
		Secret:      ch.Secret,
		ExternalID:  external,
		Attributes:  []byte("attr"),
		PublicKey:   k.pub,
		Attestation: signAttestation(k.priv, ch.ID, external, []byte("attr")),
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	return dev
}

type startedTransfer struct {
	view       *TransferView
	credential string
}

func beginTransfer(t *testing.T, env *testEnv, requestID string, dev *DeviceView, source, target string) startedTransfer {
	t.Helper()
	view, secret, err := env.svc.BeginTransfer(requestID, dev.ID, source, target, 0)
	if err != nil {
		t.Fatalf("BeginTransfer: %v", err)
	}
	return startedTransfer{view: view, credential: secret}
}

func acceptTransfer(t *testing.T, env *testEnv, tr startedTransfer, dev *DeviceView, target string, newK deviceKey) (*TransferView, error) {
	t.Helper()
	att := signMessage(newK.priv,
		TransferAcceptMessage(tr.view.ID, dev.ID, target, tr.view.FrozenVersion, newK.pub))
	return env.svc.AcceptTransfer(AcceptTransferRequest{
		TransferID:   tr.view.ID,
		Credential:   tr.credential,
		TargetTenant: target,
		NewPublicKey: newK.pub,
		Attestation:  att,
	})
}

func mustAccept(t *testing.T, env *testEnv, tr startedTransfer, dev *DeviceView, target string, newK deviceKey) *TransferView {
	t.Helper()
	view, err := acceptTransfer(t, env, tr, dev, target, newK)
	if err != nil {
		t.Fatalf("AcceptTransfer: %v", err)
	}
	return view
}

// ---- 发起转移 ----

func TestBeginTransfer_FreezesStateAndStoresDigestOnly(t *testing.T) {
	env := newTestEnv(t, time.Minute, 10*time.Minute)
	oldK := mustKey(t)
	dev := registeredDevice(t, env, testTenant, "dev-1", oldK)

	tr := beginTransfer(t, env, "req-1", dev, testTenant, tenantB)
	if tr.credential == "" {
		t.Fatal("one-time credential not returned")
	}
	if tr.view.Status != TransferPending || tr.view.FrozenVersion != 1 ||
		tr.view.SourceTenant != testTenant || tr.view.TargetTenant != tenantB {
		t.Fatalf("unexpected transfer view: %+v", tr.view)
	}

	rec := env.svc.snap.Transfers[tr.view.ID]
	if rec == nil {
		t.Fatal("transfer not persisted")
	}
	// 持久化只允许保存凭据摘要：盐与摘要存在，明文不得出现，且摘要不等于明文。
	if len(rec.CredentialSalt) == 0 || len(rec.CredentialDigest) == 0 {
		t.Fatal("credential salt/digest missing")
	}
	if bytes.Equal(rec.CredentialDigest, []byte(tr.credential)) {
		t.Fatal("credential digest equals plaintext credential")
	}
	if bytes.Contains(rec.CredentialDigest, []byte(tr.credential)) {
		t.Fatal("plaintext credential leaked into digest")
	}
	// 快照文件（若落盘）同样不含明文；这里直接序列化内存快照验证。
	raw, _ := json.Marshal(env.svc.snap)
	if bytes.Contains(raw, []byte(tr.credential)) {
		t.Fatal("plaintext credential present in serialized snapshot")
	}
	// 视图不得携带凭据/盐/摘要。
	vraw, _ := json.Marshal(tr.view)
	if bytes.Contains(vraw, []byte(tr.credential)) || bytes.Contains(vraw, []byte("credential")) {
		t.Fatalf("transfer view leaks credential material: %s", vraw)
	}
}

func TestBeginTransfer_Guards(t *testing.T) {
	env := newTestEnv(t, time.Minute, 10*time.Minute)
	oldK := mustKey(t)
	dev := registeredDevice(t, env, testTenant, "dev-1", oldK)

	// 源/目标租户不得相同。
	if _, _, err := env.svc.BeginTransfer("r0", dev.ID, testTenant, testTenant, 0); ErrorCodeOf(err) != ErrCodeInvalidArgument {
		t.Fatalf("want invalid argument for same tenant, got %v", err)
	}
	// 非当前归属租户不能发起。
	if _, _, err := env.svc.BeginTransfer("r1", dev.ID, tenantB, tenantC, 0); ErrorCodeOf(err) != ErrCodeTransferTenantMismatch {
		t.Fatalf("want tenant mismatch, got %v", err)
	}
	// 不存在的设备。
	if _, _, err := env.svc.BeginTransfer("r2", "ghost", testTenant, tenantB, 0); ErrorCodeOf(err) != ErrCodeDeviceNotFound {
		t.Fatalf("want device not found, got %v", err)
	}

	// 存在未完成轮换时不得发起。
	newK := mustKey(t)
	rot := beginRotation(t, env, dev, oldK, newK)
	if _, _, err := env.svc.BeginTransfer("r3", dev.ID, testTenant, tenantB, 0); ErrorCodeOf(err) != ErrCodeRotationInProgress {
		t.Fatalf("want rotation in progress, got %v", err)
	}
	// 轮换结束（取消）后允许发起。
	if _, err := env.svc.CancelRotation(rot.ID, signMessage(oldK.priv, cancelMsg(rot))); err != nil {
		t.Fatalf("cancel rotation: %v", err)
	}
	tr := beginTransfer(t, env, "r4", dev, testTenant, tenantB)

	// 已有活动转移时不得再次发起。
	if _, _, err := env.svc.BeginTransfer("r5", dev.ID, testTenant, tenantC, 0); ErrorCodeOf(err) != ErrCodeTransferInProgress {
		t.Fatalf("want transfer in progress, got %v", err)
	}
	// 活动转移期间也不得发起轮换。
	k3 := mustKey(t)
	_, err := env.svc.BeginRotation(dev.ID, k3.pub, signMessage(oldK.priv, RotationBeginMessage(dev.ID, k3.pub)))
	if ErrorCodeOf(err) != ErrCodeTransferInProgress {
		t.Fatalf("want transfer in progress on rotation, got %v", err)
	}

	// 禁用设备上不得再发起；禁用还把活动转移原子中止。
	if _, err := env.svc.DisableDevice(dev.ID); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if env.svc.snap.Transfers[tr.view.ID].Status != TransferAborted {
		t.Fatal("active transfer not aborted on disable")
	}
	if _, _, err := env.svc.BeginTransfer("r6", dev.ID, testTenant, tenantB, 0); ErrorCodeOf(err) != ErrCodeDeviceDisabled {
		t.Fatalf("want device disabled, got %v", err)
	}
}

func TestBeginTransfer_Idempotency(t *testing.T) {
	env := newTestEnv(t, time.Minute, 10*time.Minute)
	oldK := mustKey(t)
	dev := registeredDevice(t, env, testTenant, "dev-1", oldK)

	first := beginTransfer(t, env, "idem-1", dev, testTenant, tenantB)
	if first.credential == "" {
		t.Fatal("first call must return credential")
	}
	// 同号同内容：返回首次转移单，且不再回吐凭据明文。
	replay, secret, err := env.svc.BeginTransfer("idem-1", dev.ID, testTenant, tenantB, 0)
	if err != nil {
		t.Fatalf("idempotent replay: %v", err)
	}
	if replay.ID != first.view.ID {
		t.Fatalf("replay created different transfer: %s != %s", replay.ID, first.view.ID)
	}
	if secret != "" {
		t.Fatal("credential plaintext must not be returned on replay")
	}
	// 同号异内容（换目标租户）冲突。
	if _, _, err := env.svc.BeginTransfer("idem-1", dev.ID, testTenant, tenantC, 0); ErrorCodeOf(err) != ErrCodeConflict {
		t.Fatalf("want conflict for same id different content, got %v", err)
	}
	// 同号异内容（换源租户）同样冲突。
	if _, _, err := env.svc.BeginTransfer("idem-1", dev.ID, tenantB, tenantC, 0); ErrorCodeOf(err) != ErrCodeConflict {
		t.Fatalf("want conflict for different source, got %v", err)
	}
}

// ---- 接收：原子归属切换 ----

func TestAcceptTransfer_HappyPath_AtomicSwitch(t *testing.T) {
	env := newTestEnv(t, time.Minute, 10*time.Minute)
	oldK := mustKey(t)
	dev := registeredDevice(t, env, testTenant, "dev-1", oldK)
	tr := beginTransfer(t, env, "req-1", dev, testTenant, tenantB)
	newK := mustKey(t)

	view := mustAccept(t, env, tr, dev, tenantB, newK)
	if view.Status != TransferAccepted || view.CompletedAt == nil {
		t.Fatalf("transfer not accepted: %+v", view)
	}

	d := env.svc.snap.Devices[dev.ID]
	// 归属与新密钥版本必须同时切换。
	if d.TenantID != tenantB {
		t.Fatalf("tenant = %q, want %q", d.TenantID, tenantB)
	}
	if d.CurrentKeyVersion != 2 {
		t.Fatalf("current version = %d, want 2", d.CurrentKeyVersion)
	}
	if d.Keys[2].State != KeyStateActive || !bytes.Equal(d.Keys[2].PublicKey, newK.pub) {
		t.Fatal("new key not active with correct public key")
	}
	// 源租户的全部密钥立即失效。
	for v, key := range d.Keys {
		if v == 2 {
			continue
		}
		if key.State != KeyStateInvalidated {
			t.Fatalf("source key v%d state = %s, want invalidated", v, key.State)
		}
	}

	updated, _ := env.svc.GetDevice(dev.ID)
	// 新租户用新密钥认证成功。
	mustAuth(t, env.svc, updated, newK, []byte("hello from B"))
	// 源租户的迟到认证被拒：资格已随转移失效，不能覆盖新归属。
	err := env.svc.Authenticate(AuthRequest{
		DeviceID: dev.ID, TenantID: testTenant, KeyVersion: 1,
		Message: []byte("late from A"), Signature: signMessage(oldK.priv, []byte("late from A")),
	})
	if ErrorCodeOf(err) != ErrCodeTransferTenantMismatch {
		t.Fatalf("want tenant mismatch for stale source auth, got %v", err)
	}
	// 即便伪造目标租户、使用旧版本密钥也因版本失效被拒。
	err = env.svc.Authenticate(AuthRequest{
		DeviceID: dev.ID, TenantID: tenantB, KeyVersion: 1,
		Message: []byte("x"), Signature: signMessage(oldK.priv, []byte("x")),
	})
	if ErrorCodeOf(err) != ErrCodeKeyVersionInvalid {
		t.Fatalf("want key version invalid, got %v", err)
	}

	// 归属链更新：旧环结束、新环属于 B 且关联转移单、版本为 2。
	if len(d.Ownership) != 2 {
		t.Fatalf("ownership links = %d, want 2", len(d.Ownership))
	}
	if d.Ownership[0].TenantID != testTenant || d.Ownership[0].EndedAt == nil {
		t.Fatalf("first link not closed: %+v", d.Ownership[0])
	}
	last := d.Ownership[1]
	if last.TenantID != tenantB || last.TransferID != tr.view.ID || last.KeyVersion != 2 || last.EndedAt != nil {
		t.Fatalf("new ownership link wrong: %+v", last)
	}
}

func TestAcceptTransfer_FailuresLeaveNoPartialState(t *testing.T) {
	env := newTestEnv(t, time.Minute, 10*time.Minute)

	setup := func(t *testing.T) (deviceKey, deviceKey, *DeviceView, startedTransfer) {
		oldK := mustKey(t)
		dev := registeredDevice(t, env, testTenant, "dev-"+randomID(), oldK)
		tr := beginTransfer(t, env, "req-"+randomID(), dev, testTenant, tenantB)
		return oldK, mustKey(t), dev, tr
	}

	// 凭据错误。
	_, newK, dev, tr := setup(t)
	bad := tr
	bad.credential = "wrong-credential"
	if _, err := acceptTransfer(t, env, bad, dev, tenantB, newK); ErrorCodeOf(err) != ErrCodeCredentialMismatch {
		t.Fatalf("want credential mismatch, got %v", err)
	}

	// 目标租户不匹配。
	_, newK, dev, tr = setup(t)
	if _, err := acceptTransfer(t, env, tr, dev, tenantC, newK); ErrorCodeOf(err) != ErrCodeTransferTenantMismatch {
		t.Fatalf("want tenant mismatch, got %v", err)
	}

	// 证明非法（全零签名）。
	_, newK, dev, tr = setup(t)
	_, err := env.svc.AcceptTransfer(AcceptTransferRequest{
		TransferID: tr.view.ID, Credential: tr.credential, TargetTenant: tenantB,
		NewPublicKey: newK.pub, Attestation: make([]byte, 64),
	})
	if ErrorCodeOf(err) != ErrCodeAttestationFailed {
		t.Fatalf("want attestation failed, got %v", err)
	}

	// 设备密钥版本与冻结版本不一致。
	_, newK, dev, tr = setup(t)
	env.svc.snap.Devices[dev.ID].CurrentKeyVersion = 42
	if _, err := acceptTransfer(t, env, tr, dev, tenantB, newK); ErrorCodeOf(err) != ErrCodeTransferVersionMismatch {
		t.Fatalf("want version mismatch, got %v", err)
	}

	// 任一失败后：归属未变、旧钥仍有效、转移仍 pending（凭据未被消费）。
	d := env.svc.snap.Devices[dev.ID]
	if d.TenantID != testTenant || d.CurrentKeyVersion != 42 {
		t.Fatalf("failed accept mutated device: tenant=%s version=%d", d.TenantID, d.CurrentKeyVersion)
	}
	if env.svc.snap.Transfers[tr.view.ID].Status != TransferPending {
		t.Fatal("failed accept must not close the transfer")
	}
	// 把版本改回后仍可用原凭据成功接收，证明失败未消费凭据。
	env.svc.snap.Devices[dev.ID].CurrentKeyVersion = 1
	mustAccept(t, env, tr, dev, tenantB, newK)
}

func TestAcceptTransfer_NoDoubleReceiveAndReplay(t *testing.T) {
	env := newTestEnv(t, time.Minute, 10*time.Minute)
	oldK := mustKey(t)
	dev := registeredDevice(t, env, testTenant, "dev-1", oldK)
	tr := beginTransfer(t, env, "req-1", dev, testTenant, tenantB)
	newK := mustKey(t)
	mustAccept(t, env, tr, dev, tenantB, newK)

	// 同内容重放返回首次结果（幂等）。
	replay, err := acceptTransfer(t, env, tr, dev, tenantB, newK)
	if err != nil {
		t.Fatalf("idempotent accept replay: %v", err)
	}
	if replay.Status != TransferAccepted {
		t.Fatalf("replay status = %s", replay.Status)
	}

	// 客户端丢失一次性凭据后用空凭据重试：只要新私钥证明与首次内容一致，仍幂等返回。
	noCred := tr
	noCred.credential = ""
	replay2, err := acceptTransfer(t, env, noCred, dev, tenantB, newK)
	if err != nil {
		t.Fatalf("credential-less idempotent replay: %v", err)
	}
	if replay2.ID != tr.view.ID || replay2.Status != TransferAccepted {
		t.Fatalf("credential-less replay mismatch: %+v", replay2)
	}

	// 用另一把新公钥再次接收：拒绝，设备不能被重复接收。
	otherK := mustKey(t)
	if _, err := acceptTransfer(t, env, tr, dev, tenantB, otherK); ErrorCodeOf(err) != ErrCodeTransferClosed {
		t.Fatalf("want transfer closed on double receive, got %v", err)
	}
	// 设备归属与版本保持首次接收结果。
	d := env.svc.snap.Devices[dev.ID]
	if d.TenantID != tenantB || d.CurrentKeyVersion != 2 || !bytes.Equal(d.Keys[2].PublicKey, newK.pub) {
		t.Fatal("double receive altered the established ownership")
	}
}

// ---- 取消与过期：终态唯一 ----

func TestCancelTransfer(t *testing.T) {
	env := newTestEnv(t, time.Minute, 10*time.Minute)
	oldK := mustKey(t)
	dev := registeredDevice(t, env, testTenant, "dev-1", oldK)
	tr := beginTransfer(t, env, "req-1", dev, testTenant, tenantB)
	newK := mustKey(t)

	// 只有源租户能取消。
	if _, err := env.svc.CancelTransfer(tr.view.ID, tenantB); ErrorCodeOf(err) != ErrCodeTransferTenantMismatch {
		t.Fatalf("want tenant mismatch, got %v", err)
	}
	view, err := env.svc.CancelTransfer(tr.view.ID, testTenant)
	if err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if view.Status != TransferCancelled {
		t.Fatalf("status = %s", view.Status)
	}

	// 取消后接收被拒。
	if _, err := acceptTransfer(t, env, tr, dev, tenantB, newK); ErrorCodeOf(err) != ErrCodeTransferClosed {
		t.Fatalf("want closed after cancel, got %v", err)
	}
	// 重复取消被拒，设备仍属源租户且旧钥有效。
	if _, err := env.svc.CancelTransfer(tr.view.ID, testTenant); ErrorCodeOf(err) != ErrCodeTransferClosed {
		t.Fatalf("want closed on double cancel, got %v", err)
	}
	mustAuth(t, env.svc, dev, oldK, []byte("still A"))

	// 取消后可以为该设备重新发起转移。
	tr2 := beginTransfer(t, env, "req-2", dev, testTenant, tenantB)
	if tr2.view.ID == tr.view.ID {
		t.Fatal("new transfer reused cancelled transfer id")
	}
}

func TestTransfer_Expiry(t *testing.T) {
	env := newTestEnv(t, time.Minute, 10*time.Minute)
	oldK := mustKey(t)
	dev := registeredDevice(t, env, testTenant, "dev-1", oldK)
	tr := beginTransfer(t, env, "req-1", dev, testTenant, tenantB)
	newK := mustKey(t)

	// 恰好到达 deadline 转移仍开放（窗口含边界）。
	env.clock.Advance(15 * time.Minute)
	if v, err := env.svc.GetTransfer(tr.view.ID); err != nil || v.Status != TransferPending {
		t.Fatalf("at deadline want pending, got status=%s err=%v", v.Status, err)
	}
	// 再走 1ns 即过期，接收被拒并惰性结算。
	env.clock.Advance(time.Nanosecond)

	if _, err := acceptTransfer(t, env, tr, dev, tenantB, newK); ErrorCodeOf(err) != ErrCodeCredentialExpired {
		t.Fatalf("want credential expired, got %v", err)
	}
	if env.svc.snap.Transfers[tr.view.ID].Status != TransferExpired {
		t.Fatal("transfer not settled to expired")
	}
	// 过期不影响设备归属与源密钥。
	mustAuth(t, env.svc, dev, oldK, []byte("still A after expiry"))
	// 显式 sweep 不重复结算，过期后可重新发起。
	if n, _ := env.svc.SweepExpiredTransfers(); n != 0 {
		t.Fatalf("sweep = %d, want 0", n)
	}
	tr2 := beginTransfer(t, env, "req-2", dev, testTenant, tenantB)
	if tr2.view.Status != TransferPending {
		t.Fatalf("new transfer status = %s", tr2.view.Status)
	}
}

func TestTransfer_AcceptCancelExpireRace_OneTerminalState(t *testing.T) {
	for iter := 0; iter < 25; iter++ {
		env := newTestEnv(t, time.Minute, 10*time.Minute)
		oldK := mustKey(t)
		dev := registeredDevice(t, env, testTenant, fmt.Sprintf("dev-%d", iter), oldK)
		tr := beginTransfer(t, env, fmt.Sprintf("req-%d", iter), dev, testTenant, tenantB)
		newK := mustKey(t)
		att := signMessage(newK.priv,
			TransferAcceptMessage(tr.view.ID, dev.ID, tenantB, tr.view.FrozenVersion, newK.pub))

		// 部分迭代在竞争开始前越过凭据窗口。
		env.clock.Advance(15*time.Minute + time.Nanosecond)

		var wg sync.WaitGroup
		start := make(chan struct{})
		run := func(fn func() error) {
			defer wg.Done()
			<-start
			_ = fn()
		}
		wg.Add(3)
		go run(func() error {
			_, err := env.svc.AcceptTransfer(AcceptTransferRequest{
				TransferID: tr.view.ID, Credential: tr.credential, TargetTenant: tenantB,
				NewPublicKey: newK.pub, Attestation: att,
			})
			return err
		})
		go run(func() error {
			_, err := env.svc.CancelTransfer(tr.view.ID, testTenant)
			return err
		})
		go run(func() error {
			_, err := env.svc.SweepExpiredTransfers()
			return err
		})
		close(start)
		wg.Wait()

		final := env.svc.snap.Transfers[tr.view.ID]
		switch final.Status {
		case TransferAccepted, TransferCancelled, TransferExpired:
		default:
			t.Fatalf("iter %d: unexpected terminal status %q", iter, final.Status)
		}
		if _, open := env.svc.snap.OpenTransfer[dev.ID]; open {
			t.Fatalf("iter %d: transfer still open after race", iter)
		}
		d := env.svc.snap.Devices[dev.ID]
		switch final.Status {
		case TransferAccepted:
			if d.TenantID != tenantB || d.CurrentKeyVersion != 2 ||
				d.Keys[1].State != KeyStateInvalidated || d.Keys[2].State != KeyStateActive {
				t.Fatalf("iter %d: accepted but switch inconsistent: tenant=%s v1=%s v2=%s",
					iter, d.TenantID, d.Keys[1].State, d.Keys[2].State)
			}
			if len(d.Ownership) != 2 || d.Ownership[1].TransferID != tr.view.ID {
				t.Fatalf("iter %d: ownership chain wrong after accept", iter)
			}
		case TransferCancelled, TransferExpired:
			if d.TenantID != testTenant || d.CurrentKeyVersion != 1 || d.Keys[1].State != KeyStateActive {
				t.Fatalf("iter %d: %s but device mutated: tenant=%s version=%d",
					iter, final.Status, d.TenantID, d.CurrentKeyVersion)
			}
		}
	}
}

// ---- 迟到轮换确认不能覆盖新归属 ----

func TestTransfer_LateRotationConfirmCannotOverride(t *testing.T) {
	env := newTestEnv(t, time.Minute, 10*time.Minute)
	oldK := mustKey(t)
	dev := registeredDevice(t, env, testTenant, "dev-1", oldK)

	// 先正常完成一次轮换 v1 -> v2。
	rk := mustKey(t)
	rot := beginRotation(t, env, dev, oldK, rk)
	if _, err := env.svc.ConfirmRotation(rot.ID,
		KeyConfirmation{1, signMessage(oldK.priv, confirmMsg(rot))},
		KeyConfirmation{2, signMessage(rk.priv, confirmMsg(rot))},
	); err != nil {
		t.Fatalf("confirm rotation: %v", err)
	}
	updated, _ := env.svc.GetDevice(dev.ID)

	// 在 v2 上发起并完成转移 A -> B，新版本为 v3。
	tr := beginTransfer(t, env, "req-1", updated, testTenant, tenantB)
	if tr.view.FrozenVersion != 2 {
		t.Fatalf("frozen version = %d, want 2", tr.view.FrozenVersion)
	}
	bk := mustKey(t)
	mustAccept(t, env, tr, updated, tenantB, bk)

	// 旧租户对已完成轮换的迟到确认不能改变新归属。
	if _, err := env.svc.ConfirmRotation(rot.ID,
		KeyConfirmation{1, signMessage(oldK.priv, confirmMsg(rot))},
	); ErrorCodeOf(err) != ErrCodeRotationClosed {
		t.Fatalf("want rotation closed for late confirm, got %v", err)
	}
	d := env.svc.snap.Devices[dev.ID]
	if d.TenantID != tenantB || d.CurrentKeyVersion != 3 {
		t.Fatalf("late rotation confirm overrode ownership: tenant=%s version=%d", d.TenantID, d.CurrentKeyVersion)
	}
}

// ---- 归属历史查询：多跳链路与敏感内容隔离 ----

func TestOwnershipHistory_MultiHopChain(t *testing.T) {
	env := newTestEnv(t, time.Minute, 10*time.Minute)
	kA := mustKey(t)
	dev := registeredDevice(t, env, testTenant, "dev-1", kA)

	// A -> B
	tr1 := beginTransfer(t, env, "req-1", dev, testTenant, tenantB)
	kB := mustKey(t)
	mustAccept(t, env, tr1, dev, tenantB, kB)
	dev, _ = env.svc.GetDevice(dev.ID)

	// 中途一次取消不应出现在“生效归属”里，但仍应出现在转移历史中。
	cancelled := beginTransfer(t, env, "req-cancel", dev, tenantB, tenantC)
	if _, err := env.svc.CancelTransfer(cancelled.view.ID, tenantB); err != nil {
		t.Fatalf("cancel: %v", err)
	}

	// B -> C
	tr2 := beginTransfer(t, env, "req-2", dev, tenantB, tenantC)
	kC := mustKey(t)
	mustAccept(t, env, tr2, dev, tenantC, kC)

	hist, err := env.svc.GetOwnershipHistory(dev.ID)
	if err != nil {
		t.Fatalf("GetOwnershipHistory: %v", err)
	}
	if hist.TenantID != tenantC {
		t.Fatalf("current tenant = %s, want %s", hist.TenantID, tenantC)
	}
	// 生效归属链恰好三环：A(v1) -> B(v2) -> C(v3)。
	if len(hist.Chain) != 3 {
		t.Fatalf("chain length = %d, want 3", len(hist.Chain))
	}
	wantChain := []struct {
		tenant string
		ver    int
		tr     string
	}{
		{testTenant, 1, ""},
		{tenantB, 2, tr1.view.ID},
		{tenantC, 3, tr2.view.ID},
	}
	for i, w := range wantChain {
		got := hist.Chain[i]
		if got.TenantID != w.tenant || got.KeyVersion != w.ver || got.TransferID != w.tr {
			t.Fatalf("chain[%d] = %+v, want tenant=%s ver=%d tr=%s", i, got, w.tenant, w.ver, w.tr)
		}
		if i < 2 && got.EndedAt == nil {
			t.Fatalf("chain[%d] should be closed", i)
		}
	}
	if hist.Chain[2].EndedAt != nil {
		t.Fatal("current ownership link must be open-ended")
	}

	// 转移历史包含全部三张单（含已取消），并记录两端决定与版本变化。
	if len(hist.Transfers) != 3 {
		t.Fatalf("transfers = %d, want 3", len(hist.Transfers))
	}
	byID := map[string]TransferHistoryEntry{}
	for _, e := range hist.Transfers {
		byID[e.TransferID] = e
	}
	e1 := byID[tr1.view.ID]
	if e1.FromTenant != testTenant || e1.ToTenant != tenantB || e1.FrozenVersion != 1 ||
		e1.NewVersion != 2 || e1.Status != TransferAccepted {
		t.Fatalf("accepted entry wrong: %+v", e1)
	}
	if ec := byID[cancelled.view.ID]; ec.Status != TransferCancelled || ec.NewVersion != 0 {
		t.Fatalf("cancelled entry wrong: %+v", ec)
	}

	// 历史与转移单视图均不得携带凭据、公钥或证明。
	raw, _ := json.Marshal(hist)
	for _, secret := range []string{tr1.credential, tr2.credential, cancelled.credential} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("ownership history leaks credential")
		}
	}
	if bytes.Contains(raw, []byte(EncodeBase64(kC.pub))) || bytes.Contains(raw, kC.pub) {
		t.Fatal("ownership history leaks public key material")
	}
}

// ---- 持久化：转移状态与归属链跨重启恢复，凭据明文不落盘 ----

func TestTransfer_FileStoreRoundtrip(t *testing.T) {
	path := t.TempDir() + "/state.json"
	clock := NewFixedClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))

	svc, err := New(Config{Store: NewFileStore(path), Clock: clock,
		ChallengeTTL: time.Minute, RotationWindow: 10 * time.Minute, TransferTTL: time.Hour})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	kA := mustKey(t)
	ch, err := svc.IssueChallenge(testTenant, "dev-1", []byte("attr"), 0)
	if err != nil {
		t.Fatal(err)
	}
	dev, err := svc.Register(RegisterRequest{
		ChallengeID: ch.ID, Secret: ch.Secret, ExternalID: "dev-1", Attributes: []byte("attr"),
		PublicKey: kA.pub, Attestation: signAttestation(kA.priv, ch.ID, "dev-1", []byte("attr")),
	})
	if err != nil {
		t.Fatal(err)
	}
	view, credential, err := svc.BeginTransfer("req-1", dev.ID, testTenant, tenantB, 0)
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(credential)) {
		t.Fatal("plaintext transfer credential present in snapshot file")
	}

	// 重启后目标租户仍可凭凭据完成接收。
	svc2, err := New(Config{Store: NewFileStore(path), Clock: clock, TransferTTL: time.Hour})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	kB := mustKey(t)
	att := signMessage(kB.priv, TransferAcceptMessage(view.ID, dev.ID, tenantB, 1, kB.pub))
	acc, err := svc2.AcceptTransfer(AcceptTransferRequest{
		TransferID: view.ID, Credential: credential, TargetTenant: tenantB,
		NewPublicKey: kB.pub, Attestation: att,
	})
	if err != nil {
		t.Fatalf("accept after reload: %v", err)
	}
	if acc.Status != TransferAccepted {
		t.Fatalf("status = %s", acc.Status)
	}

	// 再次重启：归属、版本与历史保持终态。
	svc3, err := New(Config{Store: NewFileStore(path), Clock: clock})
	if err != nil {
		t.Fatalf("second reload: %v", err)
	}
	got, _ := svc3.GetDevice(dev.ID)
	if got.TenantID != tenantB || got.CurrentKeyVersion != 2 {
		t.Fatalf("final state mismatch: %+v", got)
	}
	hist, err := svc3.GetOwnershipHistory(dev.ID)
	if err != nil || len(hist.Chain) != 2 {
		t.Fatalf("history after reload: %v chain=%d", err, len(hist.Chain))
	}
}

// ---- HTTP 端到端 ----

func TestHTTPHandler_TransferEndToEnd(t *testing.T) {
	env := newTestEnv(t, time.Minute, 10*time.Minute)
	h := NewHandler(env.svc)
	srv := httptest.NewServer(h)
	defer srv.Close()

	kA := mustKey(t)
	// 注册到 A。
	var ch Challenge
	doJSON(t, http.MethodPost, srv.URL+"/admin/challenges", http.StatusCreated, map[string]string{
		"tenant_id":   testTenant,
		"external_id": "dev-tr-1",
		"attributes":  EncodeBase64([]byte("attr")),
	}, &ch)
	var dev DeviceView
	doJSON(t, http.MethodPost, srv.URL+"/devices/register", http.StatusOK, map[string]string{
		"challenge_id": ch.ID,
		"secret":       ch.Secret,
		"external_id":  "dev-tr-1",
		"attributes":   EncodeBase64([]byte("attr")),
		"public_key":   EncodeBase64(kA.pub),
		"attestation":  EncodeBase64(signAttestation(kA.priv, ch.ID, "dev-tr-1", []byte("attr"))),
	}, &dev)

	// A 发起转移到 B。
	var begun struct {
		Transfer   TransferView `json:"transfer"`
		Credential string       `json:"credential"`
	}
	doJSON(t, http.MethodPost, srv.URL+"/devices/"+dev.ID+"/transfers", http.StatusCreated, map[string]string{
		"request_id":    "http-req-1",
		"source_tenant": testTenant,
		"target_tenant": tenantB,
	}, &begun)
	if begun.Credential == "" || begun.Transfer.Status != TransferPending {
		t.Fatalf("begin response wrong: %+v", begun)
	}

	// 查询转移单不回显凭据。
	var tv TransferView
	doJSON(t, http.MethodGet, srv.URL+"/transfers/"+begun.Transfer.ID, http.StatusOK, struct{}{}, &tv)
	if tv.ID != begun.Transfer.ID || tv.TargetTenant != tenantB {
		t.Fatalf("transfer view wrong: %+v", tv)
	}

	// B 用新公钥与证明接收。
	kB := mustKey(t)
	att := ed25519.Sign(kB.priv,
		TransferAcceptMessage(begun.Transfer.ID, dev.ID, tenantB, 1, kB.pub))
	doJSON(t, http.MethodPost, srv.URL+"/transfers/"+begun.Transfer.ID+"/accept", http.StatusOK, map[string]string{
		"credential":     begun.Credential,
		"target_tenant":  tenantB,
		"new_public_key": EncodeBase64(kB.pub),
		"attestation":    EncodeBase64(att),
	}, &tv)
	if tv.Status != TransferAccepted {
		t.Fatalf("accept status = %s", tv.Status)
	}

	// 源租户认证 -> 403（tenant mismatch）。
	doJSON(t, http.MethodPost, srv.URL+"/devices/"+dev.ID+"/authenticate", http.StatusForbidden, map[string]any{
		"tenant_id":   testTenant,
		"key_version": 1,
		"message":     EncodeBase64([]byte("late A")),
		"signature":   EncodeBase64(signMessage(kA.priv, []byte("late A"))),
	}, nil)
	// 新租户新钥认证 -> 204。
	doJSON(t, http.MethodPost, srv.URL+"/devices/"+dev.ID+"/authenticate", http.StatusNoContent, map[string]any{
		"tenant_id":   tenantB,
		"key_version": 2,
		"message":     EncodeBase64([]byte("B ok")),
		"signature":   EncodeBase64(signMessage(kB.priv, []byte("B ok"))),
	}, nil)

	// 归属历史：链 2 环，且不含凭据明文。
	var hist OwnershipHistory
	doJSON(t, http.MethodGet, srv.URL+"/devices/"+dev.ID+"/ownership", http.StatusOK, struct{}{}, &hist)
	if hist.TenantID != tenantB || len(hist.Chain) != 2 || len(hist.Transfers) != 1 {
		t.Fatalf("history wrong: %+v", hist)
	}
	histRaw, _ := json.Marshal(hist)
	if bytes.Contains(histRaw, []byte(begun.Credential)) {
		t.Fatal("ownership endpoint leaked credential")
	}

	// 取消一张不存在/已终态的转移单返回 409。
	doJSON(t, http.MethodPost, srv.URL+"/transfers/"+begun.Transfer.ID+"/cancel", http.StatusConflict, map[string]string{
		"source_tenant": testTenant,
	}, nil)
}
