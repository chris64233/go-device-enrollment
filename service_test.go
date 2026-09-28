package deviceenrollment

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type testEnv struct {
	svc   *Service
	clock *fixedClock
}

// testTenant 是现有测试中设备注册与认证使用的默认租户。
const testTenant = "tenant-a"

func newTestEnv(t *testing.T, ttl, window time.Duration) *testEnv {
	t.Helper()
	clock := NewFixedClock(time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC))
	svc, err := New(Config{
		Store:          NewMemoryStore(),
		Clock:          clock,
		ChallengeTTL:   ttl,
		RotationWindow: window,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &testEnv{svc: svc, clock: clock.(*fixedClock)}
}

type deviceKey struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func mustKey(t *testing.T) deviceKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return deviceKey{pub: pub, priv: priv}
}

func (e *testEnv) issue(t *testing.T, external string, attrs []byte, ttl time.Duration) *Challenge {
	t.Helper()
	ch, err := e.svc.IssueChallenge(testTenant, external, attrs, ttl)
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	return ch
}

func (e *testEnv) register(t *testing.T, ch *Challenge, external string, attrs []byte, k deviceKey) (*DeviceView, error) {
	t.Helper()
	att := signAttestation(k.priv, ch.ID, external, attrs)
	return e.svc.Register(RegisterRequest{
		ChallengeID: ch.ID,
		Secret:      ch.Secret,
		ExternalID:  external,
		Attributes:  attrs,
		PublicKey:   k.pub,
		Attestation: att,
	})
}

func mustRegister(t *testing.T, env *testEnv, ch *Challenge, external string, attrs []byte, k deviceKey) *DeviceView {
	t.Helper()
	dev, err := env.register(t, ch, external, attrs, k)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	return dev
}

func confirmMsg(rot *RotationView) []byte {
	return RotationConfirmMessage(rot.DeviceID, rot.ID, rot.OldVersion, rot.NewVersion)
}

func cancelMsg(rot *RotationView) []byte {
	return RotationCancelMessage(rot.DeviceID, rot.ID, rot.OldVersion, rot.NewVersion)
}

func mustAuth(t *testing.T, svc *Service, dev *DeviceView, k deviceKey, msg []byte) {
	t.Helper()
	if err := svc.Authenticate(AuthRequest{
		DeviceID:   dev.ID,
		TenantID:   dev.TenantID,
		KeyVersion: dev.CurrentKeyVersion,
		Message:    msg,
		Signature:  signMessage(k.priv, msg),
	}); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
}

// ---- 挑战 ----

func TestIssueChallenge_StoresDigestOnly(t *testing.T) {
	env := newTestEnv(t, time.Minute, time.Minute)
	ch := env.issue(t, "dev-1", []byte("model-A"), 0)

	if ch.ID == "" || ch.Secret == "" {
		t.Fatal("challenge id/secret empty")
	}
	rec := env.svc.snap.Challenges[ch.ID]
	if rec == nil {
		t.Fatal("challenge not persisted")
	}
	if bytes.Contains(rec.SecretDigest, []byte(ch.Secret)) {
		t.Fatal("plaintext secret leaked into digest storage")
	}
	if bytes.Equal(rec.SecretDigest, []byte(ch.Secret)) {
		t.Fatal("digest equals plaintext secret")
	}
	if len(rec.Salt) == 0 {
		t.Fatal("salt missing")
	}
	if rec.Consumed {
		t.Fatal("fresh challenge already consumed")
	}
	if !rec.ExpiresAt.Equal(env.clock.Now().Add(time.Minute)) {
		t.Fatalf("expiry = %v, want %v", rec.ExpiresAt, env.clock.Now().Add(time.Minute))
	}
	if string(rec.Attributes) != "model-A" || rec.ExternalID != "dev-1" {
		t.Fatal("challenge did not bind expected device attributes")
	}
}

func TestRegister_ChallengeSecretAndLifecycle(t *testing.T) {
	env := newTestEnv(t, time.Minute, time.Minute)
	k := mustKey(t)
	ch := env.issue(t, "dev-1", []byte("attr"), 0)

	// 错误秘密。
	bad := *ch
	bad.Secret = "wrong"
	if _, err := env.register(t, &bad, "dev-1", []byte("attr"), k); ErrorCodeOf(err) != ErrCodeChallengeSecretMismatch {
		t.Fatalf("want secret mismatch, got %v", err)
	}

	// 过期挑战不可用。
	env.clock.Advance(61 * time.Second)
	if _, err := env.register(t, ch, "dev-1", []byte("attr"), k); ErrorCodeOf(err) != ErrCodeChallengeExpired {
		t.Fatalf("want expired, got %v", err)
	}

	// 不存在的挑战。
	if _, err := env.svc.Register(RegisterRequest{
		ChallengeID: "nope", Secret: "x", ExternalID: "dev-1", PublicKey: k.pub,
	}); ErrorCodeOf(err) != ErrCodeChallengeNotFound {
		t.Fatalf("want not found, got %v", err)
	}
}

func TestRegister_AttestationFailure(t *testing.T) {
	env := newTestEnv(t, time.Minute, time.Minute)
	k := mustKey(t)
	ch := env.issue(t, "dev-1", []byte("attr"), 0)

	_, err := env.svc.Register(RegisterRequest{
		ChallengeID: ch.ID, Secret: ch.Secret, ExternalID: "dev-1",
		Attributes: []byte("attr"), PublicKey: k.pub,
		Attestation: make([]byte, 64), // 全零签名
	})
	if ErrorCodeOf(err) != ErrCodeAttestationFailed {
		t.Fatalf("want attestation failed, got %v", err)
	}
}

func TestRegister_AttributeBinding(t *testing.T) {
	env := newTestEnv(t, time.Minute, time.Minute)
	k := mustKey(t)
	ch := env.issue(t, "dev-1", []byte("expected"), 0)

	// 外部注册号不一致。
	if _, err := env.register(t, ch, "dev-2", []byte("expected"), k); ErrorCodeOf(err) != ErrCodeChallengeAttributeMismatch {
		t.Fatalf("want attribute mismatch, got %v", err)
	}
	// 属性不一致。
	if _, err := env.register(t, ch, "dev-1", []byte("tampered"), k); ErrorCodeOf(err) != ErrCodeChallengeAttributeMismatch {
		t.Fatalf("want attribute mismatch, got %v", err)
	}
}

// ---- 幂等与冲突 ----

func TestRegister_IdempotentSameContent(t *testing.T) {
	env := newTestEnv(t, time.Minute, time.Minute)
	k := mustKey(t)
	ch := env.issue(t, "dev-1", []byte("attr"), 0)

	dev1 := mustRegister(t, env, ch, "dev-1", []byte("attr"), k)

	// 同一挑战、同号同内容重复调用（重新签名），返回原身份。
	dev2, err := env.register(t, ch, "dev-1", []byte("attr"), k)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if dev2.ID != dev1.ID {
		t.Fatalf("idempotent replay returned different device: %s != %s", dev2.ID, dev1.ID)
	}

	// 用另一把新挑战为同一外部号、同一内容注册，同样返回原身份且新挑战保持未消费。
	ch2 := env.issue(t, "dev-1", []byte("attr"), 0)
	dev3, err := env.register(t, ch2, "dev-1", []byte("attr"), k)
	if err != nil {
		t.Fatalf("second-challenge same content: %v", err)
	}
	if dev3.ID != dev1.ID {
		t.Fatalf("same-content enrollment via other challenge created a second device")
	}
	if env.svc.snap.Challenges[ch2.ID].Consumed {
		t.Fatal("idempotent replay must not consume the unused challenge")
	}
	if len(env.svc.snap.Devices) != 1 {
		t.Fatalf("devices = %d, want 1", len(env.svc.snap.Devices))
	}
}

func TestRegister_ConflictDifferentContent(t *testing.T) {
	env := newTestEnv(t, time.Minute, time.Minute)
	k1 := mustKey(t)
	k2 := mustKey(t)
	ch := env.issue(t, "dev-1", []byte("attr"), 0)

	dev1 := mustRegister(t, env, ch, "dev-1", []byte("attr"), k1)

	// 同号异内容（不同公钥）：冲突，且不得覆盖既有设备。
	if _, err := env.register(t, ch, "dev-1", []byte("attr"), k2); ErrorCodeOf(err) != ErrCodeConflict {
		t.Fatalf("want conflict, got %v", err)
	}
	// 同号异内容（不同属性）同样冲突。
	ch3 := env.issue(t, "dev-1", []byte("other"), 0)
	k3 := mustKey(t)
	if _, err := env.register(t, ch3, "dev-1", []byte("other"), k3); ErrorCodeOf(err) != ErrCodeConflict {
		t.Fatalf("want conflict for different attributes, got %v", err)
	}
	got, err := env.svc.GetDevice(dev1.ID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if !bytes.Equal(got.PublicKey, k1.pub) {
		t.Fatal("conflicting enrollment overwrote the original device key")
	}
}

func TestRegister_ConcurrentSingleChallengeOneWinner(t *testing.T) {
	env := newTestEnv(t, 5*time.Minute, time.Minute)

	t.Run("same_content_all_see_same_device", func(t *testing.T) {
		k := mustKey(t)
		ch := env.issue(t, "dev-conc-1", []byte("attr"), 0)

		const n = 32
		var wg sync.WaitGroup
		ids := make([]string, n)
		errs := make([]error, n)
		start := make(chan struct{})
		wg.Add(n)
		for i := 0; i < n; i++ {
			i := i
			go func() {
				defer wg.Done()
				<-start
				dev, err := env.register(t, ch, "dev-conc-1", []byte("attr"), k)
				if err == nil {
					ids[i] = dev.ID
				}
				errs[i] = err
			}()
		}
		close(start)
		wg.Wait()

		want := ids[0]
		if want == "" {
			t.Fatal("no winning registration")
		}
		for i := 0; i < n; i++ {
			if errs[i] != nil {
				t.Fatalf("goroutine %d: %v", i, errs[i])
			}
			if ids[i] != want {
				t.Fatalf("goroutine %d saw device %s, want %s", i, ids[i], want)
			}
		}
		rec := env.svc.snap.Challenges[ch.ID]
		if !rec.Consumed || rec.ConsumedByDevice != want {
			t.Fatal("challenge not consumed exactly once by the winner")
		}
	})

	t.Run("different_content_only_one_created", func(t *testing.T) {
		ch := env.issue(t, "dev-conc-2", []byte("attr"), 0)

		const n = 32
		var wg sync.WaitGroup
		start := make(chan struct{})
		var created, conflicts int64
		var mu sync.Mutex
		wg.Add(n)
		for i := 0; i < n; i++ {
			go func() {
				defer wg.Done()
				k := mustKey(t)
				<-start
				_, err := env.register(t, ch, "dev-conc-2", []byte("attr"), k)
				mu.Lock()
				switch ErrorCodeOf(err) {
				case "":
					created++
				case ErrCodeConflict:
					conflicts++
				default:
					t.Errorf("unexpected error: %v", err)
				}
				mu.Unlock()
			}()
		}
		close(start)
		wg.Wait()

		if created != 1 {
			t.Fatalf("created = %d, want 1 (conflicts=%d)", created, conflicts)
		}
		if conflicts != n-1 {
			t.Fatalf("conflicts = %d, want %d", conflicts, n-1)
		}
	})
}

// ---- 密钥轮换 ----

func beginRotation(t *testing.T, env *testEnv, dev *DeviceView, oldK, newK deviceKey) *RotationView {
	t.Helper()
	sig := signMessage(oldK.priv, RotationBeginMessage(dev.ID, newK.pub))
	rot, err := env.svc.BeginRotation(dev.ID, newK.pub, sig)
	if err != nil {
		t.Fatalf("BeginRotation: %v", err)
	}
	return rot
}

func TestRotation_HappyPath(t *testing.T) {
	env := newTestEnv(t, time.Minute, 10*time.Minute)
	oldK := mustKey(t)
	ch := env.issue(t, "dev-1", []byte("attr"), 0)
	dev := mustRegister(t, env, ch, "dev-1", []byte("attr"), oldK)

	newK := mustKey(t)
	rot := beginRotation(t, env, dev, oldK, newK)
	if rot.Status != RotationPending || rot.OldVersion != 1 || rot.NewVersion != 2 {
		t.Fatalf("unexpected rotation: %+v", rot)
	}

	// 窗口内当前仍是旧钥；pending 新钥不能用于认证。
	mustAuth(t, env.svc, dev, oldK, []byte("hello"))

	// 旧钥先确认。
	rot, err := env.svc.ConfirmRotation(rot.ID, KeyConfirmation{
		KeyVersion: 1, Signature: signMessage(oldK.priv, confirmMsg(rot)),
	})
	if err != nil {
		t.Fatalf("old confirm: %v", err)
	}
	if rot.Status != RotationPending || !rot.OldKeyConfirmed || rot.NewKeyConfirmed {
		t.Fatalf("rotation should stay pending after one-side confirm: %+v", rot)
	}

	// 旧钥仍有效，因为轮换尚未完成。
	mustAuth(t, env.svc, dev, oldK, []byte("still old"))

	// 新钥确认 -> 同一刻完成；之后旧钥立即失效。
	rot, err = env.svc.ConfirmRotation(rot.ID, KeyConfirmation{
		KeyVersion: 2, Signature: signMessage(newK.priv, confirmMsg(rot)),
	})
	if err != nil {
		t.Fatalf("new confirm: %v", err)
	}
	if rot.Status != RotationConfirmed || rot.CompletedAt == nil {
		t.Fatalf("rotation not completed: %+v", rot)
	}

	updated, err := env.svc.GetDevice(dev.ID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if updated.CurrentKeyVersion != 2 {
		t.Fatalf("current version = %d, want 2", updated.CurrentKeyVersion)
	}
	if env.svc.snap.Devices[dev.ID].Keys[1].State != KeyStateInvalidated {
		t.Fatal("old key not invalidated immediately after rotation")
	}

	// 新钥认证成功。
	mustAuth(t, env.svc, updated, newK, []byte("new world"))

	// 旧钥版本的迟到认证请求必须被拒绝，不能覆盖新状态。
	err = env.svc.Authenticate(AuthRequest{
		DeviceID: dev.ID, TenantID: testTenant, KeyVersion: 1,
		Message:   []byte("late"),
		Signature: signMessage(oldK.priv, []byte("late")),
	})
	if ErrorCodeOf(err) != ErrCodeKeyVersionInvalid {
		t.Fatalf("want key version invalid for stale key, got %v", err)
	}

	// 终态轮换拒绝迟到确认。
	_, err = env.svc.ConfirmRotation(rot.ID, KeyConfirmation{
		KeyVersion: 2, Signature: signMessage(newK.priv, confirmMsg(rot)),
	})
	if ErrorCodeOf(err) != ErrCodeRotationClosed {
		t.Fatalf("want rotation closed, got %v", err)
	}
}

func TestRotation_BothConfirmationsAtomic(t *testing.T) {
	env := newTestEnv(t, time.Minute, 10*time.Minute)
	oldK := mustKey(t)
	ch := env.issue(t, "dev-1", nil, 0)
	dev := mustRegister(t, env, ch, "dev-1", nil, oldK)
	newK := mustKey(t)
	rot := beginRotation(t, env, dev, oldK, newK)

	// 两侧一次给齐，但新钥签名非法：整批失败，旧钥确认也不得落库。
	_, err := env.svc.ConfirmRotation(rot.ID,
		KeyConfirmation{KeyVersion: 1, Signature: signMessage(oldK.priv, confirmMsg(rot))},
		KeyConfirmation{KeyVersion: 2, Signature: make([]byte, 64)},
	)
	if ErrorCodeOf(err) != ErrCodeSignatureInvalid {
		t.Fatalf("want signature invalid, got %v", err)
	}
	stored := env.svc.snap.Rotations[rot.ID]
	if stored.OldKeyConfirmed || stored.NewKeyConfirmed || stored.Status != RotationPending {
		t.Fatalf("failed batch must not record partial confirmation: %+v", stored)
	}

	// 合法的双侧确认一次完成。
	rot2, err := env.svc.ConfirmRotation(rot.ID,
		KeyConfirmation{KeyVersion: 1, Signature: signMessage(oldK.priv, confirmMsg(rot))},
		KeyConfirmation{KeyVersion: 2, Signature: signMessage(newK.priv, confirmMsg(rot))},
	)
	if err != nil {
		t.Fatalf("both confirm: %v", err)
	}
	if rot2.Status != RotationConfirmed {
		t.Fatalf("status = %s", rot2.Status)
	}
}

func TestRotation_Cancel(t *testing.T) {
	env := newTestEnv(t, time.Minute, 10*time.Minute)
	oldK := mustKey(t)
	ch := env.issue(t, "dev-1", nil, 0)
	dev := mustRegister(t, env, ch, "dev-1", nil, oldK)
	newK := mustKey(t)
	rot := beginRotation(t, env, dev, oldK, newK)

	// 只有旧钥（当前钥）能取消。
	_, err := env.svc.CancelRotation(rot.ID, signMessage(newK.priv, cancelMsg(rot)))
	if ErrorCodeOf(err) != ErrCodeSignatureInvalid {
		t.Fatalf("want signature invalid for new-key cancel, got %v", err)
	}

	rot2, err := env.svc.CancelRotation(rot.ID, signMessage(oldK.priv, cancelMsg(rot)))
	if err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if rot2.Status != RotationCancelled || rot2.CompletedAt == nil {
		t.Fatalf("status = %s", rot2.Status)
	}
	if env.svc.snap.Devices[dev.ID].Keys[2].State != KeyStateInvalidated {
		t.Fatal("pending new key must be invalidated on cancel")
	}
	// 旧钥继续有效。
	mustAuth(t, env.svc, dev, oldK, []byte("still here"))

	// 取消后确认、再取消都被拒绝。
	if _, err := env.svc.ConfirmRotation(rot.ID,
		KeyConfirmation{1, signMessage(oldK.priv, confirmMsg(rot))},
	); ErrorCodeOf(err) != ErrCodeRotationClosed {
		t.Fatalf("want closed on confirm-after-cancel, got %v", err)
	}
	if _, err := env.svc.CancelRotation(rot.ID, signMessage(oldK.priv, cancelMsg(rot))); ErrorCodeOf(err) != ErrCodeRotationClosed {
		t.Fatalf("want closed on double cancel, got %v", err)
	}

	// 取消后可以发起新轮换。
	newK2 := mustKey(t)
	rot3 := beginRotation(t, env, dev, oldK, newK2)
	if rot3.NewVersion != 3 {
		t.Fatalf("new rotation version = %d, want 3", rot3.NewVersion)
	}
}

func TestRotation_Timeout(t *testing.T) {
	env := newTestEnv(t, time.Minute, 10*time.Minute)
	oldK := mustKey(t)
	ch := env.issue(t, "dev-1", nil, 0)
	dev := mustRegister(t, env, ch, "dev-1", nil, oldK)
	newK := mustKey(t)
	rot := beginRotation(t, env, dev, oldK, newK)

	// 旧钥确认后时间越过窗口：超时仍是唯一终态，旧钥保留，新钥失效。
	if _, err := env.svc.ConfirmRotation(rot.ID,
		KeyConfirmation{1, signMessage(oldK.priv, confirmMsg(rot))},
	); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	env.clock.Advance(11 * time.Minute)

	n, err := env.svc.SweepExpiredRotations()
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n != 1 {
		t.Fatalf("swept = %d, want 1", n)
	}
	stored := env.svc.snap.Rotations[rot.ID]
	if stored.Status != RotationTimedOut {
		t.Fatalf("status = %s", stored.Status)
	}
	if env.svc.snap.Devices[dev.ID].Keys[2].State != KeyStateInvalidated {
		t.Fatal("pending new key must be invalidated on timeout")
	}
	mustAuth(t, env.svc, dev, oldK, []byte("survived timeout"))

	// 超时后的迟到双侧确认不得复活轮换。
	_, err = env.svc.ConfirmRotation(rot.ID,
		KeyConfirmation{1, signMessage(oldK.priv, confirmMsg(rot))},
		KeyConfirmation{2, signMessage(newK.priv, confirmMsg(rot))},
	)
	if ErrorCodeOf(err) != ErrCodeRotationClosed {
		t.Fatalf("want closed after timeout, got %v", err)
	}
	if env.svc.snap.Rotations[rot.ID].Status != RotationTimedOut {
		t.Fatal("late confirmation resurrected a timed-out rotation")
	}

	// 再次 sweep 不重复结算。
	if n, _ := env.svc.SweepExpiredRotations(); n != 0 {
		t.Fatalf("second sweep = %d, want 0", n)
	}
}

func TestRotation_TimeoutIsLazyAndDeadlineInclusive(t *testing.T) {
	env := newTestEnv(t, time.Minute, 10*time.Minute)
	oldK := mustKey(t)
	ch := env.issue(t, "dev-1", nil, 0)
	dev := mustRegister(t, env, ch, "dev-1", nil, oldK)
	newK := mustKey(t)
	rot := beginRotation(t, env, dev, oldK, newK)

	// 恰好到达 deadline（等于）窗口仍然开放。
	env.clock.Advance(10 * time.Minute)
	view, err := env.svc.GetRotation(rot.ID)
	if err != nil {
		t.Fatalf("GetRotation: %v", err)
	}
	if view.Status != RotationPending {
		t.Fatalf("status at deadline = %s, want pending", view.Status)
	}
	// 再走 1ns 即超时，访问时惰性结算。
	env.clock.Advance(1)
	view, err = env.svc.GetRotation(rot.ID)
	if err != nil {
		t.Fatalf("lazy timeout GetRotation: %v", err)
	}
	if view.Status != RotationTimedOut {
		t.Fatalf("status = %s, want timed_out", view.Status)
	}
}

func TestRotation_ConfirmCancelTimeoutRace_OneTerminalState(t *testing.T) {
	for iter := 0; iter < 20; iter++ {
		env := newTestEnv(t, time.Minute, 10*time.Minute)
		oldK := mustKey(t)
		ch := env.issue(t, fmt.Sprintf("dev-%d", iter), nil, 0)
		dev := mustRegister(t, env, ch, fmt.Sprintf("dev-%d", iter), nil, oldK)
		newK := mustKey(t)
		rot := beginRotation(t, env, dev, oldK, newK)
		msg := confirmMsg(rot)
		cMsg := cancelMsg(rot)

		// 让一半迭代在竞争开始前恰好越过超时窗口。
		env.clock.Advance(10*time.Minute + time.Nanosecond)

		var wg sync.WaitGroup
		start := make(chan struct{})
		run := func(fn func() error) {
			defer wg.Done()
			<-start
			_ = fn()
		}
		wg.Add(3)
		go run(func() error {
			_, err := env.svc.ConfirmRotation(rot.ID,
				KeyConfirmation{1, signMessage(oldK.priv, msg)},
				KeyConfirmation{2, signMessage(newK.priv, msg)},
			)
			return err
		})
		go run(func() error {
			_, err := env.svc.CancelRotation(rot.ID, signMessage(oldK.priv, cMsg))
			return err
		})
		go run(func() error {
			_, err := env.svc.SweepExpiredRotations()
			return err
		})
		close(start)
		wg.Wait()

		final := env.svc.snap.Rotations[rot.ID]
		switch final.Status {
		case RotationConfirmed, RotationCancelled, RotationTimedOut:
		default:
			t.Fatalf("iter %d: unexpected terminal status %q", iter, final.Status)
		}
		if _, open := env.svc.snap.OpenRotation[dev.ID]; open {
			t.Fatalf("iter %d: rotation still open after race", iter)
		}
		device := env.svc.snap.Devices[dev.ID]
		switch final.Status {
		case RotationConfirmed:
			if device.CurrentKeyVersion != 2 || device.Keys[1].State != KeyStateInvalidated ||
				device.Keys[2].State != KeyStateActive {
				t.Fatalf("iter %d: confirmed but key states wrong: v1=%s v2=%s current=%d",
					iter, device.Keys[1].State, device.Keys[2].State, device.CurrentKeyVersion)
			}
		case RotationCancelled, RotationTimedOut:
			if device.CurrentKeyVersion != 1 || device.Keys[1].State != KeyStateActive ||
				device.Keys[2].State != KeyStateInvalidated {
				t.Fatalf("iter %d: %s but key states wrong: v1=%s v2=%s current=%d",
					iter, final.Status, device.Keys[1].State, device.Keys[2].State, device.CurrentKeyVersion)
			}
		}
	}
}

func TestRotation_BeginGuards(t *testing.T) {
	env := newTestEnv(t, time.Minute, 10*time.Minute)
	oldK := mustKey(t)
	ch := env.issue(t, "dev-1", nil, 0)
	dev := mustRegister(t, env, ch, "dev-1", nil, oldK)
	newK := mustKey(t)

	// 必须由当前钥签名。
	_, err := env.svc.BeginRotation(dev.ID, newK.pub, signMessage(newK.priv, RotationBeginMessage(dev.ID, newK.pub)))
	if ErrorCodeOf(err) != ErrCodeSignatureInvalid {
		t.Fatalf("want signature invalid, got %v", err)
	}
	// 新旧钥不得相同。
	_, err = env.svc.BeginRotation(dev.ID, oldK.pub, signMessage(oldK.priv, RotationBeginMessage(dev.ID, oldK.pub)))
	if ErrorCodeOf(err) != ErrCodeInvalidArgument {
		t.Fatalf("want invalid argument for same key, got %v", err)
	}

	rot := beginRotation(t, env, dev, oldK, newK)
	// 设备同时只能有一个打开的轮换。
	k3 := mustKey(t)
	_, err = env.svc.BeginRotation(dev.ID, k3.pub, signMessage(oldK.priv, RotationBeginMessage(dev.ID, k3.pub)))
	if ErrorCodeOf(err) != ErrCodeRotationInProgress {
		t.Fatalf("want rotation in progress, got %v", err)
	}

	// 禁用设备不能发起轮换。
	if _, err := env.svc.DisableDevice(dev.ID); err != nil {
		t.Fatalf("disable: %v", err)
	}
	_, err = env.svc.BeginRotation(dev.ID, k3.pub, signMessage(oldK.priv, RotationBeginMessage(dev.ID, k3.pub)))
	if ErrorCodeOf(err) != ErrCodeDeviceDisabled {
		t.Fatalf("want device disabled, got %v", err)
	}
	// 禁用也原子中止了打开的轮换。
	if env.svc.snap.Rotations[rot.ID].Status != RotationAborted {
		t.Fatalf("open rotation status = %s, want aborted", env.svc.snap.Rotations[rot.ID].Status)
	}
}

// ---- 认证与禁用 ----

func TestAuthenticate_Failures(t *testing.T) {
	env := newTestEnv(t, time.Minute, 10*time.Minute)
	k := mustKey(t)
	ch := env.issue(t, "dev-1", nil, 0)
	dev := mustRegister(t, env, ch, "dev-1", nil, k)

	if err := env.svc.Authenticate(AuthRequest{DeviceID: "ghost", TenantID: testTenant, KeyVersion: 1, Message: []byte("m"),
		Signature: signMessage(k.priv, []byte("m"))}); ErrorCodeOf(err) != ErrCodeDeviceNotFound {
		t.Fatalf("want device not found, got %v", err)
	}
	if err := env.svc.Authenticate(AuthRequest{DeviceID: dev.ID, TenantID: testTenant, KeyVersion: 9, Message: []byte("m"),
		Signature: signMessage(k.priv, []byte("m"))}); ErrorCodeOf(err) != ErrCodeKeyVersionNotFound {
		t.Fatalf("want key not found, got %v", err)
	}
	if err := env.svc.Authenticate(AuthRequest{DeviceID: dev.ID, TenantID: testTenant, KeyVersion: 1, Message: []byte("m"),
		Signature: make([]byte, 64)}); ErrorCodeOf(err) != ErrCodeSignatureInvalid {
		t.Fatalf("want signature invalid, got %v", err)
	}
}

func TestDisable_AtomicallyTerminatesDeviceAndRotations(t *testing.T) {
	env := newTestEnv(t, time.Minute, 10*time.Minute)
	oldK := mustKey(t)
	ch := env.issue(t, "dev-1", nil, 0)
	dev := mustRegister(t, env, ch, "dev-1", nil, oldK)
	newK := mustKey(t)
	rot := beginRotation(t, env, dev, oldK, newK)

	updated, err := env.svc.DisableDevice(dev.ID)
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	if updated.Status != DeviceStatusDisabled {
		t.Fatalf("status = %s", updated.Status)
	}

	// 注册有效性终止：认证一律拒绝。
	if err := env.svc.Authenticate(AuthRequest{DeviceID: dev.ID, TenantID: testTenant, KeyVersion: 1, Message: []byte("x"),
		Signature: signMessage(oldK.priv, []byte("x"))}); ErrorCodeOf(err) != ErrCodeDeviceDisabled {
		t.Fatalf("want disabled on auth, got %v", err)
	}
	// 全部密钥失效。
	for v, key := range env.svc.snap.Devices[dev.ID].Keys {
		if key.State != KeyStateInvalidated {
			t.Fatalf("key v%d state = %s, want invalidated", v, key.State)
		}
	}
	// 待处理轮换被原子中止。
	final := env.svc.snap.Rotations[rot.ID]
	if final.Status != RotationAborted || final.CompletedAt == nil {
		t.Fatalf("rotation status = %s, want aborted", final.Status)
	}
	if _, open := env.svc.snap.OpenRotation[dev.ID]; open {
		t.Fatal("aborted rotation still indexed as open")
	}
	// 终态后的迟到确认无效。
	if _, err := env.svc.ConfirmRotation(rot.ID,
		KeyConfirmation{1, signMessage(oldK.priv, confirmMsg(rot))},
		KeyConfirmation{2, signMessage(newK.priv, confirmMsg(rot))},
	); ErrorCodeOf(err) != ErrCodeRotationClosed {
		t.Fatalf("want closed, got %v", err)
	}

	// 重复禁用幂等。
	if _, err := env.svc.DisableDevice(dev.ID); err != nil {
		t.Fatalf("idempotent disable: %v", err)
	}
	// 禁用不存在的设备。
	if _, err := env.svc.DisableDevice("ghost"); ErrorCodeOf(err) != ErrCodeDeviceNotFound {
		t.Fatalf("want not found, got %v", err)
	}
}

// ---- 持久化 ----

func TestFileStore_Roundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	clock := NewFixedClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))

	svc, err := New(Config{Store: NewFileStore(path), Clock: clock,
		ChallengeTTL: time.Minute, RotationWindow: 10 * time.Minute})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	oldK := mustKey(t)
	ch, err := svc.IssueChallenge(testTenant, "dev-1", []byte("attr"), 0)
	if err != nil {
		t.Fatal(err)
	}
	att := signAttestation(oldK.priv, ch.ID, "dev-1", []byte("attr"))
	dev, err := svc.Register(RegisterRequest{
		ChallengeID: ch.ID, Secret: ch.Secret, ExternalID: "dev-1",
		Attributes: []byte("attr"), PublicKey: oldK.pub, Attestation: att,
	})
	if err != nil {
		t.Fatal(err)
	}
	newK := mustKey(t)
	rot, err := svc.BeginRotation(dev.ID, newK.pub,
		signMessage(oldK.priv, RotationBeginMessage(dev.ID, newK.pub)))
	if err != nil {
		t.Fatal(err)
	}

	// 用同一文件重新加载服务，状态必须完整恢复；随后完成轮换并持久化。
	svc2, err := New(Config{Store: NewFileStore(path), Clock: clock,
		ChallengeTTL: time.Minute, RotationWindow: 10 * time.Minute})
	if err != nil {
		t.Fatalf("reload New: %v", err)
	}
	got, err := svc2.GetDevice(dev.ID)
	if err != nil {
		t.Fatalf("device lost across reload: %v", err)
	}
	if got.ExternalID != "dev-1" || got.CurrentKeyVersion != 1 {
		t.Fatalf("reloaded device mismatch: %+v", got)
	}
	if _, err := svc2.ConfirmRotation(rot.ID,
		KeyConfirmation{1, signMessage(oldK.priv, confirmMsg(rot))},
		KeyConfirmation{2, signMessage(newK.priv, confirmMsg(rot))},
	); err != nil {
		t.Fatalf("confirm after reload: %v", err)
	}
	// 明文秘密仍未出现在磁盘文件里。
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(ch.Secret)) {
		t.Fatal("plaintext challenge secret present in snapshot file")
	}

	// 再次加载，轮换终态与新当前版本都应保留。
	svc3, err := New(Config{Store: NewFileStore(path), Clock: clock})
	if err != nil {
		t.Fatalf("second reload: %v", err)
	}
	got3, _ := svc3.GetDevice(dev.ID)
	if got3.CurrentKeyVersion != 2 || got3.Status != DeviceStatusActive {
		t.Fatalf("final state mismatch: %+v", got3)
	}
	if err := svc3.Authenticate(AuthRequest{DeviceID: dev.ID, TenantID: testTenant, KeyVersion: 2,
		Message:   []byte("after-restart"),
		Signature: signMessage(newK.priv, []byte("after-restart"))}); err != nil {
		t.Fatalf("auth with new key after restart: %v", err)
	}
}

// ---- HTTP 接口冒烟测试 ----

func TestHTTPHandler_EndToEnd(t *testing.T) {
	env := newTestEnv(t, time.Minute, 10*time.Minute)
	h := NewHandler(env.svc)
	srv := httptest.NewServer(h)
	defer srv.Close()

	oldK := mustKey(t)

	// 签发挑战。
	issueBody := map[string]string{
		"tenant_id":   testTenant,
		"external_id": "dev-http-1",
		"attributes":  EncodeBase64([]byte("attr")),
	}
	var ch Challenge
	doJSON(t, http.MethodPost, srv.URL+"/admin/challenges", http.StatusCreated, issueBody, &ch)

	// 注册。
	regBody := map[string]string{
		"challenge_id": ch.ID,
		"secret":       ch.Secret,
		"external_id":  "dev-http-1",
		"attributes":   EncodeBase64([]byte("attr")),
		"public_key":   EncodeBase64(oldK.pub),
		"attestation":  EncodeBase64(signAttestation(oldK.priv, ch.ID, "dev-http-1", []byte("attr"))),
	}
	var dev DeviceView
	doJSON(t, http.MethodPost, srv.URL+"/devices/register", http.StatusOK, regBody, &dev)

	// 幂等重放返回同一设备。
	var dev2 DeviceView
	doJSON(t, http.MethodPost, srv.URL+"/devices/register", http.StatusOK, regBody, &dev2)
	if dev2.ID != dev.ID {
		t.Fatal("idempotent replay over HTTP returned different device")
	}

	// 认证成功（204 无响应体）。
	authBody := map[string]any{
		"tenant_id":   testTenant,
		"key_version": 1,
		"message":     EncodeBase64([]byte("ping")),
		"signature":   EncodeBase64(signMessage(oldK.priv, []byte("ping"))),
	}
	doJSON(t, http.MethodPost, srv.URL+"/devices/"+dev.ID+"/authenticate", http.StatusNoContent, authBody, nil)

	// 发起并完成轮换。
	newK := mustKey(t)
	var rot RotationView
	doJSON(t, http.MethodPost, srv.URL+"/devices/"+dev.ID+"/rotations", http.StatusCreated, map[string]string{
		"new_public_key": EncodeBase64(newK.pub),
		"signature":      EncodeBase64(signMessage(oldK.priv, RotationBeginMessage(dev.ID, newK.pub))),
	}, &rot)
	doJSON(t, http.MethodPost, srv.URL+"/rotations/"+rot.ID+"/confirm", http.StatusOK, map[string]any{
		"confirmations": []map[string]any{
			{"key_version": 1, "signature": EncodeBase64(signMessage(oldK.priv, confirmMsg(&rot)))},
			{"key_version": 2, "signature": EncodeBase64(signMessage(newK.priv, confirmMsg(&rot)))},
		},
	}, &rot)
	if rot.Status != RotationConfirmed {
		t.Fatalf("rotation status over HTTP = %s", rot.Status)
	}

	// 旧钥认证 -> 409（key_version_invalid 映射冲突）。
	oldAuth := map[string]any{
		"tenant_id":   testTenant,
		"key_version": 1,
		"message":     EncodeBase64([]byte("late")),
		"signature":   EncodeBase64(signMessage(oldK.priv, []byte("late"))),
	}
	doJSON(t, http.MethodPost, srv.URL+"/devices/"+dev.ID+"/authenticate", http.StatusConflict, oldAuth, nil)

	// 禁用 -> 后续认证 403。
	doJSON(t, http.MethodPost, srv.URL+"/devices/"+dev.ID+"/disable", http.StatusOK, struct{}{}, nil)
	authBody2 := map[string]any{
		"tenant_id":   testTenant,
		"key_version": 2,
		"message":     EncodeBase64([]byte("x")),
		"signature":   EncodeBase64(signMessage(newK.priv, []byte("x"))),
	}
	doJSON(t, http.MethodPost, srv.URL+"/devices/"+dev.ID+"/authenticate", http.StatusForbidden, authBody2, nil)

	// 错误码出现在响应体中。
	var eb errorBody
	doJSON(t, http.MethodPost, srv.URL+"/devices/register", http.StatusUnauthorized, map[string]string{
		"challenge_id": ch.ID,
		"secret":       "wrong-secret",
		"external_id":  "dev-http-1",
		"attributes":   EncodeBase64([]byte("attr")),
		"public_key":   EncodeBase64(oldK.pub),
		"attestation":  EncodeBase64(signAttestation(oldK.priv, ch.ID, "dev-http-1", []byte("attr"))),
	}, &eb)
	if eb.Code != ErrCodeChallengeSecretMismatch {
		t.Fatalf("error code = %q", eb.Code)
	}
}

// ---- 测试辅助 ----

func doJSON(t *testing.T, method, url string, wantStatus int, body, out any) {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(resp.Body)
		t.Fatalf("%s %s status = %d, want %d, body=%s", method, url, resp.StatusCode, wantStatus, buf.String())
	}
	if out != nil && resp.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("decode response: %v", err)
		}
	}
}

func readFileOS(path string) ([]byte, error) {
	return os.ReadFile(path)
}
