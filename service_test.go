package deviceenrollment

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeClock 是测试用的可控时钟，与生产路径共用同一个 Clock 接口，
// 保证过期判断走的是统一时间来源。
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)}
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *fakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = f.t.Add(d)
}

type testEnv struct {
	svc   *Service
	store *MemoryStore
	clock *fakeClock
}

func newTestEnv() *testEnv {
	store := NewMemoryStore()
	clock := newFakeClock()
	svc := NewService(store, clock, Config{
		ChallengeTTL:   time.Minute,
		RotationWindow: 2 * time.Minute,
	})
	return &testEnv{svc: svc, store: store, clock: clock}
}

func mustKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

var testAttrs = DeviceAttributes{Model: "sensor-x", Serial: "SN-001"}

// issueAndBuildRequest 签发挑战并构造一个合法的注册请求。
func (e *testEnv) issueAndBuildRequest(t *testing.T, externalID string, attrs DeviceAttributes) (EnrollRequest, ed25519.PrivateKey) {
	t.Helper()
	challengeID, secret, err := e.svc.IssueChallenge(attrs)
	if err != nil {
		t.Fatalf("issue challenge: %v", err)
	}
	pub, priv := mustKey(t)
	return EnrollRequest{
		ChallengeID: challengeID,
		Secret:      secret,
		ExternalID:  externalID,
		Attributes:  attrs,
		PublicKey:   pub,
		Attestation: ed25519.Sign(priv, EnrollmentMessage(challengeID, externalID)),
	}, priv
}

func (e *testEnv) mustEnroll(t *testing.T, externalID string) (*Device, ed25519.PrivateKey) {
	t.Helper()
	req, priv := e.issueAndBuildRequest(t, externalID, testAttrs)
	dev, err := e.svc.Enroll(req)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	return dev, priv
}

// ---- 挑战 ----

func TestIssueChallengeStoresOnlyDigest(t *testing.T) {
	e := newTestEnv()
	id, secret, err := e.svc.IssueChallenge(testAttrs)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	ch, ok := e.store.GetChallenge(id)
	if !ok {
		t.Fatal("challenge not persisted")
	}
	if ch.Consumed {
		t.Fatal("new challenge must not be consumed")
	}
	want := sha256.Sum256([]byte(secret))
	if ch.SecretHash != want {
		t.Fatal("stored value is not the SHA-256 digest of the secret")
	}
	// 摘要不应等于明文秘密的任何直接编码形式。
	if string(ch.SecretHash[:]) == secret {
		t.Fatal("plaintext secret appears to be stored")
	}
	if !ch.ExpiresAt.Equal(e.clock.Now().Add(time.Minute)) {
		t.Fatalf("unexpected expiry: %v", ch.ExpiresAt)
	}
}

func TestEnrollSuccess(t *testing.T) {
	e := newTestEnv()
	dev, _ := e.mustEnroll(t, "ext-1")
	if dev.Status != DeviceStatusActive {
		t.Fatalf("status = %s", dev.Status)
	}
	if dev.CurrentKeyVersion != 1 {
		t.Fatalf("key version = %d", dev.CurrentKeyVersion)
	}
	kv, ok := e.store.GetKeyVersion(dev.ID, 1)
	if !ok || kv.Status != KeyStatusActive {
		t.Fatal("initial key version missing or not active")
	}
}

func TestEnrollChallengeNotFound(t *testing.T) {
	e := newTestEnv()
	req, _ := e.issueAndBuildRequest(t, "ext-1", testAttrs)
	req.ChallengeID = "no-such-challenge"
	if _, err := e.svc.Enroll(req); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestEnrollExpiredChallenge(t *testing.T) {
	e := newTestEnv()
	req, _ := e.issueAndBuildRequest(t, "ext-1", testAttrs)
	e.clock.Advance(time.Minute + time.Second)
	if _, err := e.svc.Enroll(req); !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("err = %v", err)
	}
}

func TestEnrollWrongSecret(t *testing.T) {
	e := newTestEnv()
	req, _ := e.issueAndBuildRequest(t, "ext-1", testAttrs)
	req.Secret = "wrong-secret"
	if _, err := e.svc.Enroll(req); !errors.Is(err, ErrChallengeSecretMismatch) {
		t.Fatalf("err = %v", err)
	}
}

func TestEnrollAttributeMismatch(t *testing.T) {
	e := newTestEnv()
	req, _ := e.issueAndBuildRequest(t, "ext-1", testAttrs)
	req.Attributes = DeviceAttributes{Model: "sensor-y", Serial: "SN-001"}
	if _, err := e.svc.Enroll(req); !errors.Is(err, ErrChallengeAttributeMismatch) {
		t.Fatalf("err = %v", err)
	}
}

func TestEnrollInvalidAttestation(t *testing.T) {
	e := newTestEnv()
	req, _ := e.issueAndBuildRequest(t, "ext-1", testAttrs)
	_, otherPriv := mustKey(t)
	req.Attestation = ed25519.Sign(otherPriv, EnrollmentMessage(req.ChallengeID, req.ExternalID))
	if _, err := e.svc.Enroll(req); !errors.Is(err, ErrAttestationInvalid) {
		t.Fatalf("err = %v", err)
	}
}

func TestEnrollChallengeConsumedOnce(t *testing.T) {
	e := newTestEnv()
	req, _ := e.issueAndBuildRequest(t, "ext-1", testAttrs)
	if _, err := e.svc.Enroll(req); err != nil {
		t.Fatalf("first enroll: %v", err)
	}
	// 换一个外部注册号复用同一挑战：必须被拒绝。
	pub2, priv2 := mustKey(t)
	req2 := EnrollRequest{
		ChallengeID: req.ChallengeID,
		Secret:      req.Secret,
		ExternalID:  "ext-2",
		Attributes:  testAttrs,
		PublicKey:   pub2,
		Attestation: ed25519.Sign(priv2, EnrollmentMessage(req.ChallengeID, "ext-2")),
	}
	if _, err := e.svc.Enroll(req2); !errors.Is(err, ErrChallengeAlreadyConsumed) {
		t.Fatalf("err = %v", err)
	}
}

func TestEnrollIdempotentReplay(t *testing.T) {
	e := newTestEnv()
	req, _ := e.issueAndBuildRequest(t, "ext-1", testAttrs)
	first, err := e.svc.Enroll(req)
	if err != nil {
		t.Fatalf("first enroll: %v", err)
	}
	// 挑战已被消费，但同号同内容的重复调用应返回原设备身份。
	second, err := e.svc.Enroll(req)
	if err != nil {
		t.Fatalf("replay enroll: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("replay returned different device: %s vs %s", second.ID, first.ID)
	}
}

func TestEnrollConflictSameExternalIDDifferentContent(t *testing.T) {
	e := newTestEnv()
	e.mustEnroll(t, "ext-1")
	// 同一外部注册号、不同内容（不同挑战/公钥）。
	req2, _ := e.issueAndBuildRequest(t, "ext-1", testAttrs)
	if _, err := e.svc.Enroll(req2); !errors.Is(err, ErrEnrollmentConflict) {
		t.Fatalf("err = %v", err)
	}
}

func TestEnrollConcurrentSameChallenge(t *testing.T) {
	e := newTestEnv()
	challengeID, secret, err := e.svc.IssueChallenge(testAttrs)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	const n = 16
	var wg sync.WaitGroup
	errs := make([]error, n)
	ids := make([]string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			pub, priv, _ := ed25519.GenerateKey(rand.Reader)
			externalID := "ext-concurrent-" + string(rune('a'+i))
			dev, err := e.svc.Enroll(EnrollRequest{
				ChallengeID: challengeID,
				Secret:      secret,
				ExternalID:  externalID,
				Attributes:  testAttrs,
				PublicKey:   pub,
				Attestation: ed25519.Sign(priv, EnrollmentMessage(challengeID, externalID)),
			})
			errs[i] = err
			if dev != nil {
				ids[i] = dev.ID
			}
		}(i)
	}
	wg.Wait()

	succeeded := 0
	for i, err := range errs {
		if err == nil {
			succeeded++
			continue
		}
		if !errors.Is(err, ErrChallengeAlreadyConsumed) {
			t.Fatalf("goroutine %d got unexpected err = %v", i, err)
		}
	}
	if succeeded != 1 {
		t.Fatalf("expected exactly 1 success, got %d", succeeded)
	}
}

// ---- 密钥轮换 ----

func signRotation(t *testing.T, priv ed25519.PrivateKey, rotationID string) []byte {
	t.Helper()
	return ed25519.Sign(priv, RotationMessage(rotationID))
}

func TestRotationConfirmSuccess(t *testing.T) {
	e := newTestEnv()
	dev, oldPriv := e.mustEnroll(t, "ext-1")

	newPub, newPriv := mustKey(t)
	rot, err := e.svc.StartRotation(dev.ID, newPub)
	if err != nil {
		t.Fatalf("start rotation: %v", err)
	}
	if rot.OldVersion != 1 || rot.NewVersion != 2 {
		t.Fatalf("unexpected versions: %d -> %d", rot.OldVersion, rot.NewVersion)
	}

	confirmed, err := e.svc.ConfirmRotation(rot.ID,
		signRotation(t, oldPriv, rot.ID),
		signRotation(t, newPriv, rot.ID),
	)
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if confirmed.State != RotationConfirmed {
		t.Fatalf("state = %s", confirmed.State)
	}

	after, _ := e.svc.GetDevice(dev.ID)
	if after.CurrentKeyVersion != 2 {
		t.Fatalf("current key version = %d", after.CurrentKeyVersion)
	}
	oldKV, _ := e.store.GetKeyVersion(dev.ID, 1)
	if oldKV.Status != KeyStatusSuperseded {
		t.Fatalf("old key status = %s", oldKV.Status)
	}

	// 旧密钥版本的迟到认证请求必须被拒绝，且不影响新状态。
	err = e.svc.Authenticate(dev.ID, 1, "nonce", ed25519.Sign(oldPriv, AuthMessage(dev.ID, "nonce")))
	if !errors.Is(err, ErrStaleKeyVersion) {
		t.Fatalf("stale auth err = %v", err)
	}
	// 新版本认证通过。
	err = e.svc.Authenticate(dev.ID, 2, "nonce", ed25519.Sign(newPriv, AuthMessage(dev.ID, "nonce")))
	if err != nil {
		t.Fatalf("auth with new key: %v", err)
	}
	if final, _ := e.svc.GetDevice(dev.ID); final.CurrentKeyVersion != 2 {
		t.Fatal("stale request mutated device state")
	}
}

func TestRotationConfirmRequiresBothKeys(t *testing.T) {
	e := newTestEnv()
	dev, oldPriv := e.mustEnroll(t, "ext-1")
	newPub, _ := mustKey(t)
	rot, err := e.svc.StartRotation(dev.ID, newPub)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	// 新钥签名无效。
	_, strangerPriv := mustKey(t)
	_, err = e.svc.ConfirmRotation(rot.ID,
		signRotation(t, oldPriv, rot.ID),
		signRotation(t, strangerPriv, rot.ID),
	)
	if !errors.Is(err, ErrAttestationInvalid) {
		t.Fatalf("err = %v", err)
	}
	// 轮换仍处于 pending，可以用正确签名再次确认。
	if r, _ := e.svc.GetRotation(rot.ID); r.State != RotationPending {
		t.Fatalf("state = %s", r.State)
	}
}

func TestRotationWindowExpiry(t *testing.T) {
	e := newTestEnv()
	dev, oldPriv := e.mustEnroll(t, "ext-1")
	newPub, newPriv := mustKey(t)
	rot, _ := e.svc.StartRotation(dev.ID, newPub)

	e.clock.Advance(2*time.Minute + time.Second)
	_, err := e.svc.ConfirmRotation(rot.ID,
		signRotation(t, oldPriv, rot.ID),
		signRotation(t, newPriv, rot.ID),
	)
	if !errors.Is(err, ErrRotationWindowExpired) {
		t.Fatalf("err = %v", err)
	}
	if r, _ := e.svc.GetRotation(rot.ID); r.State != RotationExpired {
		t.Fatalf("state = %s", r.State)
	}
	// 旧钥仍然有效：超时未确认的轮换不改变当前密钥。
	after, _ := e.svc.GetDevice(dev.ID)
	if after.CurrentKeyVersion != 1 {
		t.Fatalf("current key version = %d", after.CurrentKeyVersion)
	}
}

func TestRotationCancelThenConfirmSingleTerminalState(t *testing.T) {
	e := newTestEnv()
	dev, oldPriv := e.mustEnroll(t, "ext-1")
	newPub, newPriv := mustKey(t)
	rot, _ := e.svc.StartRotation(dev.ID, newPub)

	if _, err := e.svc.CancelRotation(rot.ID); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	_, err := e.svc.ConfirmRotation(rot.ID,
		signRotation(t, oldPriv, rot.ID),
		signRotation(t, newPriv, rot.ID),
	)
	if !errors.Is(err, ErrRotationFinalized) {
		t.Fatalf("err = %v", err)
	}
	if r, _ := e.svc.GetRotation(rot.ID); r.State != RotationCancelled {
		t.Fatalf("state = %s", r.State)
	}
}

func TestRotationConcurrentConfirmAndCancel(t *testing.T) {
	for trial := 0; trial < 20; trial++ {
		e := newTestEnv()
		dev, oldPriv := e.mustEnroll(t, "ext-1")
		newPub, newPriv := mustKey(t)
		rot, _ := e.svc.StartRotation(dev.ID, newPub)

		var wg sync.WaitGroup
		errs := make([]error, 2)
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, errs[0] = e.svc.ConfirmRotation(rot.ID,
				signRotation(t, oldPriv, rot.ID),
				signRotation(t, newPriv, rot.ID),
			)
		}()
		go func() {
			defer wg.Done()
			_, errs[1] = e.svc.CancelRotation(rot.ID)
		}()
		wg.Wait()

		succeeded := 0
		for _, err := range errs {
			if err == nil {
				succeeded++
			} else if !errors.Is(err, ErrRotationFinalized) {
				t.Fatalf("unexpected err = %v", err)
			}
		}
		if succeeded != 1 {
			t.Fatalf("trial %d: expected exactly one winner, got %d", trial, succeeded)
		}
		r, _ := e.svc.GetRotation(rot.ID)
		if r.State != RotationConfirmed && r.State != RotationCancelled {
			t.Fatalf("trial %d: unexpected final state %s", trial, r.State)
		}
	}
}

func TestStartRotationRejectedWhilePending(t *testing.T) {
	e := newTestEnv()
	dev, _ := e.mustEnroll(t, "ext-1")
	newPub, _ := mustKey(t)
	if _, err := e.svc.StartRotation(dev.ID, newPub); err != nil {
		t.Fatalf("start: %v", err)
	}
	if _, err := e.svc.StartRotation(dev.ID, newPub); !errors.Is(err, ErrRotationPendingExists) {
		t.Fatalf("err = %v", err)
	}
	// 窗口过后，旧轮换自动过期，可以开启新轮换。
	e.clock.Advance(2*time.Minute + time.Second)
	rot2, err := e.svc.StartRotation(dev.ID, newPub)
	if err != nil {
		t.Fatalf("start after expiry: %v", err)
	}
	if rot2.NewVersion != 2 {
		t.Fatalf("new version = %d", rot2.NewVersion)
	}
}

// ---- 禁用 ----

func TestDisableDeviceTerminatesEnrollmentAndRotations(t *testing.T) {
	e := newTestEnv()
	dev, oldPriv := e.mustEnroll(t, "ext-1")
	newPub, _ := mustKey(t)
	rot, _ := e.svc.StartRotation(dev.ID, newPub)

	disabled, err := e.svc.DisableDevice(dev.ID)
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	if disabled.Status != DeviceStatusDisabled {
		t.Fatalf("status = %s", disabled.Status)
	}

	// 待处理轮换被原子终止。
	if r, _ := e.svc.GetRotation(rot.ID); r.State != RotationCancelled {
		t.Fatalf("rotation state = %s", r.State)
	}
	// 所有密钥版本被吊销。
	for _, kv := range e.store.ListKeyVersions(dev.ID) {
		if kv.Status != KeyStatusRevoked {
			t.Fatalf("key version %d status = %s", kv.Version, kv.Status)
		}
	}
	// 认证被拒绝。
	err = e.svc.Authenticate(dev.ID, 1, "n", ed25519.Sign(oldPriv, AuthMessage(dev.ID, "n")))
	if !errors.Is(err, ErrDeviceDisabled) {
		t.Fatalf("auth err = %v", err)
	}
	// 重复禁用是幂等的。
	if _, err := e.svc.DisableDevice(dev.ID); err != nil {
		t.Fatalf("re-disable: %v", err)
	}
}

// ---- 认证校验 ----

func TestAuthenticate(t *testing.T) {
	e := newTestEnv()
	dev, priv := e.mustEnroll(t, "ext-1")

	if err := e.svc.Authenticate(dev.ID, 1, "nonce-1", ed25519.Sign(priv, AuthMessage(dev.ID, "nonce-1"))); err != nil {
		t.Fatalf("auth: %v", err)
	}
	// 签名错误。
	if err := e.svc.Authenticate(dev.ID, 1, "nonce-1", []byte("bad")); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("err = %v", err)
	}
	// 不存在的密钥版本。
	if err := e.svc.Authenticate(dev.ID, 99, "nonce-1", nil); !errors.Is(err, ErrStaleKeyVersion) {
		t.Fatalf("err = %v", err)
	}
	// 设备不存在。
	if err := e.svc.Authenticate("no-such-device", 1, "n", nil); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("err = %v", err)
	}
}
