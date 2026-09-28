package deviceenrollment

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"time"
)

// Clock 是统一的当前时间来源。挑战是否过期、轮换确认窗口是否关闭全部经由它判断，
// 测试中可替换为可控时钟。
type Clock interface {
	Now() time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

// SystemClock 返回基于墙钟的 UTC 时钟。
func SystemClock() Clock { return systemClock{} }

// fixedClock 用于测试，始终返回设定时间。
type fixedClock struct{ t time.Time }

func (c *fixedClock) Now() time.Time { return c.t }

func (c *fixedClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// NewFixedClock 返回可手工推进的测试时钟。
func NewFixedClock(t time.Time) FixedClock {
	if t.IsZero() {
		t = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	return &fixedClock{t: t.UTC()}
}

// FixedClock 是可控时钟，供测试使用。
type FixedClock interface {
	Clock
	// Advance 将当前时间向后推移 d。
	Advance(d time.Duration)
}

func (c *fixedClock) Advance(d time.Duration) { c.advance(d) }

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("deviceenrollment: crypto/rand failed: %v", err))
	}
	return b
}

func randomID() string {
	return base64.RawURLEncoding.EncodeToString(randomBytes(18))
}

func randomSecret() string {
	return base64.RawURLEncoding.EncodeToString(randomBytes(32))
}

// digestSecret 计算挑战秘密的加盐 SHA-256 摘要。明文秘密绝不存储。
func digestSecret(salt []byte, secret string) []byte {
	mac := hmac.New(sha256.New, salt)
	mac.Write([]byte(secret))
	return mac.Sum(nil)
}

func secretMatches(record *ChallengeRecord, secret string) bool {
	return subtle.ConstantTimeCompare(record.SecretDigest, digestSecret(record.Salt, secret)) == 1
}

// attestationMessage 是注册时设备需要用初始私钥签名的规范报文。
func attestationMessage(challengeID, externalID string, attributes, publicKey []byte) []byte {
	msg := make([]byte, 0, len("ENROLL|")+len(challengeID)+len(externalID)+len(attributes)+len(publicKey)+4)
	msg = append(msg, "ENROLL|"...)
	msg = append(msg, challengeID...)
	msg = append(msg, '|')
	msg = append(msg, externalID...)
	msg = append(msg, '|')
	msg = append(msg, attributes...)
	msg = append(msg, '|')
	msg = append(msg, publicKey...)
	return msg
}

// verifyAttestation 用注册公钥校验证明签名。证明内容绑定挑战号、外部注册号、
// 设备属性与公钥本身，确保私钥持有者确实在为这组属性与公钥完成注册。
func verifyAttestation(challengeID, externalID string, attributes, publicKey, signature []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(publicKey),
		attestationMessage(challengeID, externalID, attributes, publicKey), signature)
}

// signAttestation 用设备私钥生成注册证明，供客户端/测试使用。
func signAttestation(priv ed25519.PrivateKey, challengeID, externalID string, attributes []byte) []byte {
	pub := priv.Public().(ed25519.PublicKey)
	return ed25519.Sign(priv, attestationMessage(challengeID, externalID, attributes, pub))
}

// signMessage 用设备私钥对业务报文（认证请求/轮换确认）签名。
func signMessage(priv ed25519.PrivateKey, message []byte) []byte {
	return ed25519.Sign(priv, message)
}

// verifyMessage 用指定公钥校验业务报文签名。
func verifyMessage(pub, message, signature []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), message, signature)
}

// GenerateDeviceKey 生成一把 ed25519 设备密钥，返回 (公钥, 私钥)，便于测试与示例。
// 熵源失败属于不可恢复的系统错误，直接 panic。
func GenerateDeviceKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("deviceenrollment: ed25519 key generation failed: %v", err))
	}
	return pub, priv
}

// contentHash 对注册内容（属性 + 初始公钥）取摘要，用于同号异内容冲突判定。
func contentHash(attributes, publicKey []byte) string {
	h := sha256.New()
	h.Write(attributes)
	h.Write([]byte{0})
	h.Write(publicKey)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// hashFields 对带前缀的若干字段做分隔摘要，用于转移幂等内容的一致性判定。
func hashFields(prefix string, fields ...[]byte) string {
	h := sha256.New()
	h.Write([]byte(prefix))
	for _, f := range fields {
		h.Write([]byte{0})
		h.Write(f)
	}
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
