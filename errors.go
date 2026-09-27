package deviceenrollment

import "errors"

// 服务对外暴露的错误按域分组，调用方可用 errors.Is 区分：
// 挑战、证明、密钥版本、状态、幂等冲突。
var (
	// 挑战相关。
	ErrChallengeNotFound          = errors.New("challenge not found")
	ErrChallengeExpired           = errors.New("challenge expired")
	ErrChallengeAlreadyConsumed   = errors.New("challenge already consumed")
	ErrChallengeSecretMismatch    = errors.New("challenge secret mismatch")
	ErrChallengeAttributeMismatch = errors.New("device attributes do not match challenge")

	// 证明（attestation / 持有性签名）相关。
	ErrAttestationInvalid = errors.New("attestation invalid")

	// 密钥版本相关。
	ErrStaleKeyVersion   = errors.New("stale key version")
	ErrUnknownKeyVersion = errors.New("unknown key version")

	// 状态相关。
	ErrDeviceNotFound        = errors.New("device not found")
	ErrDeviceDisabled        = errors.New("device disabled")
	ErrRotationNotFound      = errors.New("rotation not found")
	ErrRotationPendingExists = errors.New("a rotation is already pending for the device")
	ErrRotationFinalized     = errors.New("rotation already finalized")
	ErrRotationWindowExpired = errors.New("rotation confirmation window expired")

	// 幂等冲突：同一外部注册号携带了不同的注册内容。
	ErrEnrollmentConflict = errors.New("enrollment conflict: external id reused with different content")

	// 认证校验失败（签名无法通过当前密钥版本验证）。
	ErrAuthenticationFailed = errors.New("authentication failed")
)
