package deviceenrollment

import (
	"errors"
	"fmt"
)

// ErrorCode 把失败原因结构化表达出来，便于接口层映射为状态码。
type ErrorCode string

const (
	// ErrCodeInvalidArgument 入参非法。
	ErrCodeInvalidArgument ErrorCode = "invalid_argument"
	// ErrCodeChallengeNotFound 挑战不存在（或无法被当前请求找到）。
	ErrCodeChallengeNotFound ErrorCode = "challenge_not_found"
	// ErrCodeChallengeExpired 挑战已超过有效期。
	ErrCodeChallengeExpired ErrorCode = "challenge_expired"
	// ErrCodeChallengeConsumed 挑战已被成功消费，不可二次使用。
	ErrCodeChallengeConsumed ErrorCode = "challenge_consumed"
	// ErrCodeChallengeSecretMismatch 挑战秘密校验失败。
	ErrCodeChallengeSecretMismatch ErrorCode = "challenge_secret_mismatch"
	// ErrCodeChallengeAttributeMismatch 注册载荷与挑战绑定的预期设备属性不一致。
	ErrCodeChallengeAttributeMismatch ErrorCode = "challenge_attribute_mismatch"
	// ErrCodeAttestationFailed 设备证明校验失败。
	ErrCodeAttestationFailed ErrorCode = "attestation_failed"
	// ErrCodeDeviceNotFound 设备不存在。
	ErrCodeDeviceNotFound ErrorCode = "device_not_found"
	// ErrCodeDeviceDisabled 设备已禁用。
	ErrCodeDeviceDisabled ErrorCode = "device_disabled"
	// ErrCodeConflict 幂等冲突：外部注册号相同但注册内容不同。
	ErrCodeConflict ErrorCode = "idempotency_conflict"
	// ErrCodeKeyVersionNotFound 引用的密钥版本不存在。
	ErrCodeKeyVersionNotFound ErrorCode = "key_version_not_found"
	// ErrCodeKeyVersionInvalid 引用的密钥版本已失效或尚不能用于该操作。
	ErrCodeKeyVersionInvalid ErrorCode = "key_version_invalid"
	// ErrCodeRotationInProgress 设备已有未终态的轮换，不能重复发起。
	ErrCodeRotationInProgress ErrorCode = "rotation_in_progress"
	// ErrCodeRotationNotFound 轮换单不存在。
	ErrCodeRotationNotFound ErrorCode = "rotation_not_found"
	// ErrCodeRotationClosed 轮换已处于终态（确认/取消/超时/中止），拒绝迟到操作。
	ErrCodeRotationClosed ErrorCode = "rotation_closed"
	// ErrCodeSignatureInvalid 认证或确认所附签名校验失败。
	ErrCodeSignatureInvalid ErrorCode = "signature_invalid"
	// ErrCodeTransferNotFound 转移单不存在。
	ErrCodeTransferNotFound ErrorCode = "transfer_not_found"
	// ErrCodeTransferClosed 转移已处于终态（接收/取消/过期/中止），拒绝迟到操作。
	ErrCodeTransferClosed ErrorCode = "transfer_closed"
	// ErrCodeTransferInProgress 设备已有活动转移，相关操作被拒绝。
	ErrCodeTransferInProgress ErrorCode = "transfer_in_progress"
	// ErrCodeTransferVersionMismatch 接收时设备当前密钥版本与发起时冻结的版本不一致。
	ErrCodeTransferVersionMismatch ErrorCode = "transfer_version_mismatch"
	// ErrCodeTransferTenantMismatch 请求租户与转移单记载的源/目标租户不符。
	ErrCodeTransferTenantMismatch ErrorCode = "transfer_tenant_mismatch"
	// ErrCodeCredentialMismatch 一次性接收凭据校验失败。
	ErrCodeCredentialMismatch ErrorCode = "credential_mismatch"
	// ErrCodeCredentialExpired 一次性接收凭据已超过有效期。
	ErrCodeCredentialExpired ErrorCode = "credential_expired"
)

// Error 携带错误码的领域错误。
type Error struct {
	Code    ErrorCode
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func newError(code ErrorCode, format string, args ...any) error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// ErrorCodeOf 提取领域错误码；非领域错误返回空串。
func ErrorCodeOf(err error) ErrorCode {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}
