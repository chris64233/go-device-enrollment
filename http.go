package deviceenrollment

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"
)

// HTTP 接口把领域服务暴露为 REST/JSON 接口。所有字节串（属性、公钥、签名、报文）
// 均使用 base64 RawURLEncoding 编解码。
//
//	POST   /admin/challenges                 管理员为租户签发挑战
//	POST   /devices/register                 设备注册（幂等）
//	GET    /devices/{id}                     查询设备
//	POST   /devices/{id}/rotations           发起密钥轮换
//	POST   /devices/{id}/disable             管理员禁用设备
//	POST   /devices/{id}/authenticate        认证校验
//	GET    /devices/{id}/ownership           查询归属链与转移历史
//	GET    /rotations/{id}                   查询轮换单
//	POST   /rotations/{id}/confirm           提交旧/新钥确认
//	POST   /rotations/{id}/cancel            取消轮换
//	POST   /admin/rotations/sweep            结算超时轮换
//	POST   /devices/{id}/transfers           源租户发起跨租户转移
//	POST   /transfers/{id}/accept            目标租户接收设备
//	POST   /transfers/{id}/cancel            源租户取消转移
//	GET    /transfers/{id}                   查询转移单
//	POST   /admin/transfers/sweep            结算过期转移凭据
type Handler struct {
	service *Service
	mux     *http.ServeMux
}

// NewHandler 基于服务构造 HTTP 处理器。
func NewHandler(s *Service) *Handler {
	h := &Handler{service: s, mux: http.NewServeMux()}
	h.routes()
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) routes() {
	h.mux.HandleFunc("POST /admin/challenges", h.issueChallenge)
	h.mux.HandleFunc("POST /admin/rotations/sweep", h.sweepRotations)
	h.mux.HandleFunc("POST /admin/transfers/sweep", h.sweepTransfers)
	h.mux.HandleFunc("POST /devices/register", h.register)
	h.mux.HandleFunc("GET /devices/{id}", h.getDevice)
	h.mux.HandleFunc("GET /devices/{id}/ownership", h.getOwnership)
	h.mux.HandleFunc("POST /devices/{id}/rotations", h.beginRotation)
	h.mux.HandleFunc("POST /devices/{id}/disable", h.disableDevice)
	h.mux.HandleFunc("POST /devices/{id}/authenticate", h.authenticate)
	h.mux.HandleFunc("POST /devices/{id}/transfers", h.beginTransfer)
	h.mux.HandleFunc("GET /rotations/{id}", h.getRotation)
	h.mux.HandleFunc("POST /rotations/{id}/confirm", h.confirmRotation)
	h.mux.HandleFunc("POST /rotations/{id}/cancel", h.cancelRotation)
	h.mux.HandleFunc("GET /transfers/{id}", h.getTransfer)
	h.mux.HandleFunc("POST /transfers/{id}/accept", h.acceptTransfer)
	h.mux.HandleFunc("POST /transfers/{id}/cancel", h.cancelTransfer)
}

type issueChallengeRequest struct {
	TenantID   string `json:"tenant_id"`
	ExternalID string `json:"external_id"`
	Attributes string `json:"attributes"`
	// TTL 为 Go duration 字符串（如 "5m"）；空串使用服务默认值。
	TTL string `json:"ttl"`
}

func (h *Handler) issueChallenge(w http.ResponseWriter, r *http.Request) {
	var req issueChallengeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	attrs, err := decodeBase64(req.Attributes)
	if err != nil {
		writeError(w, newError(ErrCodeInvalidArgument, "attributes must be base64: %v", err))
		return
	}
	var ttl time.Duration
	if req.TTL != "" {
		ttl, err = time.ParseDuration(req.TTL)
		if err != nil {
			writeError(w, newError(ErrCodeInvalidArgument, "invalid ttl: %v", err))
			return
		}
	}
	ch, err := h.service.IssueChallenge(req.TenantID, req.ExternalID, attrs, ttl)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, ch)
}

type registerHTTPRequest struct {
	ChallengeID string `json:"challenge_id"`
	Secret      string `json:"secret"`
	ExternalID  string `json:"external_id"`
	Attributes  string `json:"attributes"`
	PublicKey   string `json:"public_key"`
	Attestation string `json:"attestation"`
}

func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	var in registerHTTPRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	pub, err := decodeBase64(in.PublicKey)
	if err != nil {
		writeError(w, newError(ErrCodeInvalidArgument, "public_key must be base64: %v", err))
		return
	}
	attrs, err := decodeBase64(in.Attributes)
	if err != nil {
		writeError(w, newError(ErrCodeInvalidArgument, "attributes must be base64: %v", err))
		return
	}
	att, err := decodeBase64(in.Attestation)
	if err != nil {
		writeError(w, newError(ErrCodeInvalidArgument, "attestation must be base64: %v", err))
		return
	}
	view, err := h.service.Register(RegisterRequest{
		ChallengeID: in.ChallengeID,
		Secret:      in.Secret,
		ExternalID:  in.ExternalID,
		Attributes:  attrs,
		PublicKey:   pub,
		Attestation: att,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (h *Handler) getDevice(w http.ResponseWriter, r *http.Request) {
	view, err := h.service.GetDevice(r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

type beginRotationHTTPRequest struct {
	NewPublicKey string `json:"new_public_key"`
	Signature    string `json:"signature"`
}

func (h *Handler) beginRotation(w http.ResponseWriter, r *http.Request) {
	var in beginRotationHTTPRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	newPub, err := decodeBase64(in.NewPublicKey)
	if err != nil {
		writeError(w, newError(ErrCodeInvalidArgument, "new_public_key must be base64: %v", err))
		return
	}
	sig, err := decodeBase64(in.Signature)
	if err != nil {
		writeError(w, newError(ErrCodeInvalidArgument, "signature must be base64: %v", err))
		return
	}
	view, err := h.service.BeginRotation(r.PathValue("id"), newPub, sig)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, view)
}

func (h *Handler) disableDevice(w http.ResponseWriter, r *http.Request) {
	view, err := h.service.DisableDevice(r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

type authHTTPRequest struct {
	TenantID   string `json:"tenant_id"`
	KeyVersion int    `json:"key_version"`
	Message    string `json:"message"`
	Signature  string `json:"signature"`
}

func (h *Handler) authenticate(w http.ResponseWriter, r *http.Request) {
	var in authHTTPRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	msg, err := decodeBase64(in.Message)
	if err != nil {
		writeError(w, newError(ErrCodeInvalidArgument, "message must be base64: %v", err))
		return
	}
	sig, err := decodeBase64(in.Signature)
	if err != nil {
		writeError(w, newError(ErrCodeInvalidArgument, "signature must be base64: %v", err))
		return
	}
	if err := h.service.Authenticate(AuthRequest{
		DeviceID:   r.PathValue("id"),
		TenantID:   in.TenantID,
		KeyVersion: in.KeyVersion,
		Message:    msg,
		Signature:  sig,
	}); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusNoContent, nil)
}

func (h *Handler) getRotation(w http.ResponseWriter, r *http.Request) {
	view, err := h.service.GetRotation(r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

type confirmationHTTP struct {
	KeyVersion int    `json:"key_version"`
	Signature  string `json:"signature"`
}

type confirmRotationHTTPRequest struct {
	Confirmations []confirmationHTTP `json:"confirmations"`
}

func (h *Handler) confirmRotation(w http.ResponseWriter, r *http.Request) {
	var in confirmRotationHTTPRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	confirmations := make([]KeyConfirmation, 0, len(in.Confirmations))
	for _, c := range in.Confirmations {
		sig, err := decodeBase64(c.Signature)
		if err != nil {
			writeError(w, newError(ErrCodeInvalidArgument, "confirmation signature must be base64: %v", err))
			return
		}
		confirmations = append(confirmations, KeyConfirmation{KeyVersion: c.KeyVersion, Signature: sig})
	}
	view, err := h.service.ConfirmRotation(r.PathValue("id"), confirmations...)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

type cancelRotationHTTPRequest struct {
	Signature string `json:"signature"`
}

func (h *Handler) cancelRotation(w http.ResponseWriter, r *http.Request) {
	var in cancelRotationHTTPRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	sig, err := decodeBase64(in.Signature)
	if err != nil {
		writeError(w, newError(ErrCodeInvalidArgument, "signature must be base64: %v", err))
		return
	}
	view, err := h.service.CancelRotation(r.PathValue("id"), sig)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (h *Handler) getOwnership(w http.ResponseWriter, r *http.Request) {
	hist, err := h.service.GetOwnershipHistory(r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, hist)
}

type beginTransferHTTPRequest struct {
	RequestID    string `json:"request_id"`
	SourceTenant string `json:"source_tenant"`
	TargetTenant string `json:"target_tenant"`
	TTL          string `json:"ttl"`
}

func (h *Handler) beginTransfer(w http.ResponseWriter, r *http.Request) {
	var in beginTransferHTTPRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	var ttl time.Duration
	if in.TTL != "" {
		var err error
		ttl, err = time.ParseDuration(in.TTL)
		if err != nil {
			writeError(w, newError(ErrCodeInvalidArgument, "invalid ttl: %v", err))
			return
		}
	}
	view, secret, err := h.service.BeginTransfer(in.RequestID, r.PathValue("id"), in.SourceTenant, in.TargetTenant, ttl)
	if err != nil {
		writeError(w, err)
		return
	}
	// 凭据明文仅在首次创建的这一次响应中出现。
	writeJSON(w, http.StatusCreated, map[string]any{
		"transfer":   view,
		"credential": secret,
	})
}

type acceptTransferHTTPRequest struct {
	Credential   string `json:"credential"`
	TargetTenant string `json:"target_tenant"`
	NewPublicKey string `json:"new_public_key"`
	Attestation  string `json:"attestation"`
}

func (h *Handler) acceptTransfer(w http.ResponseWriter, r *http.Request) {
	var in acceptTransferHTTPRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	newPub, err := decodeBase64(in.NewPublicKey)
	if err != nil {
		writeError(w, newError(ErrCodeInvalidArgument, "new_public_key must be base64: %v", err))
		return
	}
	att, err := decodeBase64(in.Attestation)
	if err != nil {
		writeError(w, newError(ErrCodeInvalidArgument, "attestation must be base64: %v", err))
		return
	}
	view, err := h.service.AcceptTransfer(AcceptTransferRequest{
		TransferID:   r.PathValue("id"),
		Credential:   in.Credential,
		TargetTenant: in.TargetTenant,
		NewPublicKey: newPub,
		Attestation:  att,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

type cancelTransferHTTPRequest struct {
	SourceTenant string `json:"source_tenant"`
}

func (h *Handler) cancelTransfer(w http.ResponseWriter, r *http.Request) {
	var in cancelTransferHTTPRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	view, err := h.service.CancelTransfer(r.PathValue("id"), in.SourceTenant)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (h *Handler) getTransfer(w http.ResponseWriter, r *http.Request) {
	view, err := h.service.GetTransfer(r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (h *Handler) sweepTransfers(w http.ResponseWriter, r *http.Request) {
	n, err := h.service.SweepExpiredTransfers()
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"expired": n})
}

func (h *Handler) sweepRotations(w http.ResponseWriter, r *http.Request) {
	n, err := h.service.SweepExpiredRotations()
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"timed_out": n})
}

// ---- 辅助 ----

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, newError(ErrCodeInvalidArgument, "invalid JSON body: %v", err))
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	enc := json.NewEncoder(w)
	_ = enc.Encode(v)
}

type errorBody struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
}

func writeError(w http.ResponseWriter, err error) {
	writeJSON(w, httpStatusForError(err), errorBody{Code: ErrorCodeOf(err), Message: err.Error()})
}

func httpStatusForError(err error) int {
	switch ErrorCodeOf(err) {
	case ErrCodeInvalidArgument:
		return http.StatusBadRequest
	case ErrCodeChallengeNotFound, ErrCodeDeviceNotFound, ErrCodeRotationNotFound,
		ErrCodeKeyVersionNotFound, ErrCodeTransferNotFound:
		return http.StatusNotFound
	case ErrCodeChallengeSecretMismatch, ErrCodeAttestationFailed, ErrCodeSignatureInvalid,
		ErrCodeCredentialMismatch:
		return http.StatusUnauthorized
	case ErrCodeDeviceDisabled, ErrCodeTransferTenantMismatch:
		return http.StatusForbidden
	case ErrCodeChallengeExpired, ErrCodeCredentialExpired:
		return http.StatusGone
	case "":
		return http.StatusInternalServerError
	default:
		// consumed / 属性不匹配 / 幂等冲突 / 版本失效 / 轮换竞态 / 转移终态等统一为 409。
		return http.StatusConflict
	}
}

func decodeBase64(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

// EncodeBase64 供客户端把字节串编码为接口要求的 base64 RawURLEncoding。
func EncodeBase64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
