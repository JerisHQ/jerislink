package sessionbroker

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const maxRequestBody = 64 << 10

type HTTPOptions struct {
	ClientIPHeader                string
	ClaimAttemptsPerWindow        int
	GlobalClaimAttemptsPerWindow  int
	SessionCreatesPerWindow       int
	GlobalSessionCreatesPerWindow int
	Window                        time.Duration
	MaxLimiterKeys                int
}

func DefaultHTTPOptions() HTTPOptions {
	return HTTPOptions{
		ClaimAttemptsPerWindow:        20,
		GlobalClaimAttemptsPerWindow:  120,
		SessionCreatesPerWindow:       10,
		GlobalSessionCreatesPerWindow: 60,
		Window:                        time.Minute,
		MaxLimiterKeys:                defaultLimiterMaxKeys,
	}
}

type HTTPServer struct {
	store                  *Store
	clientIPHeader         string
	claimPerClient         *fixedWindowLimiter
	claimGlobal            *fixedWindowLimiter
	sessionCreatePerClient *fixedWindowLimiter
	sessionCreateGlobal    *fixedWindowLimiter
}

func NewHTTPHandler(store *Store) http.Handler {
	return NewHTTPHandlerWithOptions(store, DefaultHTTPOptions())
}

func NewHTTPHandlerWithOptions(store *Store, options HTTPOptions) http.Handler {
	if store == nil {
		panic("nil session broker store")
	}
	if options.Window <= 0 {
		options.Window = time.Minute
	}
	if options.MaxLimiterKeys <= 0 {
		options.MaxLimiterKeys = defaultLimiterMaxKeys
	}
	s := &HTTPServer{
		store:                  store,
		clientIPHeader:         strings.TrimSpace(options.ClientIPHeader),
		claimPerClient:         newFixedWindowLimiter(options.ClaimAttemptsPerWindow, options.Window, options.MaxLimiterKeys, nil),
		claimGlobal:            newFixedWindowLimiter(options.GlobalClaimAttemptsPerWindow, options.Window, 1, nil),
		sessionCreatePerClient: newFixedWindowLimiter(options.SessionCreatesPerWindow, options.Window, options.MaxLimiterKeys, nil),
		sessionCreateGlobal:    newFixedWindowLimiter(options.GlobalSessionCreatesPerWindow, options.Window, 1, nil),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("POST /v1/sessions", s.createSession)
	mux.HandleFunc("GET /v1/sessions/{sessionID}", s.getSession)
	mux.HandleFunc("POST /v1/sessions/{sessionID}/replace", s.replaceSession)
	mux.HandleFunc("POST /v1/sessions/{sessionID}/approve", s.approveClaim)
	mux.HandleFunc("POST /v1/sessions/{sessionID}/reject", s.rejectClaim)
	mux.HandleFunc("POST /v1/sessions/{sessionID}/end", s.endSession)
	mux.HandleFunc("POST /v1/claims", s.createClaim)
	mux.HandleFunc("GET /v1/claims/{claimID}", s.getClaim)
	mux.HandleFunc("POST /v1/claims/{claimID}/leave", s.leaveClaim)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(w, r)
	})
}

type sessionResponse struct {
	ID            string   `json:"id"`
	Code          string   `json:"code,omitempty"`
	State         State    `json:"state"`
	CreatedAt     string   `json:"created_at"`
	ExpiresAt     string   `json:"expires_at,omitempty"`
	SupporterName string   `json:"supporter_name,omitempty"`
	ClaimID       string   `json:"claim_id,omitempty"`
	Capabilities  []string `json:"capabilities,omitempty"`
	HostToken     string   `json:"host_token,omitempty"`
}

type claimResponse struct {
	ID                  string     `json:"id"`
	State               ClaimState `json:"state"`
	SupporterName       string     `json:"supporter_name"`
	Capabilities        []string   `json:"capabilities,omitempty"`
	ClaimToken          string     `json:"claim_token,omitempty"`
	TransportDescriptor string     `json:"transport_descriptor,omitempty"`
}

func (s *HTTPServer) allowAnonymousRequest(w http.ResponseWriter, r *http.Request, global, perClient *fixedWindowLimiter) bool {
	if ok, retry := global.allow("global"); !ok {
		writeRateLimitError(w, retry)
		return false
	}
	if ok, retry := perClient.allow(s.clientKey(r)); !ok {
		writeRateLimitError(w, retry)
		return false
	}
	return true
}

func (s *HTTPServer) clientKey(r *http.Request) string {
	if s.clientIPHeader != "" {
		raw := strings.TrimSpace(r.Header.Get(s.clientIPHeader))
		if comma := strings.IndexByte(raw, ','); comma >= 0 {
			raw = strings.TrimSpace(raw[:comma])
		}
		if ip := net.ParseIP(raw); ip != nil {
			return ip.String()
		}
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil {
		if ip := net.ParseIP(host); ip != nil {
			return ip.String()
		}
		if host != "" {
			return host
		}
	}
	if ip := net.ParseIP(strings.TrimSpace(r.RemoteAddr)); ip != nil {
		return ip.String()
	}
	if strings.TrimSpace(r.RemoteAddr) != "" {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return "unknown"
}

func writeRateLimitError(w http.ResponseWriter, retry time.Duration) {
	seconds := int64((retry + time.Second - 1) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
	writeJSON(w, http.StatusTooManyRequests, map[string]any{
		"error": map[string]string{
			"code":    "rate_limited",
			"message": "too many requests; retry later",
		},
	})
}

func (s *HTTPServer) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"service": "jeris-session-broker",
	})
}

func (s *HTTPServer) createSession(w http.ResponseWriter, r *http.Request) {
	if !s.allowAnonymousRequest(w, r, s.sessionCreateGlobal, s.sessionCreatePerClient) {
		return
	}
	var input struct {
		TransportDescriptor string `json:"transport_descriptor"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		writeAPIError(w, err)
		return
	}
	session, token, err := s.store.Create(input.TransportDescriptor)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	out := toSessionResponse(session)
	out.HostToken = token
	writeJSON(w, http.StatusCreated, out)
}

func (s *HTTPServer) getSession(w http.ResponseWriter, r *http.Request) {
	session, err := s.store.Snapshot(r.PathValue("sessionID"), bearerToken(r))
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toSessionResponse(session))
}

func (s *HTTPServer) replaceSession(w http.ResponseWriter, r *http.Request) {
	var input struct {
		TransportDescriptor string `json:"transport_descriptor"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		writeAPIError(w, err)
		return
	}
	session, token, err := s.store.Replace(r.PathValue("sessionID"), bearerToken(r), input.TransportDescriptor)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	out := toSessionResponse(session)
	out.HostToken = token
	writeJSON(w, http.StatusCreated, out)
}

func (s *HTTPServer) createClaim(w http.ResponseWriter, r *http.Request) {
	if !s.allowAnonymousRequest(w, r, s.claimGlobal, s.claimPerClient) {
		return
	}
	var input struct {
		Code          string   `json:"code"`
		SupporterName string   `json:"supporter_name"`
		Capabilities  []string `json:"capabilities"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		writeAPIError(w, err)
		return
	}
	claim, token, err := s.store.Claim(input.Code, input.SupporterName, input.Capabilities)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	out := toClaimResponse(claim)
	out.ClaimToken = token
	writeJSON(w, http.StatusCreated, out)
}

func (s *HTTPServer) getClaim(w http.ResponseWriter, r *http.Request) {
	claim, err := s.store.ClaimStatus(r.PathValue("claimID"), bearerToken(r))
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toClaimResponse(claim))
}

func (s *HTTPServer) leaveClaim(w http.ResponseWriter, r *http.Request) {
	claim, err := s.store.LeaveClaim(r.PathValue("claimID"), bearerToken(r))
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toClaimResponse(claim))
}

func (s *HTTPServer) approveClaim(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ClaimID string `json:"claim_id"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		writeAPIError(w, err)
		return
	}
	if strings.TrimSpace(input.ClaimID) == "" {
		writeAPIError(w, errors.New("claim_id is required"))
		return
	}
	session, err := s.store.Approve(r.PathValue("sessionID"), bearerToken(r), input.ClaimID)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toSessionResponse(session))
}

func (s *HTTPServer) rejectClaim(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ClaimID string `json:"claim_id"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		writeAPIError(w, err)
		return
	}
	if strings.TrimSpace(input.ClaimID) == "" {
		writeAPIError(w, errors.New("claim_id is required"))
		return
	}
	session, err := s.store.Reject(r.PathValue("sessionID"), bearerToken(r), input.ClaimID)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toSessionResponse(session))
}

func (s *HTTPServer) endSession(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > 0 {
		var unused map[string]any
		if err := decodeJSON(w, r, &unused); err != nil {
			writeAPIError(w, err)
			return
		}
	}
	session, err := s.store.End(r.PathValue("sessionID"), bearerToken(r))
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toSessionResponse(session))
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return errors.New("invalid JSON body: multiple JSON values")
		}
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	return nil
}

func bearerToken(r *http.Request) string {
	value := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(value) < 7 || !strings.EqualFold(value[:7], "Bearer ") {
		return ""
	}
	return strings.TrimSpace(value[7:])
}

func writeAPIError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	code := "invalid_request"
	switch {
	case errors.Is(err, ErrUnauthorized):
		status = http.StatusUnauthorized
		code = "unauthorized"
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrCodeNotFound), errors.Is(err, ErrClaimNotFound):
		status = http.StatusNotFound
		code = "not_found"
	case errors.Is(err, ErrBusy), errors.Is(err, ErrInvalidState):
		status = http.StatusConflict
		code = "conflict"
	case errors.Is(err, ErrCapacity):
		status = http.StatusServiceUnavailable
		code = "capacity"
	}
	writeJSON(w, status, map[string]any{
		"error": map[string]string{
			"code":    code,
			"message": err.Error(),
		},
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func toSessionResponse(s Session) sessionResponse {
	out := sessionResponse{
		ID:            s.ID,
		Code:          s.Code,
		State:         s.State,
		CreatedAt:     s.CreatedAt.UTC().Format("2006-01-02T15:04:05.000000000Z07:00"),
		SupporterName: s.SupporterName,
		ClaimID:       s.ClaimID,
		Capabilities:  append([]string(nil), s.Capabilities...),
	}
	if !s.ExpiresAt.IsZero() {
		out.ExpiresAt = s.ExpiresAt.UTC().Format("2006-01-02T15:04:05.000000000Z07:00")
	}
	return out
}

func toClaimResponse(c Claim) claimResponse {
	return claimResponse{
		ID:                  c.ID,
		State:               c.State,
		SupporterName:       c.SupporterName,
		Capabilities:        append([]string(nil), c.Capabilities...),
		TransportDescriptor: c.TransportDescriptor,
	}
}
