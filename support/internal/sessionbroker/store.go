package sessionbroker

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrNotFound      = errors.New("session not found")
	ErrUnauthorized  = errors.New("unauthorized")
	ErrCodeNotFound  = errors.New("support code not found")
	ErrBusy          = errors.New("session already has a pending or active supporter")
	ErrClaimNotFound = errors.New("claim not found")
	ErrInvalidState  = errors.New("invalid session state")
	ErrCapacity      = errors.New("session capacity reached")
)

type State string

const (
	StateWaiting         State = "waiting"
	StateApprovalPending State = "approval_pending"
	StateActive          State = "active"
	StateEnded           State = "ended"
	StateExpired         State = "expired"
)

type ClaimState string

const (
	ClaimPending  ClaimState = "pending"
	ClaimApproved ClaimState = "approved"
	ClaimRejected ClaimState = "rejected"
	ClaimEnded    ClaimState = "ended"
	ClaimExpired  ClaimState = "expired"
)

type Session struct {
	ID            string
	Code          string
	State         State
	CreatedAt     time.Time
	ExpiresAt     time.Time
	SupporterName string
	ClaimID       string
	Capabilities  []string
}

type Claim struct {
	ID                  string
	State               ClaimState
	SupporterName       string
	Capabilities        []string
	TransportDescriptor string
}

type createdSession struct {
	Session   Session
	HostToken string
}

type sessionRecord struct {
	Session
	hostTokenHash [32]byte
	transport     []byte
	claimID       string
	terminalAt    time.Time
}

type claimRecord struct {
	Claim
	tokenHash  [32]byte
	sessionID  string
	terminalAt time.Time
}

type StoreOptions struct {
	WaitingTTL        time.Duration
	MaxLiveSessions   int
	TerminalRetention time.Duration
}

const defaultMaxLiveSessions = 10000
const defaultTerminalRetention = 15 * time.Minute

type Store struct {
	mu                sync.Mutex
	rng               io.Reader
	now               func() time.Time
	waitingTTL        time.Duration
	maxLiveSessions   int
	terminalRetention time.Duration
	sessions          map[string]*sessionRecord
	codes             map[string]string
	claims            map[string]*claimRecord
}

func NewStore(waitingTTL time.Duration) *Store {
	return NewStoreWithOptions(StoreOptions{WaitingTTL: waitingTTL})
}

func NewStoreWithOptions(options StoreOptions) *Store {
	return newStoreWithOptions(options, rand.Reader, time.Now)
}

func newStore(waitingTTL time.Duration, rng io.Reader, now func() time.Time) *Store {
	return newStoreWithOptions(StoreOptions{WaitingTTL: waitingTTL}, rng, now)
}

func newStoreWithOptions(options StoreOptions, rng io.Reader, now func() time.Time) *Store {
	if options.WaitingTTL <= 0 {
		options.WaitingTTL = 10 * time.Minute
	}
	if options.MaxLiveSessions <= 0 {
		options.MaxLiveSessions = defaultMaxLiveSessions
	}
	if options.TerminalRetention <= 0 {
		options.TerminalRetention = defaultTerminalRetention
	}
	return &Store{
		rng:               rng,
		now:               now,
		waitingTTL:        options.WaitingTTL,
		maxLiveSessions:   options.MaxLiveSessions,
		terminalRetention: options.TerminalRetention,
		sessions:          make(map[string]*sessionRecord),
		codes:             make(map[string]string),
		claims:            make(map[string]*claimRecord),
	}
}

func (s *Store) Create(transportDescriptor string) (Session, string, error) {
	transportDescriptor = strings.TrimSpace(transportDescriptor)
	if transportDescriptor == "" {
		return Session{}, "", errors.New("transport descriptor is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	return s.createLocked(transportDescriptor, "")
}

func (s *Store) Replace(sessionID, hostToken, transportDescriptor string) (Session, string, error) {
	transportDescriptor = strings.TrimSpace(transportDescriptor)
	if transportDescriptor == "" {
		return Session{}, "", errors.New("transport descriptor is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	rec, err := s.authorizeHostLocked(sessionID, hostToken)
	if err != nil {
		return Session{}, "", err
	}
	if rec.State == StateActive {
		return Session{}, "", fmt.Errorf("%w: active session must be ended before generating a new code", ErrInvalidState)
	}
	oldCode := normalizeCode(rec.Code)
	s.endLocked(rec, ClaimEnded)
	return s.createLocked(transportDescriptor, oldCode)
}

func (s *Store) Snapshot(sessionID, hostToken string) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	rec, err := s.authorizeHostLocked(sessionID, hostToken)
	if err != nil {
		return Session{}, err
	}
	return cloneSession(rec.Session), nil
}

func (s *Store) Claim(code, supporterName string, capabilities []string) (Claim, string, error) {
	code = normalizeCode(code)
	supporterName = strings.TrimSpace(supporterName)
	if err := validateSupporterName(supporterName); err != nil {
		return Claim{}, "", err
	}
	caps, err := normalizeCapabilities(capabilities)
	if err != nil {
		return Claim{}, "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()

	sessionID, ok := s.codes[code]
	if !ok {
		return Claim{}, "", ErrCodeNotFound
	}
	rec := s.sessions[sessionID]
	if rec == nil || rec.State != StateWaiting {
		return Claim{}, "", ErrBusy
	}

	claimID, err := randomToken(s.rng, 18)
	if err != nil {
		return Claim{}, "", err
	}
	claimToken, err := randomToken(s.rng, 32)
	if err != nil {
		return Claim{}, "", err
	}
	claim := Claim{
		ID:            claimID,
		State:         ClaimPending,
		SupporterName: supporterName,
		Capabilities:  caps,
	}
	s.claims[claimID] = &claimRecord{
		Claim:     claim,
		tokenHash: sha256.Sum256([]byte(claimToken)),
		sessionID: sessionID,
	}
	rec.State = StateApprovalPending
	rec.SupporterName = supporterName
	rec.Capabilities = append([]string(nil), caps...)
	rec.ClaimID = claimID
	rec.claimID = claimID
	return cloneClaim(claim), claimToken, nil
}

func (s *Store) ClaimStatus(claimID, claimToken string) (Claim, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	rec, err := s.authorizeClaimLocked(claimID, claimToken)
	if err != nil {
		return Claim{}, err
	}
	out := cloneClaim(rec.Claim)
	if rec.State == ClaimApproved {
		session := s.sessions[rec.sessionID]
		if session != nil && session.State == StateActive {
			out.TransportDescriptor = string(session.transport)
		}
	}
	return out, nil
}

func (s *Store) LeaveClaim(claimID, claimToken string) (Claim, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	claim, err := s.authorizeClaimLocked(claimID, claimToken)
	if err != nil {
		return Claim{}, err
	}
	session := s.sessions[claim.sessionID]
	if session == nil {
		claim.State = ClaimEnded
		claim.terminalAt = s.now().UTC()
		return cloneClaim(claim.Claim), nil
	}

	switch claim.State {
	case ClaimPending:
		claim.State = ClaimEnded
		claim.terminalAt = s.now().UTC()
		if session.State == StateApprovalPending && session.claimID == claimID {
			session.State = StateWaiting
			session.SupporterName = ""
			session.Capabilities = nil
			session.ClaimID = ""
			session.claimID = ""
		}
	case ClaimApproved:
		if session.State == StateActive && session.claimID == claimID {
			s.endLocked(session, ClaimEnded)
		} else {
			claim.State = ClaimEnded
			claim.terminalAt = s.now().UTC()
		}
	case ClaimRejected, ClaimEnded, ClaimExpired:
		// Already terminal; leave is idempotent.
	}
	return cloneClaim(claim.Claim), nil
}

func (s *Store) Approve(sessionID, hostToken, claimID string) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	rec, err := s.authorizeHostLocked(sessionID, hostToken)
	if err != nil {
		return Session{}, err
	}
	if rec.State != StateApprovalPending || rec.claimID == "" || rec.claimID != claimID {
		return Session{}, ErrInvalidState
	}
	claim := s.claims[claimID]
	if claim == nil || claim.State != ClaimPending {
		return Session{}, ErrClaimNotFound
	}
	claim.State = ClaimApproved
	rec.State = StateActive
	delete(s.codes, rec.Code)
	rec.Code = ""
	rec.ExpiresAt = time.Time{}
	return cloneSession(rec.Session), nil
}

func (s *Store) Reject(sessionID, hostToken, claimID string) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	rec, err := s.authorizeHostLocked(sessionID, hostToken)
	if err != nil {
		return Session{}, err
	}
	if rec.State != StateApprovalPending || rec.claimID == "" || rec.claimID != claimID {
		return Session{}, ErrInvalidState
	}
	claim := s.claims[claimID]
	if claim == nil || claim.State != ClaimPending {
		return Session{}, ErrClaimNotFound
	}
	claim.State = ClaimRejected
	claim.terminalAt = s.now().UTC()
	rec.State = StateWaiting
	rec.SupporterName = ""
	rec.Capabilities = nil
	rec.ClaimID = ""
	rec.claimID = ""
	return cloneSession(rec.Session), nil
}

func (s *Store) End(sessionID, hostToken string) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	rec, err := s.authorizeHostLocked(sessionID, hostToken)
	if err != nil {
		return Session{}, err
	}
	if rec.State == StateEnded || rec.State == StateExpired {
		return cloneSession(rec.Session), nil
	}
	s.endLocked(rec, ClaimEnded)
	return cloneSession(rec.Session), nil
}

func (s *Store) createLocked(transportDescriptor, excludedCode string) (Session, string, error) {
	if s.liveSessionCountLocked() >= s.maxLiveSessions {
		return Session{}, "", ErrCapacity
	}
	id, err := randomToken(s.rng, 18)
	if err != nil {
		return Session{}, "", err
	}
	hostToken, err := randomToken(s.rng, 32)
	if err != nil {
		return Session{}, "", err
	}
	code, err := s.uniqueCodeLocked(excludedCode)
	if err != nil {
		return Session{}, "", err
	}
	now := s.now().UTC()
	rec := &sessionRecord{
		Session: Session{
			ID:        id,
			Code:      formatCode(code),
			State:     StateWaiting,
			CreatedAt: now,
			ExpiresAt: now.Add(s.waitingTTL),
		},
		hostTokenHash: sha256.Sum256([]byte(hostToken)),
		transport:     []byte(transportDescriptor),
	}
	s.sessions[id] = rec
	s.codes[code] = id
	return cloneSession(rec.Session), hostToken, nil
}

func (s *Store) uniqueCodeLocked(excludedCode string) (string, error) {
	limit := big.NewInt(900000)
	for i := 0; i < 100; i++ {
		n, err := rand.Int(s.rng, limit)
		if err != nil {
			return "", err
		}
		code := fmt.Sprintf("%06d", n.Int64()+100000)
		if code == excludedCode {
			continue
		}
		if _, exists := s.codes[code]; !exists {
			return code, nil
		}
	}
	return "", errors.New("unable to allocate unique support code")
}

func (s *Store) authorizeHostLocked(sessionID, token string) (*sessionRecord, error) {
	rec := s.sessions[sessionID]
	if rec == nil {
		return nil, ErrNotFound
	}
	provided := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(provided[:], rec.hostTokenHash[:]) != 1 {
		return nil, ErrUnauthorized
	}
	return rec, nil
}

func (s *Store) authorizeClaimLocked(claimID, token string) (*claimRecord, error) {
	rec := s.claims[claimID]
	if rec == nil {
		return nil, ErrClaimNotFound
	}
	provided := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(provided[:], rec.tokenHash[:]) != 1 {
		return nil, ErrUnauthorized
	}
	return rec, nil
}

func (s *Store) expireLocked() {
	now := s.now().UTC()
	for _, rec := range s.sessions {
		if rec.State != StateWaiting && rec.State != StateApprovalPending {
			continue
		}
		if rec.ExpiresAt.IsZero() || now.Before(rec.ExpiresAt) {
			continue
		}
		delete(s.codes, normalizeCode(rec.Code))
		rec.Code = ""
		rec.State = StateExpired
		rec.terminalAt = now
		zeroBytes(rec.transport)
		rec.transport = nil
		if rec.claimID != "" {
			if claim := s.claims[rec.claimID]; claim != nil && claim.State == ClaimPending {
				claim.State = ClaimExpired
				claim.terminalAt = now
			}
		}
	}
	s.pruneTerminalLocked(now)
}

func (s *Store) endLocked(rec *sessionRecord, claimState ClaimState) {
	now := s.now().UTC()
	delete(s.codes, normalizeCode(rec.Code))
	rec.Code = ""
	rec.State = StateEnded
	rec.ExpiresAt = time.Time{}
	rec.terminalAt = now
	zeroBytes(rec.transport)
	rec.transport = nil
	if rec.claimID != "" {
		if claim := s.claims[rec.claimID]; claim != nil && (claim.State == ClaimPending || claim.State == ClaimApproved) {
			claim.State = claimState
			claim.terminalAt = now
		}
	}
}

func (s *Store) liveSessionCountLocked() int {
	count := 0
	for _, rec := range s.sessions {
		switch rec.State {
		case StateWaiting, StateApprovalPending, StateActive:
			count++
		}
	}
	return count
}

func (s *Store) pruneTerminalLocked(now time.Time) {
	if s.terminalRetention <= 0 {
		return
	}
	for id, rec := range s.sessions {
		if rec.terminalAt.IsZero() || now.Sub(rec.terminalAt) < s.terminalRetention {
			continue
		}
		delete(s.sessions, id)
	}
	for id, claim := range s.claims {
		if claim.terminalAt.IsZero() || now.Sub(claim.terminalAt) < s.terminalRetention {
			continue
		}
		delete(s.claims, id)
	}
}

func randomToken(r io.Reader, bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func normalizeCode(code string) string {
	var b strings.Builder
	for _, r := range code {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func formatCode(code string) string {
	if len(code) == 6 {
		return code[:3] + " " + code[3:]
	}
	return code
}

// validateSupporterName protects the Agent's line-oriented status stream and
// the GUI approval gate against remote-user-controlled line/control injection.
// A display name is not an authentication identity.
func validateSupporterName(name string) error {
	if name == "" {
		return errors.New("supporter name is required")
	}
	if utf8.RuneCountInString(name) > 64 {
		return errors.New("supporter name must be at most 64 characters")
	}
	for _, r := range name {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			return errors.New("supporter name must not contain control or format characters")
		}
	}
	return nil
}

func normalizeCapabilities(input []string) ([]string, error) {
	if len(input) == 0 {
		return []string{"view", "input", "clipboard"}, nil
	}
	allowed := map[string]bool{"view": true, "input": true, "clipboard": true}
	seen := make(map[string]bool)
	out := make([]string, 0, len(input))
	for _, raw := range input {
		capability := strings.ToLower(strings.TrimSpace(raw))
		if !allowed[capability] {
			return nil, fmt.Errorf("unsupported capability %q", raw)
		}
		if !seen[capability] {
			seen[capability] = true
			out = append(out, capability)
		}
	}
	return out, nil
}

func zeroBytes(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}

func cloneSession(in Session) Session {
	out := in
	out.Capabilities = append([]string(nil), in.Capabilities...)
	return out
}

func cloneClaim(in Claim) Claim {
	out := in
	out.Capabilities = append([]string(nil), in.Capabilities...)
	return out
}
