package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/roofn/secure-messenger/server/internal/identity"
)

var (
	ErrInvalidToken               = errors.New("auth: token is invalid or expired")
	ErrInvalidAuthorizationHeader = errors.New("auth: invalid authorization header")
)

const bearerPrefix = "Bearer "

type TokenValidator interface {
	ValidateToken(token string) (identity.Identity, time.Time, error)
}

type tokenEntry struct {
	identity identity.Identity
	expires  time.Time
}

type TokenManager struct {
	mu     sync.RWMutex
	tokens map[string]tokenEntry
	ttl    time.Duration
}

func NewTokenManager(ttl time.Duration) *TokenManager {
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	return &TokenManager{
		tokens: make(map[string]tokenEntry),
		ttl:    ttl,
	}
}

func (m *TokenManager) IssueToken(ident identity.Identity) (string, time.Time, error) {
	token, err := randomToken(32)
	if err != nil {
		return "", time.Time{}, err
	}
	expires := time.Now().Add(m.ttl)

	m.mu.Lock()
	m.tokens[token] = tokenEntry{identity: ident, expires: expires}
	m.mu.Unlock()

	return token, expires, nil
}

func (m *TokenManager) ValidateToken(token string) (identity.Identity, time.Time, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return identity.Identity{}, time.Time{}, ErrInvalidToken
	}

	m.mu.RLock()
	entry, ok := m.tokens[token]
	m.mu.RUnlock()
	if !ok {
		return identity.Identity{}, time.Time{}, ErrInvalidToken
	}

	if time.Now().After(entry.expires) {
		m.mu.Lock()
		delete(m.tokens, token)
		m.mu.Unlock()
		return identity.Identity{}, time.Time{}, ErrInvalidToken
	}

	return entry.identity, entry.expires, nil
}

func (m *TokenManager) Revoke(token string) {
	m.mu.Lock()
	delete(m.tokens, strings.TrimSpace(token))
	m.mu.Unlock()
}

func randomToken(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func ParseBearerToken(header string) (string, error) {
	header = strings.TrimSpace(header)
	if header == "" {
		return "", ErrInvalidAuthorizationHeader
	}
	if !strings.HasPrefix(strings.ToLower(header), strings.ToLower(bearerPrefix)) {
		return "", ErrInvalidAuthorizationHeader
	}
	token := strings.TrimSpace(header[len(bearerPrefix):])
	if token == "" {
		return "", ErrInvalidAuthorizationHeader
	}
	return token, nil
}
