package storage

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// AuthorizationCode represents an OAuth2 authorization code
type AuthorizationCode struct {
	Code        string
	Email       string
	RedirectURI string
	Nonce       string
	CreatedAt   time.Time
	Used        bool
}

// Storage provides in-memory storage for authorization codes
type Storage struct {
	mu        sync.RWMutex
	authCodes map[string]*AuthorizationCode // code -> auth code
}

// NewStorage creates a new storage instance
func NewStorage() *Storage {
	s := &Storage{
		authCodes: make(map[string]*AuthorizationCode),
	}

	// Start cleanup goroutine
	go s.cleanup()

	return s
}

// CreateAuthorizationCode creates a new authorization code
func (s *Storage) CreateAuthorizationCode(email, redirectURI, nonce string) (*AuthorizationCode, error) {
	code, err := generateToken()
	if err != nil {
		return nil, err
	}

	authCode := &AuthorizationCode{
		Code:        code,
		Email:       email,
		RedirectURI: redirectURI,
		Nonce:       nonce,
		CreatedAt:   time.Now(),
		Used:        false,
	}

	s.mu.Lock()
	s.authCodes[code] = authCode
	s.mu.Unlock()

	return authCode, nil
}

// GetAuthorizationCode retrieves and marks as used an authorization code
func (s *Storage) GetAuthorizationCode(code string) (*AuthorizationCode, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	authCode, exists := s.authCodes[code]
	if !exists || authCode.Used {
		return nil, false
	}

	authCode.Used = true
	return authCode, true
}

// cleanup removes expired authorization codes
func (s *Storage) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()

		s.mu.Lock()

		// Remove auth codes older than 5 minutes
		for code, authCode := range s.authCodes {
			if now.Sub(authCode.CreatedAt) > 5*time.Minute {
				delete(s.authCodes, code)
			}
		}

		s.mu.Unlock()
	}
}

// generateToken generates a random token
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

var ErrCodeNotFound = &StorageError{"authorization code not found"}

type StorageError struct {
	message string
}

func (e *StorageError) Error() string {
	return e.message
}
