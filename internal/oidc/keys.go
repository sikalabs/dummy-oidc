package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"io"
	"math/big"
	mathrand "math/rand"
)

// Keys holds the RSA key pair for signing tokens
type Keys struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	kid        string
}

// NewKeys generates a new RSA key pair
// If seed is empty, generates a random key
// If seed is provided, generates a deterministic key from the seed
func NewKeys(seed string) (*Keys, error) {
	var reader io.Reader

	if seed == "" {
		// Use cryptographically secure random
		reader = rand.Reader
	} else {
		// Use deterministic reader from seed
		// Hash the seed to get a 64-bit integer for math/rand
		h := sha256.Sum256([]byte(seed))
		seedInt := int64(binary.BigEndian.Uint64(h[:8]))

		// Create a deterministic random source
		source := mathrand.NewSource(seedInt)
		rng := mathrand.New(source)
		// math/rand.Rand implements io.Reader, so we can use it directly
		reader = rng
	}

	privateKey, err := rsa.GenerateKey(reader, 2048)
	if err != nil {
		return nil, err
	}

	return &Keys{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		kid:        "default-key",
	}, nil
}

// GetPrivateKey returns the private key
func (k *Keys) GetPrivateKey() *rsa.PrivateKey {
	return k.privateKey
}

// GetKID returns the key ID
func (k *Keys) GetKID() string {
	return k.kid
}

// GetJWKS returns the JSON Web Key Set
func (k *Keys) GetJWKS() map[string]interface{} {
	n := k.publicKey.N
	e := k.publicKey.E

	// Encode n and e as base64url
	nBytes := n.Bytes()
	eBytes := big.NewInt(int64(e)).Bytes()

	return map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"use": "sig",
				"kid": k.kid,
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(nBytes),
				"e":   base64.RawURLEncoding.EncodeToString(eBytes),
			},
		},
	}
}
