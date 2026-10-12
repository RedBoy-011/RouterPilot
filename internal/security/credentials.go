package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"sync"
)

// CredentialStore manages encrypted credentials
type CredentialStore struct {
	mu      sync.RWMutex
	key     []byte
	storage map[string]string
}

// NewCredentialStore creates a store bound to the machine
func NewCredentialStore() *CredentialStore {
	// Derive machine-specific key from hostname and user
	host, _ := os.Hostname()
	user := os.Getenv("USERNAME")
	hasher := sha256.New()
	hasher.Write([]byte(fmt.Sprintf("%s:%s:RouterPilotSecure2026", host, user)))
	key := hasher.Sum(nil)

	return &CredentialStore{
		key:     key,
		storage: make(map[string]string),
	}
}

// StoreCredential encrypts and saves a password/token
func (cs *CredentialStore) StoreCredential(target, secret string) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	block, err := aes.NewCipher(cs.key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(secret), nil)
	cs.storage[target] = base64.StdEncoding.EncodeToString(ciphertext)
	return nil
}

// RetrieveCredential decrypts and retrieves a password/token
func (cs *CredentialStore) RetrieveCredential(target string) (string, error) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	encoded, ok := cs.storage[target]
	if !ok {
		return "", fmt.Errorf("credential not found for target %s", target)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(cs.key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("malformed ciphertext")
	}

	nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}

	return string(plaintext), nil
}
