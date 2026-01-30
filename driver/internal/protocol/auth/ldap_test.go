// SPDX-FileCopyrightText: 2014-2024 SAP SE
//
// SPDX-License-Identifier: Apache-2.0

//go:build unit

package auth

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestLDAPInitialData(t *testing.T) {
	// Test with deterministic values
	clientNonce := make([]byte, 64)
	for i := range clientNonce {
		clientNonce[i] = byte(i)
	}

	ldap := newLDAPWithTestData("testuser", "testpass", clientNonce, nil)

	prms := &Prms{}
	err := ldap.PrepareInitReq(prms)
	if err != nil {
		t.Fatalf("PrepareInitReq failed: %v", err)
	}

	// Verify client nonce was set
	if !bytes.Equal(ldap.clientNonce, clientNonce) {
		t.Errorf("client nonce mismatch")
	}

	// Verify capabilities
	expectedCaps := []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if !bytes.Equal(ldap.capabilities, expectedCaps) {
		t.Errorf("capabilities mismatch: got %v, want %v", ldap.capabilities, expectedCaps)
	}
}

func TestLDAPPasswordEncryption(t *testing.T) {
	// Generate a test RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Create deterministic test values
	serverNonce := make([]byte, 64)
	sessionKey := make([]byte, 32)

	for i := range serverNonce {
		serverNonce[i] = byte(i + 100)
	}
	for i := range sessionKey {
		sessionKey[i] = byte(i + 200)
	}

	password := "testpassword123"

	ldap := newLDAPWithTestData("testuser", password, nil, sessionKey)
	ldap.serverNonce = serverNonce
	ldap.serverPublicKey = &privateKey.PublicKey
	ldap.sessionKey = sessionKey

	// Encrypt password
	encryptedPassword, err := ldap.encryptPassword()
	if err != nil {
		t.Fatalf("encryptPassword failed: %v", err)
	}

	// Decrypt and verify
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}

	iv := serverNonce[:16]
	decrypted := make([]byte, len(encryptedPassword))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(decrypted, encryptedPassword)

	// Remove PKCS7 padding
	padLen := int(decrypted[len(decrypted)-1])
	decrypted = decrypted[:len(decrypted)-padLen]

	// Verify: password + 0x00 + serverNonce
	expectedPlaintext := append([]byte(password), 0x00)
	expectedPlaintext = append(expectedPlaintext, serverNonce...)

	if !bytes.Equal(decrypted, expectedPlaintext) {
		t.Errorf("decrypted password mismatch: got %v, want %v", decrypted, expectedPlaintext)
	}
}

func TestLDAPSessionKeyEncryption(t *testing.T) {
	// Generate a test RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	serverNonce := make([]byte, 64)
	sessionKey := make([]byte, 32)

	for i := range serverNonce {
		serverNonce[i] = byte(i + 100)
	}
	for i := range sessionKey {
		sessionKey[i] = byte(i + 200)
	}

	ldap := newLDAPWithTestData("testuser", "testpass", nil, sessionKey)
	ldap.serverNonce = serverNonce
	ldap.serverPublicKey = &privateKey.PublicKey
	ldap.sessionKey = sessionKey

	// Encrypt session key
	encryptedSessionKey, err := ldap.encryptSessionKey()
	if err != nil {
		t.Fatalf("encryptSessionKey failed: %v", err)
	}

	// Decrypt and verify using SHA-1 (matches the encryption)
	decrypted, err := rsa.DecryptOAEP(
		sha1.New(), //nolint:gosec
		rand.Reader,
		privateKey,
		encryptedSessionKey,
		nil,
	)
	if err != nil {
		t.Fatalf("failed to decrypt session key: %v", err)
	}

	// Verify: sessionKey + serverNonce
	expectedPlaintext := append(sessionKey, serverNonce...)

	if !bytes.Equal(decrypted, expectedPlaintext) {
		t.Errorf("decrypted session key data mismatch")
	}
}

func TestParseRSAPublicKey(t *testing.T) {
	// Generate a test key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Convert to PEM format (PKCS8/SPKI)
	pubASN1, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})

	// Parse it back
	parsedKey, err := parseRSAPublicKey(pemData)
	if err != nil {
		t.Fatalf("parseRSAPublicKey failed: %v", err)
	}

	// Verify it matches
	if parsedKey.N.Cmp(privateKey.PublicKey.N) != 0 {
		t.Errorf("parsed key does not match original")
	}
}

func TestPKCS7Padding(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		blockSize int
		wantLen   int
	}{
		{"empty", []byte{}, 16, 16},
		{"one byte", []byte{0x01}, 16, 16},
		{"15 bytes", make([]byte, 15), 16, 16},
		{"16 bytes", make([]byte, 16), 16, 32},
		{"17 bytes", make([]byte, 17), 16, 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			padded := pkcs7Pad(tt.data, tt.blockSize)
			if len(padded) != tt.wantLen {
				t.Errorf("pkcs7Pad() len = %d, want %d", len(padded), tt.wantLen)
			}
			// Verify padding value
			padLen := padded[len(padded)-1]
			for i := len(padded) - int(padLen); i < len(padded); i++ {
				if padded[i] != padLen {
					t.Errorf("invalid padding at position %d: got %d, want %d", i, padded[i], padLen)
				}
			}
		})
	}
}

func TestLDAPTypAndOrder(t *testing.T) {
	ldap := NewLDAP("user", "pass")

	if ldap.Typ() != MtLDAP {
		t.Errorf("Typ() = %s, want %s", ldap.Typ(), MtLDAP)
	}

	if ldap.Order() != MoLDAP {
		t.Errorf("Order() = %d, want %d", ldap.Order(), MoLDAP)
	}
}

func TestLDAPString(t *testing.T) {
	ldap := NewLDAP("testuser", "testpass")
	s := ldap.String()

	if s != "method type LDAP username testuser" {
		t.Errorf("String() = %s, want 'method type LDAP username testuser'", s)
	}
}
