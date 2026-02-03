// SPDX-FileCopyrightText: 2014-2024 SAP SE
//
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // HANA LDAP protocol requires SHA-1 for RSA-OAEP
	"fmt"

	"github.com/SAP/go-hdb/driver/internal/protocol/auth/ldap"
)

const ldapSessionKeySize = 32 // AES-256 key size

// LDAP implements LDAP authentication.
type LDAP struct {
	username string
	password string

	// Phase 1 data
	clientChallenge ldap.ClientChallenge

	// Phase 2 data (received from server)
	serverChallenge *ldap.ServerChallenge

	// Phase 3 data (computed)
	sessionKey []byte
}

// NewLDAP creates a new LDAP authentication instance.
func NewLDAP(username, password string) *LDAP {
	return &LDAP{
		username: username,
		password: password,
	}
}

func (a *LDAP) String() string {
	return fmt.Sprintf("method type %s username %s", a.Typ(), a.username)
}

// Typ implements the Method interface.
func (a *LDAP) Typ() string { return MtLDAP }

// Order implements the Method interface.
func (a *LDAP) Order() byte { return MoLDAP }

// PrepareInitReq implements the Method interface.
// Sends: method type, [clientNonce, capabilities] as sub-parameters.
func (a *LDAP) PrepareInitReq(prms *Prms) error {
	a.clientChallenge = ldap.NewClientChallenge()

	prms.addString(a.Typ())

	// Add sub-parameters: clientNonce and capabilities
	subPrms := prms.addPrms()
	subPrms.addBytes(a.clientChallenge.ClientNonce[:])
	subPrms.addBytes(a.clientChallenge.Capabilities[:])

	return nil
}

// InitRepDecode implements the Method interface.
func (a *LDAP) InitRepDecode(d *Decoder) error {
	d.subSize()

	if err := d.NumPrm(4); err != nil {
		return fmt.Errorf("LDAP authentication: %w", err)
	}

	sc, err := ldap.NewServerChallenge(d.bytes(), d.bytes(), d.bytes(), d.bytes())
	if err != nil {
		return fmt.Errorf("LDAP authentication: %w", err)
	}
	if sc.ClientNonce != a.clientChallenge.ClientNonce {
		return fmt.Errorf("LDAP authentication: client nonce mismatch")
	}

	a.serverChallenge = sc
	return nil
}

// PrepareFinalReq implements the Method interface.
// Sends: username, method type, [encryptedSessionKey, encryptedPassword].
func (a *LDAP) PrepareFinalReq(prms *Prms) error {
	// Generate session key for AES-256 encryption
	a.sessionKey = a.generateSessionKey()

	// Encrypt session key with server's RSA public key using OAEP
	encryptedSessionKey, err := a.encryptSessionKey()
	if err != nil {
		return fmt.Errorf("LDAP authentication: failed to encrypt session key: %w", err)
	}

	// Encrypt password with AES-256-CBC
	encryptedPassword, err := a.encryptPassword()
	if err != nil {
		return fmt.Errorf("LDAP authentication: failed to encrypt password: %w", err)
	}

	prms.AddCESU8String(a.username)
	prms.addString(a.Typ())

	// Add sub-parameters: encryptedSessionKey and encryptedPassword
	subPrms := prms.addPrms()
	subPrms.addBytes(encryptedSessionKey)
	subPrms.addBytes(encryptedPassword)

	return nil
}

// generateSessionKey generates a 32-byte random AES-256 session key.
func (a *LDAP) generateSessionKey() []byte {
	key := make([]byte, ldapSessionKeySize)
	rand.Read(key) //nolint:errcheck
	return key
}

// encryptSessionKey encrypts (sessionKey || serverNonce) with RSA-OAEP.
// Uses SHA-1 for OAEP to match HANA server expectations (same as node-hdb).
func (a *LDAP) encryptSessionKey() ([]byte, error) {
	serverNonce := a.serverChallenge.ServerNonce[:]

	// Concatenate: sessionKey (32 bytes) + serverNonce (64 bytes) = 96 bytes
	plaintext := make([]byte, ldapSessionKeySize+len(serverNonce))
	copy(plaintext[:ldapSessionKeySize], a.sessionKey)
	copy(plaintext[ldapSessionKeySize:], serverNonce)

	// Encrypt with RSA-OAEP using SHA-1 (matches node-hdb default)
	ciphertext, err := rsa.EncryptOAEP(
		sha1.New(), //nolint:gosec // HANA LDAP protocol requires SHA-1
		rand.Reader,
		a.serverChallenge.ServerPublicKey,
		plaintext,
		nil, // no label
	)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

// encryptPassword encrypts (password || 0x00 || serverNonce) with AES-256-CBC.
func (a *LDAP) encryptPassword() ([]byte, error) {
	serverNonce := a.serverChallenge.ServerNonce[:]

	// Prepare plaintext: password + 0x00 (separator) + serverNonce
	// The 0x00 separator matches node-hdb's `new Buffer(1)` which creates a zero-filled buffer
	passwordBytes := []byte(a.password)
	plaintext := make([]byte, len(passwordBytes)+1+len(serverNonce))
	copy(plaintext, passwordBytes)
	plaintext[len(passwordBytes)] = 0x00 // separator byte
	copy(plaintext[len(passwordBytes)+1:], serverNonce)

	// Apply PKCS7 padding for AES block size (16 bytes)
	plaintext = pkcs7Pad(plaintext, aes.BlockSize)

	// Create AES cipher with 32-byte session key
	block, err := aes.NewCipher(a.sessionKey)
	if err != nil {
		return nil, err
	}

	// IV is the first 16 bytes of serverNonce
	iv := serverNonce[:aes.BlockSize]

	// Encrypt with CBC mode
	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	return ciphertext, nil
}

// pkcs7Pad pads data to a multiple of blockSize using PKCS7 padding.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// FinalRepDecode implements the Method interface.
func (a *LDAP) FinalRepDecode(d *Decoder) error {
	if err := d.NumPrm(2); err != nil {
		return err
	}
	mt := d.String()
	if err := checkAuthMethodType(mt, a.Typ()); err != nil {
		return err
	}
	// Second parameter may contain additional data - read and discard
	d.bytes()
	return nil
}
