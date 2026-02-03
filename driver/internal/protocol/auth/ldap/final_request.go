// SPDX-FileCopyrightText: 2014-2024 SAP SE
//
// SPDX-License-Identifier: Apache-2.0

package ldap

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SHA-1 is safe in OAEP (requires preimage resistance, not collision resistance)
)

// Final LDAP authentication request.
// Taken from "SAP HANA SQL Command Network Protocol Reference" version 1.1 chapter 3.9.2.2
//
// Wire format:
//	Field            Data Type        Description
//	FIELDCOUNT       I2               Number of fields within this request.
//	LENGTHINDICATOR  B1               Length of the USERNAME field.
//	USERNAME         B[DATALENGTH]    Username.
//	LENGTHINDICATOR  B1               Length of the METHODNAME field.
//	METHODNAME       B[DATALENGTH]    Method name "LDAP".
//	LENGTHINDICATOR  B1-2             Length of the CLIENTPROOF field.
//	CLIENTPROOF      B[DATALENGTH]    Client proof (see ClientProof).
//
// Missing fields are set elsewhere (e.g., when serializing).
type FinalRequest struct {
	ClientProof ClientProof
}

// LDAP client proof data.
// Taken from "SAP HANA SQL Command Network Protocol Reference" version 1.1 chapter 3.9.2.2
//
// Wire format:
//	Field                 Data Type        Description
//	FIELDCOUNT            I2               Number of fields within this request.
//	LENGTHINDICATOR       B1-2             Length of the ENCRYPTEDSESSIONKEY field.
//	ENCRYPTEDSESSIONKEY   B[DATALENGTH]    RSAEncrypt(publicKey, SESSIONKEY + SERVERNONCE).
//	LENGTHINDICATOR       B1-2             Length of the ENCRYPTEDPASSWORD field.
//	ENCRYPTEDPASSWORD     B[DATALENGTH]    AES256Encrypt(SESSIONKEY, PASSWORD + SERVERNONCE).
type ClientProof struct {
	EncryptedSessionKey []byte
	EncryptedPassword   []byte
}

const sessionKeySize = 32 // AES-256 key size

// NewClientProof creates a ClientProof by encrypting the password with a new session key.
// The session key is encrypted with RSA-OAEP using the server's public key.
// The password is encrypted with AES-256-CBC using the session key.
func NewClientProof(password string, serverChallenge *ServerChallenge) (*ClientProof, error) {
	// Generate random session key
	sessionKey := make([]byte, sessionKeySize)
	rand.Read(sessionKey) //nolint:errcheck

	serverNonce := serverChallenge.ServerNonce[:]

	// Encrypt session key: RSAEncrypt(publicKey, SESSIONKEY + SERVERNONCE)
	encryptedSessionKey, err := encryptSessionKey(sessionKey, serverNonce, serverChallenge.ServerPublicKey)
	if err != nil {
		return nil, err
	}

	// Encrypt password: AES256Encrypt(SESSIONKEY, PASSWORD + SERVERNONCE)
	encryptedPassword, err := encryptPassword(password, sessionKey, serverNonce)
	if err != nil {
		return nil, err
	}

	return &ClientProof{
		EncryptedSessionKey: encryptedSessionKey,
		EncryptedPassword:   encryptedPassword,
	}, nil
}

// encryptSessionKey encrypts (sessionKey || serverNonce) with RSA-OAEP.
func encryptSessionKey(sessionKey, serverNonce []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	// Concatenate: sessionKey (32 bytes) + serverNonce (64 bytes) = 96 bytes
	plaintext := make([]byte, len(sessionKey)+len(serverNonce))
	copy(plaintext[:len(sessionKey)], sessionKey)
	copy(plaintext[len(sessionKey):], serverNonce)

	ciphertext, err := rsa.EncryptOAEP(
		sha1.New(), //nolint:gosec
		rand.Reader,
		publicKey,
		plaintext,
		nil, // no label
	)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

// encryptPassword encrypts (password || 0x00 || serverNonce) with AES-256-CBC.
func encryptPassword(password string, sessionKey, serverNonce []byte) ([]byte, error) {
	// Prepare plaintext: password + 0x00 (separator) + serverNonce
	// The 0x00 separator matches node-hdb's `new Buffer(1)` which creates a zero-filled buffer
	passwordBytes := []byte(password)
	plaintext := make([]byte, len(passwordBytes)+1+len(serverNonce))
	copy(plaintext, passwordBytes)
	plaintext[len(passwordBytes)] = 0x00 // separator byte
	copy(plaintext[len(passwordBytes)+1:], serverNonce)

	// Apply PKCS7 padding for AES block size (16 bytes)
	plaintext = pkcs7Pad(plaintext, aes.BlockSize)

	// Create AES cipher with 32-byte session key
	block, err := aes.NewCipher(sessionKey)
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
