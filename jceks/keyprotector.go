package jceks

import (
	"bytes"
	"crypto/sha1"
	"errors"
	"fmt"
)

const saltLen = 20

func recoverKeyProtector(data, password []byte) ([]byte, error) {
	md := sha1.New()
	passwordBytes := make([]byte, 0, len(password)*2)
	for _, b := range password {
		passwordBytes = append(passwordBytes, 0, b)
	}
	salt := make([]byte, saltLen)
	copy(salt, data)
	encryptedKeyLen := len(data) - saltLen - md.Size()
	numRounds := encryptedKeyLen / md.Size()
	if encryptedKeyLen%md.Size() != 0 {
		numRounds++
	}
	encryptedKey := make([]byte, encryptedKeyLen)
	copy(encryptedKey, data[saltLen:])
	xorKey := make([]byte, encryptedKeyLen)
	digest := salt
	for i, xorOffset := 0, 0; i < numRounds; i++ {
		if _, err := md.Write(passwordBytes); err != nil {
			return nil, fmt.Errorf("update digest with password on %d round: %w", i, err)
		}
		if _, err := md.Write(digest); err != nil {
			return nil, fmt.Errorf("update digest with digest from previous round on %d round: %w", i, err)
		}
		digest = md.Sum(nil)
		md.Reset()
		copy(xorKey[xorOffset:], digest)
		xorOffset += md.Size()
	}
	plainKey := make([]byte, encryptedKeyLen)
	for i := 0; i < len(plainKey); i++ {
		plainKey[i] = encryptedKey[i] ^ xorKey[i]
	}

	if _, err := md.Write(passwordBytes); err != nil {
		return nil, fmt.Errorf("update digest with password: %w", err)
	}
	if _, err := md.Write(plainKey); err != nil {
		return nil, fmt.Errorf("update digest with plain key: %w", err)
	}
	digest = md.Sum(nil)
	md.Reset()

	digestOffset := saltLen + encryptedKeyLen
	if !bytes.Equal(digest, data[digestOffset:digestOffset+len(digest)]) {
		return nil, errors.New("got invalid digest")
	}
	return plainKey, nil
}
