package jceks

import (
	"bytes"
	"crypto/sha1"
	"errors"
	"fmt"
	"hash"
)

func recoverKeyProtector(data, password []byte) ([]byte, error) {
	passwordBytes := make([]byte, 0, len(password)*2)
	for _, b := range password {
		passwordBytes = append(passwordBytes, 0, b)
	}
	// salt is the first 20 bytes of the encrypted key
	const saltLen = sha1.Size
	salt := make([]byte, saltLen)
	copy(salt, data)

	md := sha1.New()
	encryptedKeyLen := len(data) - saltLen - sha1.Size
	encryptedKey := make([]byte, encryptedKeyLen)
	copy(encryptedKey, data[saltLen:])

	keystream, err := generateKeystream(passwordBytes, salt, encryptedKeyLen, md)
	if err != nil {
		return nil, fmt.Errorf("could not generate keystream: %w", err)
	}
	plainKey := make([]byte, encryptedKeyLen)
	for i := 0; i < len(plainKey); i++ {
		plainKey[i] = encryptedKey[i] ^ keystream[i]
	}

	if _, err := md.Write(passwordBytes); err != nil {
		return nil, fmt.Errorf("update digest with password: %w", err)
	}
	if _, err := md.Write(plainKey); err != nil {
		return nil, fmt.Errorf("update digest with plain key: %w", err)
	}
	digest := md.Sum(nil)
	md.Reset()

	digestOffset := saltLen + encryptedKeyLen
	if !bytes.Equal(digest, data[digestOffset:digestOffset+len(digest)]) {
		return nil, errors.New("got invalid digest")
	}
	return plainKey, nil
}

// generate the keystream which is sha1(password + salt),
// with the output being the salt for the next round until
// the length matches the encrypted key.
func generateKeystream(password, salt []byte, length int, digestAlgorithm hash.Hash) ([]byte, error) {
	keystream := make([]byte, length)
	rounds := length / digestAlgorithm.Size()
	if length%digestAlgorithm.Size() != 0 {
		rounds++
	}

	for i, xorOffset := 0, 0; i < rounds; i++ {
		if _, err := digestAlgorithm.Write(password); err != nil {
			return nil, fmt.Errorf("update digest with password on %d round: %w", i, err)
		}
		if _, err := digestAlgorithm.Write(salt); err != nil {
			return nil, fmt.Errorf("update digest with digest from previous round on %d round: %w", i, err)
		}
		salt = digestAlgorithm.Sum(nil)
		digestAlgorithm.Reset()
		copy(keystream[xorOffset:], salt)
		xorOffset += digestAlgorithm.Size()
	}

	return keystream, nil
}
