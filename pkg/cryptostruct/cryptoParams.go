/*
 * Copyright 2024 CoreLayer BV
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package cryptostruct

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/minio/sio"
	"golang.org/x/crypto/hkdf"
)

func NewCryptoParams(cipherSuite string) (CryptoParams, error) {
	var (
		err   error
		nonce string
		p     CryptoParams
	)
	if nonce, err = createNonce(); err != nil {
		return CryptoParams{}, err
	}

	// Initialize CryptoParams with function arguments
	p = CryptoParams{
		CipherSuite: cipherSuite,
		Nonce:       nonce,
	}

	// Validate the cipherSuite
	_, err = p.getCipherSuite()
	return p, err
}

type CryptoParams struct {
	CipherSuite string `json:"cipherSuite" yaml:"cipherSuite" mapstructure:"cipherSuite"`
	Nonce       string `json:"nonce" yaml:"nonce" mapstructure:"nonce"`
}

func (p CryptoParams) getNonce() ([]byte, error) {
	if p.Nonce != "" {
		return hex.DecodeString(p.Nonce)
	}
	return nil, fmt.Errorf("nonce is not set")
}

func createNonce() (string, error) {
	var nonce [32]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return "", fmt.Errorf("failed to read random data for nonce: %w", err)
	}

	return hex.EncodeToString(nonce[:]), nil
}

func (p CryptoParams) getCipherSuite() ([]byte, error) {
	switch p.CipherSuite {
	case "AES_256_GCM":
		return []byte{sio.AES_256_GCM}, nil
	case "CHACHA20_POLY1305":
		return []byte{sio.CHACHA20_POLY1305}, nil
	default:
		return nil, fmt.Errorf("invalid cipher suite %s", p.CipherSuite)
	}
}

func (p CryptoParams) GetCryptoConfig(masterKeyHex string) (sio.Config, error) {
	var (
		err          error
		masterKey    []byte
		nonce        []byte
		key          [32]byte
		cipherSuites []byte
	)

	masterKey, err = hex.DecodeString(masterKeyHex)
	if err != nil {
		return sio.Config{}, fmt.Errorf("could not decode masterKeyHex key: %w", err)
	}

	nonce, err = p.getNonce()
	if err != nil {
		return sio.Config{}, err
	}

	kdf := hkdf.New(sha256.New, masterKey, nonce, nil)
	if _, err = io.ReadFull(kdf, key[:]); err != nil {
		return sio.Config{}, fmt.Errorf("failed to derive encryption key: %w", err)
	}

	cipherSuites, err = p.getCipherSuite()
	if err != nil {
		return sio.Config{}, err
	}

	return sio.Config{Key: key[:], CipherSuites: cipherSuites}, nil
}
