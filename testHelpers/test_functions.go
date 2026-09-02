/*
Copyright (c) 2023 Securosys SA, authors: Tomasz Madej

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.
*/

package testHelpers

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
	"securosys.ch/backend"
)

type TestEnv struct {
	Backend logical.Backend
	Context context.Context
	Storage logical.Storage
	Conf    logical.BackendConfig
}

var keyPair *rsa.PrivateKey = nil

// Function checking that 2 variables are equals
func AreEqual(x, y interface{}) (bool, error) {
	xv := reflect.ValueOf(x)
	yv := reflect.ValueOf(y)
	if yv.Type().ConvertibleTo(xv.Type()) {
		return xv.Interface() == yv.Convert(xv.Type()).Interface(), nil
	} else {
		return false, errors.New("Types are mismatched")
	}
}
func InitRSAKeyPair() {
	keyPair, _ = rsa.GenerateKey(rand.Reader, 2048)
}
func Sign(data []byte) string {
	msgHash := sha256.New()
	msgHash.Write(data)
	msgHashSum := msgHash.Sum(nil)
	signature, _ := rsa.SignPKCS1v15(rand.Reader, keyPair, crypto.SHA256, msgHashSum)
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)
	return signatureBase64
}
func GetPublicKey() string {
	pub := keyPair.Public()
	asn1Bytes, _ := x509.MarshalPKIXPublicKey(pub)
	// Encode private key to PKCS#1 ASN.1 PEM.
	pubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: asn1Bytes,
		},
	)
	publicKey := string(pubPEM[:])
	publicKey = strings.Replace(publicKey, "-----BEGIN PUBLIC KEY-----", "", 1)
	publicKey = strings.Replace(publicKey, "-----END PUBLIC KEY-----", "", 1)
	publicKey = strings.Replace(publicKey, "\n", "", 20)
	return publicKey
}

// This function create initialized test environment with storage in memory
func NewTestEnv() (*TestEnv, error) {
	ctx := context.Background()

	maxLease, _ := time.ParseDuration("99999s")
	defaultLease, _ := time.ParseDuration("88888s")
	conf := &logical.BackendConfig{
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLease,
			MaxLeaseTTLVal:     maxLease,
		},
		Logger: logging.NewVaultLogger(log.Debug),
	}
	b, err := backend.Factory(ctx, conf)
	if err != nil {
		return nil, err
	}
	return &TestEnv{
		Backend: b,
		Context: ctx,
		Conf:    *conf,
		Storage: &logical.InmemStorage{},
	}, nil
}

// Function initialize configuration needed by all functions/operations on keys in TSB
func (e *TestEnv) AddConfig(t *testing.T) {
	t.Helper()
	RequireTSBConfig(t)
	require.NoError(t, e.AddConfigRaw())
}

func (e *TestEnv) AddConfigRaw() error {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   e.Storage,
		Data:      ConfigParams,
	}
	_, err := e.Backend.HandleRequest(e.Context, req)
	return err
}

// Function prepare some test keys
func (e *TestEnv) PrepareTestKeys(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		e.RemoveTestKeys(t)
	})
	require.NoError(t, e.PrepareTestKeysRaw())
}

func (e *TestEnv) PrepareTestKeysRaw() error {
	InitRSAKeyPair()

	keys := []struct {
		name       string
		createPath string
		data       map[string]interface{}
	}{
		{
			name:       "test_aes_256",
			createPath: "keys/aes/test_aes_256",
			data: map[string]interface{}{
				"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_AES_256",
				"keySize":    256,
				"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": true,"sensitive": false,"extractable": true,"modifiable": true,"copyable": false,"destroyable": true}`,
			},
		},
		{
			name:       "test_aes_256_rotate",
			createPath: "keys/aes/test_aes_256_rotate",
			data: map[string]interface{}{
				"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_AES_256_ROTATE",
				"keySize":    256,
				"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": true,"sensitive": false,"extractable": true,"modifiable": true,"copyable": false,"destroyable": true}`,
			},
		},
		{
			name:       "test_aes_128",
			createPath: "keys/aes/test_aes_128",
			data: map[string]interface{}{
				"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_AES_128",
				"keySize":    128,
				"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": true,"sensitive": false,"extractable": true,"modifiable": true,"copyable": false,"destroyable": true}`,
			},
		},
		{
			name:       "test_bls",
			createPath: "keys/bls/test_bls",
			data: map[string]interface{}{
				"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_BLS",
				"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": false,"sensitive": true,"extractable": true,"modifiable": true,"copyable": false,"destroyable": true}`,
			},
		},
		{
			name:       "test_camellia",
			createPath: "keys/camellia/test_camellia",
			data: map[string]interface{}{
				"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_CAMELLIA",
				"keySize":    256,
				"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": true,"sensitive": false,"extractable": true,"modifiable": true,"copyable": false,"destroyable": true}`,
			},
		},
		{
			name:       "test_chacha20",
			createPath: "keys/chacha20/test_chacha20",
			data: map[string]interface{}{
				"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_CHACHA20",
				"keySize":    256,
				"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": true,"sensitive": false,"extractable": true,"modifiable": true,"copyable": false,"destroyable": true}`,
			},
		},
		{
			name:       "test_dsa_1024",
			createPath: "keys/dsa/test_dsa_1024",
			data: map[string]interface{}{
				"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_DSA_1024",
				"keySize":    1024,
				"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": false,"sensitive": true,"extractable": true,"modifiable": true,"copyable": false,"destroyable": true}`,
			},
		},
		{
			name:       "test_ec_secp256k1",
			createPath: "keys/ec/test_ec_secp256k1",
			data: map[string]interface{}{
				"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_EC_SECP256K1",
				"curveOid":   "1.3.132.0.10",
				"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": false,"sensitive": true,"extractable": true,"modifiable": true,"copyable": false,"destroyable": true}`,
			},
		},
		{
			name:       "test_ed_ed25519",
			createPath: "keys/ed/test_ed_ed25519",
			data: map[string]interface{}{
				"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_ED_ED25519",
				"curveOid":   "1.3.101.112",
				"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": false,"sensitive": true,"extractable": true,"modifiable": true,"copyable": false,"destroyable": true}`,
			},
		},
		{
			name:       "test_tdea",
			createPath: "keys/tdea/test_tdea",
			data: map[string]interface{}{
				"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_TDEA",
				"keySize":    0,
				"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": true,"sensitive": false,"extractable": true,"modifiable": true,"copyable": false,"destroyable": true}`,
			},
		},
		{
			name:       "test_rsa_2048_pass",
			createPath: "keys/rsa/test_rsa_2048_pass",
			data: map[string]interface{}{
				"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_RSA_2048_PASS",
				"password":   "",
				"keySize":    2048,
				"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": false,"sensitive": true,"extractable": true,"modifiable": true,"copyable": false,"destroyable": true}`,
			},
		},
		{
			name:       "test_rsa_2048",
			createPath: "keys/rsa/test_rsa_2048",
			data: map[string]interface{}{
				"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_RSA_2048",
				"keySize":    2048,
				"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": false,"sensitive": true,"extractable": true,"modifiable": true,"copyable": false,"destroyable": true}`,
			},
		},
		{
			name:       "test_rsa_2048_modify",
			createPath: "keys/rsa/test_rsa_2048_modify",
			data: map[string]interface{}{
				"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_RSA_2048_MODIFY",
				"keySize":    1024,
				"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": false,"sensitive": true,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
			},
		},
		{
			name:       "test_rsa_2048_policy",
			createPath: "keys/rsa/test_rsa_2048_policy",
			data: map[string]interface{}{
				"keyLabel":     "TEST_SECUROSYS_SECRETS_ENGINE_RSA_2048_POLICY",
				"keySize":      2048,
				"attributes":   `{"decrypt": true,"sign": true,"unwrap": true,"derive": false,"sensitive": true,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
				"simplePolicy": `{"Tomasz Madej":"` + GetPublicKey() + `"}`,
			},
		},
		{
			name:       "type_aes",
			createPath: "keys/type/aes256-gcm96/type_aes",
			data: map[string]interface{}{
				"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_TYPE_AES",
				"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": false,"sensitive": true,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
			},
		},
		{
			name:       "type_rsa_2048",
			createPath: "keys/type/rsa-2048/type_rsa_2048",
			data: map[string]interface{}{
				"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_TYPE_RSA_2048",
				"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": false,"sensitive": true,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
			},
		},
		{
			name:       "type_rsa_3072",
			createPath: "keys/type/rsa-3072/type_rsa_3072",
			data: map[string]interface{}{
				"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_TYPE_RSA_3072",
				"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": false,"sensitive": true,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
			},
		},
		{
			name:       "type_rsa_4096",
			createPath: "keys/type/rsa-4096/type_rsa_4096",
			data: map[string]interface{}{
				"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_TYPE_RSA_4096",
				"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": false,"sensitive": true,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
			},
		},
		{
			name:       "type_ec_p256",
			createPath: "keys/type/ecdsa-p256/type_ec_p256",
			data: map[string]interface{}{
				"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_TYPE_EC_P256",
				"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": false,"sensitive": true,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
			},
		},
		{
			name:       "type_ec_p384",
			createPath: "keys/type/ecdsa-p384/type_ec_p384",
			data: map[string]interface{}{
				"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_TYPE_EC_P384",
				"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": false,"sensitive": true,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
			},
		},
		{
			name:       "type_ec_p521",
			createPath: "keys/type/ecdsa-p521/type_ec_p521",
			data: map[string]interface{}{
				"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_TYPE_EC_P521",
				"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": false,"sensitive": true,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
			},
		},
	}

	for _, key := range keys {
		if err := e.createTestKeyIfMissing(key.name, key.createPath, key.data); err != nil {
			return fmt.Errorf("prepare test key %s failed: %w", key.name, err)
		}
	}
	return nil
}

func (e *TestEnv) createTestKeyIfMissing(keyName, createPath string, data map[string]interface{}) error {
	keyLabel, _ := data["keyLabel"].(string)
	password, _ := data["password"].(string)
	keyTypeName := keyTypeNameFromCreatePath(createPath)

	resp, err := e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "keys/" + keyName,
		Storage:   e.Storage,
	})
	if err == nil && resp != nil && !resp.IsError() && resp.Data != nil {
		return nil
	}

	if keyLabel != "" {
		if removeErr := e.removeStaleRotatedHSMKeyLabels(keyLabel); removeErr != nil {
			return fmt.Errorf("remove stale rotated HSM keys for %s failed: %w", keyLabel, removeErr)
		}
		if existingKeyLabel := e.findHSMKeyLabel(keyLabel); existingKeyLabel != "" {
			if registerErr := e.registerTestKey(keyName, existingKeyLabel, keyTypeName, password); registerErr == nil {
				return nil
			} else if isPasswordMismatchError(registerErr) {
				if removeErr := e.removeHSMKeyLabels(keyLabel, existingKeyLabel); removeErr != nil {
					return fmt.Errorf("register existing key %s failed: %w; remove stale HSM key failed: %w", existingKeyLabel, registerErr, removeErr)
				}
				return createTestKey(e, createPath, data)
			} else {
				return registerErr
			}
		}
	}

	createKey := func() (*logical.Response, error) {
		return createKeyWithData(e, createPath, data)
	}

	resp, err = createKey()
	if err != nil {
		if keyLabel != "" {
			existingKeyLabel := e.findHSMKeyLabel(keyLabel)
			if existingKeyLabel == "" {
				existingKeyLabel = keyLabel
			}
			if registerErr := e.registerTestKey(keyName, existingKeyLabel, keyTypeName, password); registerErr == nil {
				return nil
			} else if isAlreadyExistsError(err) || isPasswordMismatchError(registerErr) {
				if removeErr := e.removeHSMKeyLabels(keyLabel, existingKeyLabel); removeErr != nil {
					return fmt.Errorf("%w; register existing key %s failed: %w; remove stale HSM key failed: %w", err, existingKeyLabel, registerErr, removeErr)
				}
				return createTestKey(e, createPath, data)
			}
		}
		return err
	}
	if resp != nil && resp.IsError() {
		if keyLabel != "" {
			existingKeyLabel := e.findHSMKeyLabel(keyLabel)
			if existingKeyLabel == "" {
				existingKeyLabel = keyLabel
			}
			if registerErr := e.registerTestKey(keyName, existingKeyLabel, keyTypeName, password); registerErr == nil {
				return nil
			} else if isAlreadyExistsError(resp.Error()) || isPasswordMismatchError(registerErr) {
				if removeErr := e.removeHSMKeyLabels(keyLabel, existingKeyLabel); removeErr != nil {
					return fmt.Errorf("%w; register existing key %s failed: %w; remove stale HSM key failed: %w", resp.Error(), existingKeyLabel, registerErr, removeErr)
				}
				return createTestKey(e, createPath, data)
			}
		}
		return resp.Error()
	}
	return nil
}

func createKeyWithData(e *TestEnv, createPath string, data map[string]interface{}) (*logical.Response, error) {
	return e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      createPath,
		Data:      data,
		Storage:   e.Storage,
	})
}

func createTestKey(e *TestEnv, createPath string, data map[string]interface{}) error {
	resp, err := createKeyWithData(e, createPath, data)
	if err != nil {
		return err
	}
	if resp != nil && resp.IsError() {
		return resp.Error()
	}
	return nil
}

func (e *TestEnv) findHSMKeyLabel(keyLabel string) string {
	resp, err := e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "keys_hsm",
		Storage:   e.Storage,
	})
	if err != nil || resp == nil || resp.IsError() {
		return ""
	}

	var exactMatch string
	var firstVersionMatch string
	collect := func(key string) {
		switch key {
		case keyLabel:
			exactMatch = key
		case keyLabel + "_v1":
			firstVersionMatch = key
		}
	}

	switch keys := resp.Data["keys"].(type) {
	case []string:
		for _, key := range keys {
			collect(key)
		}
	case []interface{}:
		for _, key := range keys {
			if keyString, ok := key.(string); ok {
				collect(keyString)
			}
		}
	}
	if firstVersionMatch != "" {
		return firstVersionMatch
	}
	if exactMatch != "" {
		return exactMatch
	}
	return ""
}

func (e *TestEnv) removeStaleRotatedHSMKeyLabels(keyLabel string) error {
	resp, err := e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "keys_hsm",
		Storage:   e.Storage,
	})
	if err != nil || resp == nil || resp.IsError() {
		return nil
	}

	var labels []string
	switch keys := resp.Data["keys"].(type) {
	case []string:
		labels = keys
	case []interface{}:
		for _, key := range keys {
			if keyString, ok := key.(string); ok {
				labels = append(labels, keyString)
			}
		}
	}

	var rotatedLabels []string
	for _, label := range labels {
		if isStaleRotatedHSMKeyLabel(keyLabel, label) {
			rotatedLabels = append(rotatedLabels, label)
		}
	}
	return e.removeHSMKeyLabels(rotatedLabels...)
}

func isStaleRotatedHSMKeyLabel(baseLabel string, label string) bool {
	prefix := baseLabel + "_v"
	if !strings.HasPrefix(label, prefix) {
		return false
	}
	version := strings.TrimPrefix(label, prefix)
	if version == "" || version == "1" {
		return false
	}
	for _, r := range version {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func keyTypeNameFromCreatePath(createPath string) string {
	const prefix = "keys/type/"
	if !strings.HasPrefix(createPath, prefix) {
		return ""
	}
	remaining := strings.TrimPrefix(createPath, prefix)
	keyTypeName, _, _ := strings.Cut(remaining, "/")
	return keyTypeName
}

func (e *TestEnv) registerTestKey(keyName, keyLabel string, keyTypeName string, password string) error {
	data := map[string]interface{}{"keyLabel": keyLabel}
	if keyTypeName != "" {
		data["keyTypeName"] = keyTypeName
	}
	if password != "" {
		data["password"] = password
	}
	resp, err := e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/" + keyName + "/register",
		Data:      data,
		Storage:   e.Storage,
	})
	if err != nil {
		return err
	}
	if resp != nil && resp.IsError() {
		return resp.Error()
	}
	return nil
}

func (e *TestEnv) removeHSMKeyLabel(keyLabel string) error {
	client, err := backend.Backend(&e.Conf).GetClient(context.Background(), e.Storage)
	if err != nil {
		return err
	}
	return client.RemoveKey(keyLabel)
}

func (e *TestEnv) removeHSMKeyLabels(labels ...string) error {
	var removeErr error
	seen := make(map[string]bool, len(labels))
	for _, label := range labels {
		if label == "" || seen[label] {
			continue
		}
		seen[label] = true
		if err := e.removeHSMKeyLabel(label); err != nil && !isNotExistsError(err) {
			removeErr = errors.Join(removeErr, fmt.Errorf("%s: %w", label, err))
		}
	}
	return removeErr
}

func (e *TestEnv) RemoveTestKeysRaw() error {
	var cleanupErr error
	keyNames := []string{
		"test_aes_256",
		"test_aes_256_rotate",
		"test_aes_128",
		"test_bls",
		"test_camellia",
		"test_chacha20",
		"test_dsa_1024",
		"test_ec_secp256k1",
		"test_ed_ed25519",
		"test_tdea",
		"test_rsa_2048",
		"test_rsa_2048_modify",
		"test_rsa_2048_pass",
		"test_rsa_2048_policy",
		"type_aes",
		"type_rsa_2048",
		"type_rsa_3072",
		"type_rsa_4096",
		"type_ec_p256",
		"type_ec_p384",
		"type_ec_p521",
	}

	for _, keyName := range keyNames {
		_, err := e.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      "keys/" + keyName,
			Data:      map[string]interface{}{"removeFromHSM": true},
			Storage:   e.Storage,
		})
		if err != nil {
			if !isNotExistsError(err) {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("%s: %w", keyName, err))
			}
		}
		time.Sleep(1000)
	}

	return cleanupErr
}

func isNotExistsError(err error) bool {
	if err == nil {
		return false
	}
	errString := strings.ToLower(err.Error())
	return strings.Contains(errString, "not exists") ||
		strings.Contains(errString, "not existent") ||
		strings.Contains(errString, "does not exist")
}

func isAlreadyExistsError(err error) bool {
	if err == nil {
		return false
	}
	errString := strings.ToLower(err.Error())
	return strings.Contains(errString, "already") || strings.Contains(errString, "existing")
}

func isPasswordMismatchError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "password mismatch")
}

// Function deletes test keys
func (e *TestEnv) RemoveTestKeys(t *testing.T) {
	t.Helper()
	if err := e.RemoveTestKeysRaw(); err != nil {
		fmt.Println(err.Error())
	}
}

// Function preparing a testing backend system
func GetTestBackend(tb testing.TB) (*backend.SecurosysBackend, logical.Storage) {
	tb.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	config.Logger = hclog.NewNullLogger()
	config.System = logical.TestSystemView()

	b, err := backend.Factory(context.Background(), config)
	if err != nil {
		tb.Fatal(err)
	}

	return b.(*backend.SecurosysBackend), config.StorageView
}

// Function thats make a request for delete key operation
func TestKeyDelete(t *testing.T, b logical.Backend, s logical.Storage, keyName string) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "keys/" + keyName,
		Data:      map[string]interface{}{"removeFromHSM": true},
		Storage:   s,
	})

	if err != nil {
		return err
	}

	if resp != nil && resp.IsError() {
		return resp.Error()
	}
	return nil
}

// Function thats make a request for create key operation
func TestKeyCreate(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}, keyName string, keyType string) error {
	t.Cleanup(func() {
		_ = TestKeyDelete(t, b, s, keyName)
	})

	return TestKeyCreateWithoutCleanup(b, s, d, keyName, keyType)
}

func TestKeyCreateWithoutCleanup(b logical.Backend, s logical.Storage, d map[string]interface{}, keyName string, keyType string) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/" + keyType + "/" + keyName,
		Data:      d,
		Storage:   s,
	})

	if err != nil {
		return err
	}

	if resp != nil && resp.IsError() {
		return resp.Error()
	}
	return nil
}

// Function thats make a request for reading key xml data
func TestKeyReadXML(t *testing.T, b logical.Backend, s logical.Storage, expected []string, keyName string) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "keys/" + keyName + "/xml",
		Storage:   s,
	})

	if err != nil {
		return err
	}
	if resp == nil && expected == nil {
		return nil
	}

	if resp.IsError() {
		return resp.Error()
	}

	for _, expectedV := range expected {
		actualV, ok := resp.Data[expectedV]
		if !ok {
			return fmt.Errorf(`expected data["%s"] = %v but was not included in read output`, expectedV, expectedV)
		}
		if actualV == "" || actualV == nil {
			return fmt.Errorf(`expected data["%s"] = is not empty`, expectedV)
		}
	}

	return nil
}

// Function thats make a request for reading key data
func TestKeyRead(t *testing.T, b logical.Backend, s logical.Storage, expected map[string]interface{}, keyName string) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "keys/" + keyName,
		Storage:   s,
	})

	if err != nil {
		return err
	}
	if resp == nil && expected == nil {
		return nil
	}

	if resp.IsError() {
		return resp.Error()
	}

	for k, expectedV := range expected {
		actualV, ok := resp.Data[k]
		if !ok {
			return fmt.Errorf(`expected data["%s"] = %v but was not included in read output`, k, expectedV)
		}
		result, err := AreEqual(expectedV, actualV)
		if err != nil {
			return fmt.Errorf(`unexpected error: %s`, err.Error())
		}
		if !result {
			return fmt.Errorf(`expected data["%s"] = %v, instead got %v`, k, expectedV, actualV)
		}
	}

	return nil
}
