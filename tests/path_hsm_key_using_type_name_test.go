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

package tests

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	testHelpers "securosys.ch/test-helpers"
)

func TestCreateKeyUsingTypeName(t *testing.T) {
	testHelpers.RequireTSBConfig(t)

	testEnv, err := testHelpers.NewTestEnv()
	if err != nil {
		t.Fatal(err)
	}
	t.Run("add config", testEnv.AddConfig)
	t.Run("Test Creating Key with type name = chacha20-poly1305", func(t *testing.T) {
		now := time.Now().UTC()
		timeStr := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02dZ", now.Year(), int(now.Month()), now.Day(), now.Hour(), now.Minute(), now.Second())
		err := testKeyUsingNameCreate(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_chacha20-poly1305_" + timeStr,
			"attributes": `{"decrypt": true,"sign": false,"unwrap": true,"derive": true,"sensitive": false,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
		}, "chacha20-poly1305", "custom_chacha20-poly1305")

		assert.NoError(t, err)

		err = testHelpers.TestKeyRead(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"baseLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_chacha20-poly1305_" + timeStr,
			"algorithm":   "ChaCha20",
			"keySize":     256,
			"keyTypeName": "chacha20-poly1305",
		}, "custom_chacha20-poly1305")
		if err != nil {
			testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_chacha20-poly1305")
		}
		assert.NoError(t, err)

		err = testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_chacha20-poly1305")

		assert.NoError(t, err)
	})

	t.Run("Test Creating Key with type name = aes256-gcm96", func(t *testing.T) {
		now := time.Now().UTC()
		timeStr := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02dZ", now.Year(), int(now.Month()), now.Day(), now.Hour(), now.Minute(), now.Second())
		err := testKeyUsingNameCreate(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_aes256-gcm96_" + timeStr,
			"attributes": `{"decrypt": true,"sign": false,"unwrap": true,"derive": true,"sensitive": false,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
		}, "aes256-gcm96", "custom_aes256-gcm96_aes")

		assert.NoError(t, err)

		err = testHelpers.TestKeyRead(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"baseLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_aes256-gcm96_" + timeStr,
			"algorithm":   "AES",
			"keySize":     256,
			"keyTypeName": "aes256-gcm96",
		}, "custom_aes256-gcm96_aes")
		if err != nil {
			testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_aes256-gcm96_aes")
		}
		assert.NoError(t, err)

		err = testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_aes256-gcm96_aes")

		assert.NoError(t, err)
	})
	t.Run("Test Creating Key with type name = aes128-gcm96", func(t *testing.T) {
		now := time.Now().UTC()
		timeStr := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02dZ", now.Year(), int(now.Month()), now.Day(), now.Hour(), now.Minute(), now.Second())
		err := testKeyUsingNameCreate(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_aes128-gcm96_" + timeStr,
			"attributes": `{"decrypt": true,"sign": false,"unwrap": true,"derive": true,"sensitive": false,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
		}, "aes128-gcm96", "custom_aes128-gcm96_aes")

		assert.NoError(t, err)

		err = testHelpers.TestKeyRead(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"baseLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_aes128-gcm96_" + timeStr,
			"algorithm":   "AES",
			"keySize":     128,
			"keyTypeName": "aes128-gcm96",
		}, "custom_aes128-gcm96_aes")
		if err != nil {
			testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_aes128-gcm96_aes")
		}
		assert.NoError(t, err)

		err = testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_aes128-gcm96_aes")

		assert.NoError(t, err)
	})
	t.Run("Test Creating Key with type name = rsa-2048", func(t *testing.T) {
		now := time.Now().UTC()
		timeStr := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02dZ", now.Year(), int(now.Month()), now.Day(), now.Hour(), now.Minute(), now.Second())
		err := testKeyUsingNameCreate(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_rsa-2048_" + timeStr,
			"attributes": `{"decrypt": true,"sign": false,"unwrap": true,"derive": true,"sensitive": false,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
		}, "rsa-2048", "custom_rsa-2048")

		assert.NoError(t, err)

		err = testHelpers.TestKeyRead(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"baseLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_rsa-2048_" + timeStr,
			"algorithm":   "RSA",
			"keySize":     2048,
			"keyTypeName": "rsa-2048",
		}, "custom_rsa-2048")
		if err != nil {
			testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_rsa-2048")
		}
		assert.NoError(t, err)

		err = testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_rsa-2048")

		assert.NoError(t, err)
	})
	t.Run("Test Creating Key with type name = rsa-3072", func(t *testing.T) {
		now := time.Now().UTC()
		timeStr := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02dZ", now.Year(), int(now.Month()), now.Day(), now.Hour(), now.Minute(), now.Second())
		err := testKeyUsingNameCreate(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_rsa-3072_" + timeStr,
			"attributes": `{"decrypt": true,"sign": false,"unwrap": true,"derive": true,"sensitive": false,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
		}, "rsa-3072", "custom_rsa-3072")

		assert.NoError(t, err)

		err = testHelpers.TestKeyRead(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"baseLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_rsa-3072_" + timeStr,
			"algorithm":   "RSA",
			"keySize":     3072,
			"keyTypeName": "rsa-3072",
		}, "custom_rsa-3072")
		if err != nil {
			testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_rsa-3072")
		}
		assert.NoError(t, err)

		err = testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_rsa-3072")

		assert.NoError(t, err)
	})
	t.Run("Test Creating Key with type name = rsa-4096", func(t *testing.T) {
		now := time.Now().UTC()
		timeStr := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02dZ", now.Year(), int(now.Month()), now.Day(), now.Hour(), now.Minute(), now.Second())
		err := testKeyUsingNameCreate(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_rsa-4096_" + timeStr,
			"attributes": `{"decrypt": true,"sign": false,"unwrap": true,"derive": true,"sensitive": false,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
		}, "rsa-4096", "custom_rsa-4096")

		assert.NoError(t, err)

		err = testHelpers.TestKeyRead(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"baseLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_rsa-4096_" + timeStr,
			"algorithm":   "RSA",
			"keySize":     4096,
			"keyTypeName": "rsa-4096",
		}, "custom_rsa-4096")
		if err != nil {
			testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_rsa-4096")
		}
		assert.NoError(t, err)

		err = testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_rsa-4096")

		assert.NoError(t, err)
	})
	t.Run("Test Creating Key with type name = ecdsa-p256", func(t *testing.T) {
		now := time.Now().UTC()
		timeStr := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02dZ", now.Year(), int(now.Month()), now.Day(), now.Hour(), now.Minute(), now.Second())
		err := testKeyUsingNameCreate(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_ecdsa-p256_" + timeStr,
			"attributes": `{"decrypt": true,"sign": false,"unwrap": true,"derive": true,"sensitive": false,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
		}, "ecdsa-p256", "custom_ecdsa-p256")

		assert.NoError(t, err)

		err = testHelpers.TestKeyRead(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"baseLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_ecdsa-p256_" + timeStr,
			"algorithm":   "EC",
			"curveOid":    "1.2.840.10045.3.1.7",
			"keyTypeName": "ecdsa-p256",
		}, "custom_ecdsa-p256")
		if err != nil {
			testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_ecdsa-p256")
		}
		assert.NoError(t, err)

		err = testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_ecdsa-p256")

		assert.NoError(t, err)
	})
	t.Run("Test Creating Key with type name = ecdsa-p384", func(t *testing.T) {
		now := time.Now().UTC()
		timeStr := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02dZ", now.Year(), int(now.Month()), now.Day(), now.Hour(), now.Minute(), now.Second())
		err := testKeyUsingNameCreate(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_ecdsa-p384_" + timeStr,
			"attributes": `{"decrypt": true,"sign": false,"unwrap": true,"derive": true,"sensitive": false,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
		}, "ecdsa-p384", "custom_ecdsa-p384")

		assert.NoError(t, err)

		err = testHelpers.TestKeyRead(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"baseLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_ecdsa-p384_" + timeStr,
			"algorithm":   "EC",
			"curveOid":    "1.3.132.0.34",
			"keyTypeName": "ecdsa-p384",
		}, "custom_ecdsa-p384")
		if err != nil {
			testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_ecdsa-p384")
		}
		assert.NoError(t, err)

		err = testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_ecdsa-p384")

		assert.NoError(t, err)
	})
	t.Run("Test Creating Key with type name = ed25519", func(t *testing.T) {
		now := time.Now().UTC()
		timeStr := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02dZ", now.Year(), int(now.Month()), now.Day(), now.Hour(), now.Minute(), now.Second())
		err := testKeyUsingNameCreate(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_ed25519_" + timeStr,
			"attributes": `{"decrypt": true,"sign": false,"unwrap": true,"derive": true,"sensitive": false,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
		}, "ed25519", "custom_ed25519")

		assert.NoError(t, err)

		err = testHelpers.TestKeyRead(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"baseLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_ed25519_" + timeStr,
			"algorithm":   "ED",
			"curveOid":    "1.3.101.112",
			"keyTypeName": "ed25519",
		}, "custom_ed25519")
		if err != nil {
			testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_ed25519")
		}
		assert.NoError(t, err)

		err = testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_ed25519")

		assert.NoError(t, err)
	})
	t.Run("Test Creating Key with type name = ecdsa-p521", func(t *testing.T) {
		now := time.Now().UTC()
		timeStr := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02dZ", now.Year(), int(now.Month()), now.Day(), now.Hour(), now.Minute(), now.Second())
		err := testKeyUsingNameCreate(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_ecdsa-p521_" + timeStr,
			"attributes": `{"decrypt": true,"sign": false,"unwrap": true,"derive": true,"sensitive": false,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
		}, "ecdsa-p521", "custom_ecdsa-p521")

		assert.NoError(t, err)

		err = testHelpers.TestKeyRead(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"baseLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_ecdsa-p521_" + timeStr,
			"algorithm":   "EC",
			"curveOid":    "1.3.132.0.35",
			"keyTypeName": "ecdsa-p521",
		}, "custom_ecdsa-p521")
		if err != nil {
			testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_ecdsa-p521")
		}
		assert.NoError(t, err)

		err = testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_ecdsa-p521")

		assert.NoError(t, err)
	})
	t.Run("Test Creating Key with type name = that is not supported", func(t *testing.T) {
		now := time.Now().UTC()
		timeStr := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02dZ", now.Year(), int(now.Month()), now.Day(), now.Hour(), now.Minute(), now.Second())
		err := testKeyUsingNameCreate(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_ecdsa-p921_" + timeStr,
			"attributes": `{"decrypt": true,"sign": false,"unwrap": true,"derive": true,"sensitive": false,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
		}, "ecdsa-p921", "custom_ecdsa-p921")
		if err == nil {
			assert.FailNow(t, fmt.Sprintf("Expected error: 'Key type name ecdsa-p921 is not supported. Available key type names [aes256-gcm96 rsa-2048 rsa-3072 rsa-4096 ecdsa-p256 ecdsa-p384 ecdsa-p521]', but error is nil"))
		}

	})

}

func testKeyUsingNameCreate(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}, keyTypeName string, keyName string) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/type/" + keyTypeName + "/" + keyName,
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		return fmt.Errorf(err.Error())
	}

	if resp != nil && resp.IsError() {
		return resp.Error()
	}
	return nil
}
