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

package integrationTests

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"testing"

	"github.com/hashicorp/vault-client-go"
	"github.com/stretchr/testify/assert"
	integrationClient "securosys.ch/integration/client"
)

func TestOperationsEncryptPlugin(t *testing.T) {
	cleanupIntegrationKeysForTest(t)
	t.Run("D.1 Test Create Key TDEA Key with name integrationTestKeyTDEA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/tdea/integration_test_tdea_key", map[string]interface{}{
			"keyLabel": "integrationTestKeyTDEA",
			"keySize":  192,
			"attributes": `{
				"decrypt": true,
				"sign": false,
				"unwrap": true,
				"derive": true,
				"sensitive": false,
				"alwaysSensitive": false,
				"extractable": true,
				"neverExtractable": true,
				"modifiable": true,
				"copyable": false,
				"destroyable": true
			}`,
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Key response got %s", "null").Error())
		}
		if resp.Data["algorithm"].(string) != "TDEA" {
			assert.FailNow(t, fmt.Errorf("Expected: Key type %s got %s", "TDEA", resp.Data["algorithm"]).Error())
		}
		if resp.Data["baseLabel"].(string) != "integrationTestKeyTDEA" {
			assert.FailNow(t, fmt.Errorf("Expected: Key name %s got %s", "integrationTestKeyTDEA", resp.Data["baseLabel"]).Error())
		}
		if resp.Data["version"].(string) != "v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key version %s got %s", "v1", resp.Data["version"]).Error())
		}
		if resp.Data["keySize"].(json.Number) != json.Number("192") {
			assert.FailNow(t, fmt.Errorf("Expected: Key size %s got %s", "192", resp.Data["keySize"]).Error())
		}
		if resp.Data["keyLabel"].(string) != "integrationTestKeyTDEA_v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key label %s got %s", "integrationTestKeyTDEA_v1", resp.Data["keyLabel"]).Error())
		}
	})

	t.Run("D.1 Test Create Key CAMELLIA Key with name integrationTestKeyCAMELLIA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/camellia/integration_test_camellia_key", map[string]interface{}{
			"keyLabel": "integrationTestKeyCAMELLIA",
			"keySize":  256,
			"attributes": `{
				"decrypt": true,
				"sign": false,
				"unwrap": true,
				"derive": true,
				"sensitive": false,
				"alwaysSensitive": false,
				"extractable": true,
				"neverExtractable": true,
				"modifiable": true,
				"copyable": false,
				"destroyable": true
			}`,
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Key response got %s", "null").Error())
		}
		if resp.Data["algorithm"].(string) != "Camellia" {
			assert.FailNow(t, fmt.Errorf("Expected: Key type %s got %s", "Camellia", resp.Data["algorithm"]).Error())
		}
		if resp.Data["baseLabel"].(string) != "integrationTestKeyCAMELLIA" {
			assert.FailNow(t, fmt.Errorf("Expected: Key name %s got %s", "integrationTestKeyCAMELLIA", resp.Data["baseLabel"]).Error())
		}
		if resp.Data["version"].(string) != "v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key version %s got %s", "v1", resp.Data["version"]).Error())
		}
		if resp.Data["keyLabel"].(string) != "integrationTestKeyCAMELLIA_v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key label %s got %s", "integrationTestKeyCAMELLIA_v1", resp.Data["keyLabel"]).Error())
		}
	})
	t.Run("D.1 Test Create Key CHACHA20 Key with name integrationTestKeyCHACHA20", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/chacha20/integration_test_chacha20_key", map[string]interface{}{
			"keyLabel": "integrationTestKeyCHACHA20",
			"keySize":  256,
			"attributes": `{
				"decrypt": true,
				"sign": false,
				"unwrap": true,
				"derive": true,
				"sensitive": false,
				"alwaysSensitive": false,
				"extractable": true,
				"neverExtractable": true,
				"modifiable": true,
				"copyable": false,
				"destroyable": true
			}`,
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Key response got %s", "null").Error())
		}
		if resp.Data["algorithm"].(string) != "ChaCha20" {
			assert.FailNow(t, fmt.Errorf("Expected: Key type %s got %s", "ChaCha20", resp.Data["algorithm"]).Error())
		}
		if resp.Data["baseLabel"].(string) != "integrationTestKeyCHACHA20" {
			assert.FailNow(t, fmt.Errorf("Expected: Key name %s got %s", "integrationTestKeyCHACHA20", resp.Data["baseLabel"]).Error())
		}
		if resp.Data["version"].(string) != "v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key version %s got %s", "v1", resp.Data["version"]).Error())
		}
		if resp.Data["keyLabel"].(string) != "integrationTestKeyCHACHA20_v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key label %s got %s", "integrationTestKeyCHACHA20_v1", resp.Data["keyLabel"]).Error())
		}
	})
	t.Run("D.1 Test Create Key Smart RSA Key with name integrationTestKeySmartRSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/rsa/integration_test_smart_key_rsa", map[string]interface{}{
			"keyLabel": "integrationTestKeySmartRSA",
			"keySize":  2048,
			"attributes": `{
				"decrypt": true,
				"sign": true,
				"unwrap": true,
				"derive": true,
				"sensitive": false,
				"extractable": true,
				"modifiable": true,
				"copyable": false,
				"destroyable": true
			}`,
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Key response got %s", "null").Error())
		}
		if resp.Data["algorithm"].(string) != "RSA" {
			assert.FailNow(t, fmt.Errorf("Expected: Key type %s got %s", "RSA", resp.Data["algorithm"]).Error())
		}
		if resp.Data["baseLabel"].(string) != "integrationTestKeySmartRSA" {
			assert.FailNow(t, fmt.Errorf("Expected: Key name %s got %s", "integrationTestKeySmartRSA", resp.Data["baseLabel"]).Error())
		}
		if resp.Data["version"].(string) != "v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key version %s got %s", "v1", resp.Data["version"]).Error())
		}
		if resp.Data["keySize"].(json.Number) != json.Number("2048") {
			assert.FailNow(t, fmt.Errorf("Expected: Key size %s got %s", "2048", resp.Data["keySize"]).Error())
		}
		if resp.Data["keyLabel"].(string) != "integrationTestKeySmartRSA_v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key label %s got %s", "integrationTestKeySmartRSA_v1", resp.Data["keyLabel"]).Error())
		}
	})
	t.Run("D.1 Test Create Key AES Key with name integrationTestKeyAES", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/aes/integration_test_key_aes", map[string]interface{}{
			"keyLabel": "integrationTestKeyAES",
			"keySize":  256,
			"attributes": `{
				"decrypt": true,
				"sign": false,
				"unwrap": true,
				"derive": true,
				"sensitive": false,
				"alwaysSensitive": false,
				"extractable": true,
				"neverExtractable": true,
				"modifiable": true,
				"copyable": false,
				"destroyable": true
			}`,
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Key response got %s", "null").Error())
		}
		if resp.Data["algorithm"].(string) != "AES" {
			assert.FailNow(t, fmt.Errorf("Expected: Key type %s got %s", "AES", resp.Data["algorithm"]).Error())
		}
		if resp.Data["baseLabel"].(string) != "integrationTestKeyAES" {
			assert.FailNow(t, fmt.Errorf("Expected: Key name %s got %s", "integrationTestKeyAES", resp.Data["baseLabel"]).Error())
		}
		if resp.Data["version"].(string) != "v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key version %s got %s", "v1", resp.Data["version"]).Error())
		}
		if resp.Data["keySize"].(json.Number) != json.Number("256") {
			assert.FailNow(t, fmt.Errorf("Expected: Key size %s got %s", "256", resp.Data["keySize"]).Error())
		}
		if resp.Data["keyLabel"].(string) != "integrationTestKeyAES_v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key label %s got %s", "integrationTestKeyAES_v1", resp.Data["keyLabel"]).Error())
		}
	})

	t.Run("D.2 Test Encrypt AES - cipher AES", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/encrypt/integration_test_key_aes", map[string]interface{}{
			"payload":         "cGF5bG9hZAo=",
			"cipherAlgorithm": "AES",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload got %s", "null").Error())
		}
		if resp.Data["encryptedPayload"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload %s", "null").Error())
		}
	})
	t.Run("D.2 Test Encrypt AES -  after rotate - cipher AES_GCM - 96", func(t *testing.T) {
		ctx := context.Background()
		client := integrationClient.InitVaultClient()
		_, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_aes/rotate", map[string]interface{}{})
		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/encrypt/integration_test_key_aes", map[string]interface{}{
			"payload":         "cGF5bG9hZAo=",
			"tagLength":       -1,
			"cipherAlgorithm": "AES_GCM",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload got %s", "null").Error())
		}
		if resp.Data["encryptedPayload"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload %s", "null").Error())
		}
	})
	t.Run("D.2 Test Encrypt AES - cipher AES_GCM", func(t *testing.T) {
		ctx := context.Background()
		client := integrationClient.InitVaultClient()
		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/encrypt/integration_test_key_aes", map[string]interface{}{
			"cipherAlgorithm": "AES_GCM",
			"payload":         "cGF5bG9hZA==",
			"tagLength":       -1,
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload got %s", "null").Error())
		}
		if resp.Data["encryptedPayload"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload %s", "null").Error())
		}
	})
	t.Run("D.2 Test Encrypt AES - cipher CTR", func(t *testing.T) {
		ctx := context.Background()
		client := integrationClient.InitVaultClient()
		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/encrypt/integration_test_key_aes", map[string]interface{}{
			"cipherAlgorithm": "AES_CTR",
			"payload":         "cGF5bG9hZA==",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload got %s", "null").Error())
		}
		if resp.Data["encryptedPayload"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload %s", "null").Error())
		}
	})
	t.Run("D.2 Test Encrypt AES - cipher ECB", func(t *testing.T) {
		ctx := context.Background()
		client := integrationClient.InitVaultClient()
		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/encrypt/integration_test_key_aes", map[string]interface{}{
			"cipherAlgorithm": "AES_ECB",
			"payload":         "cGF5bG9hZA==",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload got %s", "null").Error())
		}
		if resp.Data["encryptedPayload"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload %s", "null").Error())
		}
	})
	t.Run("D.2 Test Encrypt AES - cipher AES_CBC_NO_PADDING", func(t *testing.T) {
		ctx := context.Background()
		client := integrationClient.InitVaultClient()
		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/encrypt/integration_test_key_aes", map[string]interface{}{
			"cipherAlgorithm": "AES_CBC_NO_PADDING",
			"payload":         "cGF5bG9hZA==",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload got %s", "null").Error())
		}
		if resp.Data["encryptedPayload"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload %s", "null").Error())
		}
	})
	t.Run("D.2 Test Encrypt AES - wrong AES cipher algorithm", func(t *testing.T) {
		ctx := context.Background()
		client := integrationClient.InitVaultClient()
		_, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/encrypt/integration_test_key_aes", map[string]interface{}{
			"cipherAlgorithm": "RSA",
			"payload":         "cGF5bG9hZA==",
		})
		assert.Error(t, err)

	})
	t.Run("D.2 Test Encrypt AES - wrong tagLength ", func(t *testing.T) {
		ctx := context.Background()
		client := integrationClient.InitVaultClient()
		_, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/encrypt/integration_test_key_aes", map[string]interface{}{
			"cipherAlgorithm": "AES_GCM",
			"payload":         "cGF5bG9hZA==",
			"tagLength":       256,
		})
		assert.Error(t, err)

	})

	t.Run("D.2 Test Encrypt - No payload", func(t *testing.T) {
		ctx := context.Background()
		client := integrationClient.InitVaultClient()
		_, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/encrypt/integration_test_key_aes", map[string]interface{}{
			"cipherAlgorithm": "AES",
		})
		assert.Error(t, err)

	})
	t.Run("D.2 Test Encrypt - Wrong payload format", func(t *testing.T) {
		ctx := context.Background()
		client := integrationClient.InitVaultClient()
		_, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/encrypt/integration_test_key_aes", map[string]interface{}{
			"cipherAlgorithm": "AES",
			"payload":         "aaaaaa",
		})
		assert.Error(t, err)

	})
	t.Run("D.2 Test Encrypt - Wrong key name", func(t *testing.T) {
		ctx := context.Background()
		client := integrationClient.InitVaultClient()
		_, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/encrypt/integration_test_key_aes2", map[string]interface{}{
			"cipherAlgorithm": "AES_GCM",
			"payload":         "cGF5bG9hZA==",
			"tagLength":       256,
		})
		assert.Error(t, err)

	})
	t.Run("D.2 Test Encrypt - Wrong key algorithm", func(t *testing.T) {
		ctx := context.Background()
		client := integrationClient.InitVaultClient()
		_, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/encrypt/integration_test_key_aes", map[string]interface{}{
			"cipherAlgorithm": "RSA",
			"payload":         "cGF5bG9hZA==",
			"tagLength":       256,
		})
		assert.Error(t, err)

	})
	t.Run("D.2 Test Encrypt - No cipher algorithm", func(t *testing.T) {
		ctx := context.Background()
		client := integrationClient.InitVaultClient()
		_, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/encrypt/integration_test_key_aes", map[string]interface{}{
			"payload": "cGF5bG9hZA==",
		})
		assert.Error(t, err)

	})
	t.Run("D.2 Test Encrypt - wrong AAD ", func(t *testing.T) {
		ctx := context.Background()
		client := integrationClient.InitVaultClient()
		_, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/encrypt/integration_test_key_aes", map[string]interface{}{
			"cipherAlgorithm":              "AES_GCM",
			"payload":                      "cGF5bG9hZA==",
			"additionalAuthenticationData": "wrong_base64",
		})
		assert.Error(t, err)

	})
	t.Run("D.2 Test Encrypt RSA - cipher RSA_PADDING_OAEP_WITH_SHA512", func(t *testing.T) {
		ctx := context.Background()
		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/encrypt/integration_test_smart_key_rsa", map[string]interface{}{
			"cipherAlgorithm": "RSA_PADDING_OAEP_WITH_SHA512",
			"payload":         "cGF5bG9hZA==",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload got %s", "null").Error())
		}
		if resp.Data["encryptedPayload"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload %s", "null").Error())
		}

	})
	t.Run("D.2 Test Encrypt RSA - cipher RSA", func(t *testing.T) {
		ctx := context.Background()
		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/encrypt/integration_test_smart_key_rsa", map[string]interface{}{
			"cipherAlgorithm": "RSA",
			"payload":         "cGF5bG9hZA==",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload got %s", "null").Error())
		}
		if resp.Data["encryptedPayload"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload %s", "null").Error())
		}

	})
	t.Run("D.2 Test Encrypt RSA - cipher RSA_PADDING_OAEP_WITH_SHA224", func(t *testing.T) {
		ctx := context.Background()
		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/encrypt/integration_test_smart_key_rsa", map[string]interface{}{
			"cipherAlgorithm": "RSA_PADDING_OAEP_WITH_SHA224",
			"payload":         "cGF5bG9hZA==",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload got %s", "null").Error())
		}
		if resp.Data["encryptedPayload"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload %s", "null").Error())
		}

	})
	t.Run("D.2 Test Encrypt RSA - cipher RSA_PADDING_OAEP_WITH_SHA256", func(t *testing.T) {
		ctx := context.Background()
		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/encrypt/integration_test_smart_key_rsa", map[string]interface{}{
			"cipherAlgorithm": "RSA_PADDING_OAEP_WITH_SHA256",
			"payload":         "cGF5bG9hZA==",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload got %s", "null").Error())
		}
		if resp.Data["encryptedPayload"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload %s", "null").Error())
		}

	})
	t.Run("D.2 Test Encrypt RSA - cipher RSA_PADDING_OAEP_WITH_SHA1", func(t *testing.T) {
		ctx := context.Background()
		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/encrypt/integration_test_smart_key_rsa", map[string]interface{}{
			"cipherAlgorithm": "RSA_PADDING_OAEP_WITH_SHA1",
			"payload":         "cGF5bG9hZA==",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload got %s", "null").Error())
		}
		if resp.Data["encryptedPayload"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload %s", "null").Error())
		}
	})
	t.Run("D.2 Test Encrypt RSA - cipher RSA_PADDING_OAEP", func(t *testing.T) {
		ctx := context.Background()
		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/encrypt/integration_test_smart_key_rsa", map[string]interface{}{
			"cipherAlgorithm": "RSA_PADDING_OAEP",
			"payload":         "cGF5bG9hZA==",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload got %s", "null").Error())
		}
		if resp.Data["encryptedPayload"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload %s", "null").Error())
		}
	})
	t.Run("D.2 Test Encrypt RSA - cipher RSA_PADDING_OAEP_WITH_SHA384", func(t *testing.T) {
		ctx := context.Background()
		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/encrypt/integration_test_smart_key_rsa", map[string]interface{}{
			"cipherAlgorithm": "RSA_PADDING_OAEP_WITH_SHA384",
			"payload":         "cGF5bG9hZA==",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload got %s", "null").Error())
		}
		if resp.Data["encryptedPayload"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload %s", "null").Error())
		}
	})
	t.Run("D.2 Test Encrypt RSA - cipher RSA_NO_PADDING", func(t *testing.T) {
		ctx := context.Background()
		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/encrypt/integration_test_smart_key_rsa", map[string]interface{}{
			"cipherAlgorithm": "RSA_NO_PADDING",
			"payload":         "cGF5bG9hZA==",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload got %s", "null").Error())
		}
		if resp.Data["encryptedPayload"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload %s", "null").Error())
		}
	})
	t.Run("D.2 Test Encrypt CHACHA20 - cipher CHACHA20_AEAD", func(t *testing.T) {
		ctx := context.Background()
		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/encrypt/integration_test_chacha20_key", map[string]interface{}{
			"cipherAlgorithm":              "CHACHA20_AEAD",
			"payload":                      "cGF5bG9hZA==",
			"additionalAuthenticationData": "QWRkaXRpb25hbCBBdXRoZW50aWNhdGlvbiBEYXRh",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload got %s", "null").Error())
		}
		if resp.Data["encryptedPayload"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload %s", "null").Error())
		}
	})
	t.Run("D.2 Test Encrypt CHACHA20 - cipher CHACHA20", func(t *testing.T) {
		ctx := context.Background()
		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/encrypt/integration_test_chacha20_key", map[string]interface{}{
			"cipherAlgorithm": "CHACHA20",
			"payload":         "cGF5bG9hZA==",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload got %s", "null").Error())
		}
		if resp.Data["encryptedPayload"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload %s", "null").Error())
		}
	})
	t.Run("D.2 Test Encrypt CAMELLIA - cipher CAMELLIA", func(t *testing.T) {
		ctx := context.Background()
		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/encrypt/integration_test_camellia_key", map[string]interface{}{
			"cipherAlgorithm": "CAMELLIA",
			"payload":         "cGF5bG9hZA==",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload got %s", "null").Error())
		}
		if resp.Data["encryptedPayload"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload %s", "null").Error())
		}
	})
	t.Run("D.2 Test Encrypt CAMELLIA - cipher CAMELLIA_CBC_NO_PADDING", func(t *testing.T) {
		ctx := context.Background()
		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/encrypt/integration_test_camellia_key", map[string]interface{}{
			"cipherAlgorithm": "CAMELLIA_CBC_NO_PADDING",
			"payload":         "cGF5bG9hZA==",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload got %s", "null").Error())
		}
		if resp.Data["encryptedPayload"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload %s", "null").Error())
		}
	})
	t.Run("D.2 Test Encrypt CAMELLIA - cipher CAMELLIA_ECB", func(t *testing.T) {
		ctx := context.Background()
		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/encrypt/integration_test_camellia_key", map[string]interface{}{
			"cipherAlgorithm": "CAMELLIA_ECB",
			"payload":         "cGF5bG9hZA==",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload got %s", "null").Error())
		}
		if resp.Data["encryptedPayload"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload %s", "null").Error())
		}
	})
	t.Run("D.2 Test Encrypt TDEA - cipher TDEA_CBC", func(t *testing.T) {
		ctx := context.Background()
		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/encrypt/integration_test_tdea_key", map[string]interface{}{
			"cipherAlgorithm": "TDEA_CBC",
			"payload":         "cGF5bG9hZA==",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload got %s", "null").Error())
		}
		if resp.Data["encryptedPayload"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload %s", "null").Error())
		}
	})
	t.Run("D.2 Test Encrypt TDEA - cipher TDEA_CBC_NO_PADDING", func(t *testing.T) {
		ctx := context.Background()
		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/encrypt/integration_test_tdea_key", map[string]interface{}{
			"cipherAlgorithm": "TDEA_CBC_NO_PADDING",
			"payload":         "cGF5bG9hZA==",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload got %s", "null").Error())
		}
		if resp.Data["encryptedPayload"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload %s", "null").Error())
		}
	})
	t.Run("D.2 Test Encrypt TDEA - cipher TDEA_ECB", func(t *testing.T) {
		ctx := context.Background()
		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/encrypt/integration_test_tdea_key", map[string]interface{}{
			"cipherAlgorithm": "TDEA_ECB",
			"payload":         "cGF5bG9hZA==",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload got %s", "null").Error())
		}
		if resp.Data["encryptedPayload"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Encrypted payload %s", "null").Error())
		}
	})
	t.Run("D.3 Test Remove Key Smart RSA Key with name integrationTestKeySmartRSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		_, err := client.Delete(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_smart_key_rsa", vault.WithQueryParameters(url.Values{
			"removeFromHSM": {"true"},
		}))
		if err != nil {
			assert.FailNow(t, err.Error())
		}
	})
	t.Run("D.3 Test Remove Key AES Key with name integrationTestKeyAES", func(t *testing.T) {

		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		_, err := client.Delete(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_aes", vault.WithQueryParameters(url.Values{
			"removeFromHSM": {"true"},
		}))
		if err != nil {
			assert.FailNow(t, err.Error())
		}
	})
	t.Run("D.3 Test Remove Key CHACHA20 Key with name integrationTestKeyCHACHA20", func(t *testing.T) {

		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		_, err := client.Delete(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_chacha20_key", vault.WithQueryParameters(url.Values{
			"removeFromHSM": {"true"},
		}))
		if err != nil {
			assert.FailNow(t, err.Error())
		}
	})
	t.Run("D.3 Test Remove Key CAMELIA Key with name integrationTestKeyCAMELLIA", func(t *testing.T) {

		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		_, err := client.Delete(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_camellia_key", vault.WithQueryParameters(url.Values{
			"removeFromHSM": {"true"},
		}))
		if err != nil {
			assert.FailNow(t, err.Error())
		}
	})
	t.Run("D.3 Test Remove Key TDEA Key with name integrationTestKeyTDEA", func(t *testing.T) {

		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		_, err := client.Delete(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_tdea_key", vault.WithQueryParameters(url.Values{
			"removeFromHSM": {"true"},
		}))
		if err != nil {
			assert.FailNow(t, err.Error())
		}
	})
}
