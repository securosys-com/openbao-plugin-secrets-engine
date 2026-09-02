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

func TestOperationsOnKeyPlugin(t *testing.T) {
	cleanupIntegrationKeysForTest(t)

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
				"alwaysSensitive": false,
				"extractable": false,
				"neverExtractable": true,
				"modifiable": true,
				"copyable": false,
				"destroyable": true
			}`,
			"simplePolicy": "{}",
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
	t.Run("D.2 Test Create Key AES Key with name integrationTestKeyAES", func(t *testing.T) {
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
	t.Run("D.3 Test Encrypt using integrationTestKeySmartRSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/encrypt/integration_test_smart_key_rsa", map[string]interface{}{
			"payload":         "cGF5bG9hZAo=",
			"cipherAlgorithm": "RSA",
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
	t.Run("D.4 Test Encrypt using integrationTestKeyAES", func(t *testing.T) {
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
	t.Run("D.5 Test Decrypt using integrationTestKeySmartRSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/encrypt/integration_test_smart_key_rsa", map[string]interface{}{
			"payload":         "cGF5bG9hZAo=",
			"cipherAlgorithm": "RSA",
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
		resp, err = client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/decrypt/integration_test_smart_key_rsa", map[string]interface{}{
			"encryptedPayload":     resp.Data["encryptedPayload"].(string),
			"keyVersion":           "v1",
			"initializationVector": resp.Data["initializationVector"],
			"cipherAlgorithm":      "RSA",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Payload got %s", "null").Error())
		}
		if resp.Data["payload"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Payload got %s", "null").Error())
		}
		if resp.Data["payload"] != "cGF5bG9hZAo=" {
			assert.FailNow(t, fmt.Errorf("Expected: Payload %s got %s", "cGF5bG9hZAo=", resp.Data["payload"]).Error())
		}

	})
	t.Run("D.6 Test Decrypt using integrationTestKeyAES", func(t *testing.T) {
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
		resp, err = client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/decrypt/integration_test_key_aes", map[string]interface{}{
			"encryptedPayload":     resp.Data["encryptedPayload"].(string),
			"keyVersion":           "v1",
			"initializationVector": resp.Data["initializationVector"],
			"cipherAlgorithm":      "AES",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Payload got %s", "null").Error())
		}
		if resp.Data["payload"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Payload got %s", "null").Error())
		}
		if resp.Data["payload"] != "cGF5bG9hZAo=" {
			assert.FailNow(t, fmt.Errorf("Expected: Payload %s got %s", "cGF5bG9hZAo=", resp.Data["payload"]).Error())
		}

	})
	t.Run("D.7 Test Sign using integrationTestKeySmartRSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/sign/integration_test_smart_key_rsa", map[string]interface{}{
			"payload":            "cGF5bG9hZAo=",
			"signatureAlgorithm": "SHA256_WITH_RSA",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Signature got %s", "null").Error())
		}
		if resp.Data["signature"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Signature %s", "null").Error())
		}
	})
	t.Run("D.8 Test Verify using integrationTestKeySmartRSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/sign/integration_test_smart_key_rsa", map[string]interface{}{
			"payload":            "cGF5bG9hZAo=",
			"signatureAlgorithm": "SHA256_WITH_RSA",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Signature got %s", "null").Error())
		}
		if resp.Data["signature"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Signature %s", "null").Error())
		}
		resp, err = client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/verify/integration_test_smart_key_rsa", map[string]interface{}{
			"payload":            "cGF5bG9hZAo=",
			"keyVersion":         "v1",
			"signatureAlgorithm": "SHA256_WITH_RSA",
			"signature":          resp.Data["signature"].(string),
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: SignatureValid got %s", "null").Error())
		}
		if resp.Data["signatureValid"] == false {
			assert.FailNow(t, fmt.Errorf("Expected: SignatureValid %s got %s", "true", resp.Data["signatureValid"]).Error())
		}
	})
	t.Run("D.9 Test Modify using integrationTestKeySmartRSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		_, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_smart_key_rsa/modify", map[string]interface{}{
			"simplePolicy": `{"test":"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnydX62tLYNF+Op1SRnX6avkkyQWlpYPagH85zxaGnMlZoMioqgjSOCuRvjaP7Y5noPMYayp3gJ2PwLXvw9+JlnL+iwklOcpONSa6gDoCDsk26DOoY0ELEPaGdW61mc2bj2hOQE0GEpPsRywJoRLS3B2e8bqRfAniAfGsUq3MK09iL5YOCuUCHCUiR9iZMSt0+Ek/kE4TrazbOCev1g6Ux2vOyTuQ6mF3wVuqwd8RhfvlNNKXbD2GD/jR3BwuhaodwzRPmDyDQPmEMwornxrMLavTcC+Igb4k5qol0Di6Oq8axpBvrH7KlxHT11Wd+ALKCsqoPSGxcIbd6TdN+ag9AQIDAQAB"}`,
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
	})
	t.Run("D.10 Test Remove Key Smart RSA Key with name integrationTestKeySmartRSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		_, err := client.Delete(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_smart_key_rsa", vault.WithQueryParameters(url.Values{
			"removeFromHSM": {"true"},
		}))
		if err != nil {
			assert.FailNow(t, err.Error())
		}
	})
	t.Run("D.11 Test Remove Key AES Key with name integrationTestKeyAES", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		_, err := client.Delete(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_aes", vault.WithQueryParameters(url.Values{
			"removeFromHSM": {"true"},
		}))
		if err != nil {
			assert.FailNow(t, err.Error())
		}
	})
}
