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

func TestOperationsWrapPlugin(t *testing.T) {
	cleanupIntegrationKeysForTest(t)

	t.Run("D.1 Test Create Key RSA Key with name integrationTestKeyRSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/rsa/integration_test_key_rsa", map[string]interface{}{
			"keyLabel": "integrationTestKeyRSA",
			"keySize":  2048,
			"attributes": `{
				"decrypt": true,
				"sign": true,
				"wrap": true,
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
		if resp.Data["baseLabel"].(string) != "integrationTestKeyRSA" {
			assert.FailNow(t, fmt.Errorf("Expected: Key name %s got %s", "integrationTestKeyRSA", resp.Data["baseLabel"]).Error())
		}
		if resp.Data["version"].(string) != "v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key version %s got %s", "v1", resp.Data["version"]).Error())
		}
		if resp.Data["keySize"].(json.Number) != json.Number("2048") {
			assert.FailNow(t, fmt.Errorf("Expected: Key size %s got %s", "2048", resp.Data["keySize"]).Error())
		}
		if resp.Data["keyLabel"].(string) != "integrationTestKeyRSA_v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key label %s got %s", "integrationTestKeyRSA_v1", resp.Data["keyLabel"]).Error())
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
				"wrap": true,
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
	t.Run("D.1 Test Create Key RSA Key with name integrationTestKeyRSAWrapTest", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/rsa/integration_test_key_rsa_wrap", map[string]interface{}{
			"keyLabel": "integrationTestKeyRSAWrapTest",
			"keySize":  2048,
			"attributes": `{
				"decrypt": true,
				"sign": true,
				"wrap": true,
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
		if resp.Data["baseLabel"].(string) != "integrationTestKeyRSAWrapTest" {
			assert.FailNow(t, fmt.Errorf("Expected: Key name %s got %s", "integrationTestKeyRSAWrapTest", resp.Data["baseLabel"]).Error())
		}
		if resp.Data["version"].(string) != "v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key version %s got %s", "v1", resp.Data["version"]).Error())
		}
		if resp.Data["keySize"].(json.Number) != json.Number("2048") {
			assert.FailNow(t, fmt.Errorf("Expected: Key size %s got %s", "2048", resp.Data["keySize"]).Error())
		}
		if resp.Data["keyLabel"].(string) != "integrationTestKeyRSAWrapTest_v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key label %s got %s", "integrationTestKeyRSAWrapTest_v1", resp.Data["keyLabel"]).Error())
		}
	})
	t.Run("D.1 Test Create Key AES Key with name integrationTestKeyAESWrapTest", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/aes/integration_test_key_aes_wrap", map[string]interface{}{
			"keyLabel": "integrationTestKeyAESWrapTest",
			"keySize":  128,
			"attributes": `{
				"decrypt": true,
				"sign": false,
				"unwrap": true,
				"wrap": true,
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
		if resp.Data["baseLabel"].(string) != "integrationTestKeyAESWrapTest" {
			assert.FailNow(t, fmt.Errorf("Expected: Key name %s got %s", "integrationTestKeyAESWrapTest", resp.Data["baseLabel"]).Error())
		}
		if resp.Data["version"].(string) != "v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key version %s got %s", "v1", resp.Data["version"]).Error())
		}
		if resp.Data["keySize"].(json.Number) != json.Number("128") {
			assert.FailNow(t, fmt.Errorf("Expected: Key size %s got %s", "128", resp.Data["keySize"]).Error())
		}
		if resp.Data["keyLabel"].(string) != "integrationTestKeyAESWrapTest_v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key label %s got %s", "integrationTestKeyAESWrapTest_v1", resp.Data["keyLabel"]).Error())
		}
	})
	t.Run("D.1 Test Create Key DSA Key with name integrationTestKeyDSAWrapTest", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/dsa/integration_test_key_dsa_wrap", map[string]interface{}{
			"keyLabel": "integrationTestKeyDSAWrapTest",
			"keySize":  1024,
			"attributes": `{
				"decrypt": true,
				"sign": false,
				"unwrap": true,
				"wrap": true,
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
		if resp.Data["algorithm"].(string) != "DSA" {
			assert.FailNow(t, fmt.Errorf("Expected: Key type %s got %s", "DSA", resp.Data["algorithm"]).Error())
		}
		if resp.Data["baseLabel"].(string) != "integrationTestKeyDSAWrapTest" {
			assert.FailNow(t, fmt.Errorf("Expected: Key name %s got %s", "integrationTestKeyDSAWrapTest", resp.Data["baseLabel"]).Error())
		}
		if resp.Data["version"].(string) != "v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key version %s got %s", "v1", resp.Data["version"]).Error())
		}
		if resp.Data["keySize"].(json.Number) != json.Number("1024") {
			assert.FailNow(t, fmt.Errorf("Expected: Key size %s got %s", "1024", resp.Data["keySize"]).Error())
		}
		if resp.Data["keyLabel"].(string) != "integrationTestKeyDSAWrapTest_v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key label %s got %s", "integrationTestKeyDSAWrapTest_v1", resp.Data["keyLabel"]).Error())
		}
	})

	t.Run("D.1 Test Create Key BLS Key with name integrationTestKeyBLSWrapTest", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/bls/integration_test_key_bls_wrap", map[string]interface{}{
			"keyLabel": "integrationTestKeyBLSWrapTest",
			"keySize":  256,
			"attributes": `{
				"decrypt": true,
				"sign": true,
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
		if resp.Data["algorithm"].(string) != "BLS" {
			assert.FailNow(t, fmt.Errorf("Expected: Key type %s got %s", "BLS", resp.Data["algorithm"]).Error())
		}
		if resp.Data["baseLabel"].(string) != "integrationTestKeyBLSWrapTest" {
			assert.FailNow(t, fmt.Errorf("Expected: Key name %s got %s", "integrationTestKeyBLSWrapTest", resp.Data["baseLabel"]).Error())
		}
		if resp.Data["version"].(string) != "v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key version %s got %s", "v1", resp.Data["version"]).Error())
		}
		if resp.Data["keyLabel"].(string) != "integrationTestKeyBLSWrapTest_v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key label %s got %s", "integrationTestKeyBLSWrapTest_v1", resp.Data["keyLabel"]).Error())
		}
	})
	t.Run("D.1 Test Create Key EC Key with name integrationTestKeyEC_prime256v1WrapTest", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/ec/integration_test_key_ec_wrap", map[string]interface{}{
			"keyLabel": "integrationTestKeyEC_prime256v1WrapTest",
			"curveOid": "1.2.840.10045.3.1.7",
			"attributes": `{
				"decrypt": true,
				"sign": true,
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
		if resp.Data["algorithm"].(string) != "EC" {
			assert.FailNow(t, fmt.Errorf("Expected: Key type %s got %s", "EC", resp.Data["algorithm"]).Error())
		}
		if resp.Data["baseLabel"].(string) != "integrationTestKeyEC_prime256v1WrapTest" {
			assert.FailNow(t, fmt.Errorf("Expected: Key name %s got %s", "integrationTestKeyEC_prime256v1WrapTest", resp.Data["baseLabel"]).Error())
		}
		if resp.Data["version"].(string) != "v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key version %s got %s", "v1", resp.Data["version"]).Error())
		}
		if resp.Data["curveOid"].(string) != "1.2.840.10045.3.1.7" {
			assert.FailNow(t, fmt.Errorf("Expected: key curve oid %s got %s", "1.2.840.10045.3.1.7", resp.Data["curveOid"]).Error())
		}
		if resp.Data["keyLabel"].(string) != "integrationTestKeyEC_prime256v1WrapTest_v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key label %s got %s", "integrationTestKeyEC_prime256v1WrapTest_v1", resp.Data["keyLabel"]).Error())
		}
	})
	t.Run("D.1 Test Create Key ED Key with name integrationTestKeyED_ed25519WrapTest", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/ed/integration_test_key_ed_wrap", map[string]interface{}{
			"keyLabel": "integrationTestKeyED_ed25519WrapTest",
			"curveOid": "1.3.101.112",
			"attributes": `{
				"decrypt": true,
				"sign": true,
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
		if resp.Data["algorithm"].(string) != "ED" {
			assert.FailNow(t, fmt.Errorf("Expected: Key type %s got %s", "ED", resp.Data["algorithm"]).Error())
		}
		if resp.Data["baseLabel"].(string) != "integrationTestKeyED_ed25519WrapTest" {
			assert.FailNow(t, fmt.Errorf("Expected: Key name %s got %s", "integrationTestKeyED_ed25519WrapTest", resp.Data["baseLabel"]).Error())
		}
		if resp.Data["version"].(string) != "v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key version %s got %s", "v1", resp.Data["version"]).Error())
		}
		if resp.Data["curveOid"].(string) != "1.3.101.112" {
			assert.FailNow(t, fmt.Errorf("Expected: key curve oid %s got %s", "1.3.101.112", resp.Data["curveOid"]).Error())
		}
		if resp.Data["keyLabel"].(string) != "integrationTestKeyED_ed25519WrapTest_v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key label %s got %s", "integrationTestKeyED_ed25519WrapTest_v1", resp.Data["keyLabel"]).Error())
		}
	})

	t.Run("D.2 Test Wrap AES - wrap method AES_WRAP", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/wrap/integration_test_key_aes_wrap/integration_test_key_aes", map[string]interface{}{
			"wrapMethod": "AES_WRAP",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Wrapped key got %s", "null").Error())
		}
		if resp.Data["wrappedKey"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Wrapped key %s", "null").Error())
		}
	})
	t.Run("D.2 Test Wrap AES - wrap method AES_WRAP_DSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/wrap/integration_test_key_dsa_wrap/integration_test_key_aes", map[string]interface{}{
			"wrapMethod": "AES_WRAP_DSA",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Wrapped key got %s", "null").Error())
		}
		if resp.Data["wrappedKey"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Wrapped key %s", "null").Error())
		}
	})
	t.Run("D.2 Test Wrap AES - wrap method AES_WRAP_EC", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/wrap/integration_test_key_ec_wrap/integration_test_key_aes", map[string]interface{}{
			"wrapMethod": "AES_WRAP_EC",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Wrapped key got %s", "null").Error())
		}
		if resp.Data["wrappedKey"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Wrapped key %s", "null").Error())
		}
	})
	t.Run("D.2 Test Wrap AES - wrap method AES_WRAP_ED", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/wrap/integration_test_key_ed_wrap/integration_test_key_aes", map[string]interface{}{
			"wrapMethod": "AES_WRAP_ED",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Wrapped key got %s", "null").Error())
		}
		if resp.Data["wrappedKey"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Wrapped key %s", "null").Error())
		}
	})
	t.Run("D.2 Test Wrap AES - wrap method AES_WRAP_RSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/wrap/integration_test_key_rsa_wrap/integration_test_key_aes", map[string]interface{}{
			"wrapMethod": "AES_WRAP_RSA",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Wrapped key got %s", "null").Error())
		}
		if resp.Data["wrappedKey"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Wrapped key %s", "null").Error())
		}
	})
	t.Run("D.2 Test Wrap AES - wrap method AES_WRAP_BLS", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/wrap/integration_test_key_bls_wrap/integration_test_key_aes", map[string]interface{}{
			"wrapMethod": "AES_WRAP_BLS",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Wrapped key got %s", "null").Error())
		}
		if resp.Data["wrappedKey"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Wrapped key %s", "null").Error())
		}
	})
	t.Run("D.2 Test Wrap AES - wrap method AES_WRAP_PAD", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/wrap/integration_test_key_aes_wrap/integration_test_key_aes", map[string]interface{}{
			"wrapMethod": "AES_WRAP_PAD",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Wrapped key got %s", "null").Error())
		}
		if resp.Data["wrappedKey"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Wrapped key %s", "null").Error())
		}
	})
	t.Run("D.2 Test Wrap AES - wrap method AES_WRAP_PAD_DSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/wrap/integration_test_key_dsa_wrap/integration_test_key_aes", map[string]interface{}{
			"wrapMethod": "AES_WRAP_PAD_DSA",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Wrapped key got %s", "null").Error())
		}
		if resp.Data["wrappedKey"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Wrapped key %s", "null").Error())
		}
	})
	t.Run("D.2 Test Wrap AES - wrap method AES_WRAP_PAD_EC", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/wrap/integration_test_key_ec_wrap/integration_test_key_aes", map[string]interface{}{
			"wrapMethod": "AES_WRAP_PAD_EC",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Wrapped key got %s", "null").Error())
		}
		if resp.Data["wrappedKey"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Wrapped key %s", "null").Error())
		}
	})
	t.Run("D.2 Test Wrap AES - wrap method AES_WRAP_PAD_ED", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/wrap/integration_test_key_ed_wrap/integration_test_key_aes", map[string]interface{}{
			"wrapMethod": "AES_WRAP_PAD_ED",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Wrapped key got %s", "null").Error())
		}
		if resp.Data["wrappedKey"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Wrapped key %s", "null").Error())
		}
	})
	t.Run("D.2 Test Wrap AES - wrap method AES_WRAP_PAD_RSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/wrap/integration_test_key_rsa_wrap/integration_test_key_aes", map[string]interface{}{
			"wrapMethod": "AES_WRAP_PAD_RSA",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Wrapped key got %s", "null").Error())
		}
		if resp.Data["wrappedKey"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Wrapped key %s", "null").Error())
		}
	})
	t.Run("D.2 Test Wrap AES - wrap method AES_WRAP_PAD_BLS", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/wrap/integration_test_key_bls_wrap/integration_test_key_aes", map[string]interface{}{
			"wrapMethod": "AES_WRAP_PAD_BLS",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Wrapped key got %s", "null").Error())
		}
		if resp.Data["wrappedKey"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Wrapped key %s", "null").Error())
		}
	})
	t.Run("D.2 Test Wrap RSA - wrap method RSA_WRAP_PAD", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/wrap/integration_test_key_aes_wrap/integration_test_key_rsa", map[string]interface{}{
			"wrapMethod": "RSA_WRAP_PAD",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Wrapped key got %s", "null").Error())
		}
		if resp.Data["wrappedKey"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Wrapped key %s", "null").Error())
		}
	})
	t.Run("D.2 Test Wrap RSA - rotate key - wrap method RSA_WRAP_PAD", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		_, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_rsa/rotate", map[string]interface{}{})
		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/wrap/integration_test_key_aes_wrap/integration_test_key_rsa", map[string]interface{}{
			"wrapMethod": "RSA_WRAP_PAD",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Wrapped key got %s", "null").Error())
		}
		if resp.Data["wrappedKey"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Wrapped key %s", "null").Error())
		}
	})
	t.Run("D.2 Test Wrap RSA - wrap method RSA_WRAP_OAEP", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/wrap/integration_test_key_aes_wrap/integration_test_key_rsa", map[string]interface{}{
			"wrapMethod": "RSA_WRAP_OAEP",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Wrapped key got %s", "null").Error())
		}
		if resp.Data["wrappedKey"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Wrapped key %s", "null").Error())
		}
	})
	t.Run("D.3 Test Remove Key Smart RSA Key with name integrationTestKeyRSAWrapTest", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		_, err := client.Delete(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_rsa_wrap", vault.WithQueryParameters(url.Values{
			"removeFromHSM": {"true"},
		}))
		if err != nil {
			assert.FailNow(t, err.Error())
		}
	})
	t.Run("D.3 Test Remove Key Smart RSA Key with name integrationTestKeyRSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		_, err := client.Delete(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_rsa", vault.WithQueryParameters(url.Values{
			"removeFromHSM": {"true"},
		}))
		if err != nil {
			assert.FailNow(t, err.Error())
		}
	})
	t.Run("D.3 Test Remove Key AES Key with name integrationTestKeyAESWrapTest", func(t *testing.T) {

		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		_, err := client.Delete(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_aes_wrap", vault.WithQueryParameters(url.Values{
			"removeFromHSM": {"true"},
		}))
		if err != nil {
			assert.FailNow(t, err.Error())
		}
	})
	t.Run("D.3 Test Remove Key DSA Key with name integrationTestKeyDSAWrapTest", func(t *testing.T) {

		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		_, err := client.Delete(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_dsa_wrap", vault.WithQueryParameters(url.Values{
			"removeFromHSM": {"true"},
		}))
		if err != nil {
			assert.FailNow(t, err.Error())
		}
	})
	t.Run("D.3 Test Remove Key DSA Key with name integrationTestKeyED_ed25519WrapTest", func(t *testing.T) {

		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		_, err := client.Delete(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_ed_wrap", vault.WithQueryParameters(url.Values{
			"removeFromHSM": {"true"},
		}))
		if err != nil {
			assert.FailNow(t, err.Error())
		}
	})
	t.Run("D.3 Test Remove Key DSA Key with name integrationTestKeyEC_prime256v1WrapTest", func(t *testing.T) {

		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		_, err := client.Delete(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_ec_wrap", vault.WithQueryParameters(url.Values{
			"removeFromHSM": {"true"},
		}))
		if err != nil {
			assert.FailNow(t, err.Error())
		}
	})
	t.Run("D.3 Test Remove Key DSA Key with name integrationTestKeyBLSWrapTest", func(t *testing.T) {

		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		_, err := client.Delete(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_bls_wrap", vault.WithQueryParameters(url.Values{
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
}
