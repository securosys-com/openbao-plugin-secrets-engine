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

func TestOperationsVerifyPlugin(t *testing.T) {
	cleanupIntegrationKeysForTest(t)

	t.Run("D.1 Test Create Key Smart RSA Key with name integrationTestKeyRSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/rsa/integration_test_key_rsa", map[string]interface{}{
			"keyLabel": "integrationTestKeyRSA",
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
	t.Run("D.1 Test Create Key BLS Key with name integrationTestKeyBLS", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/bls/integration_test_key_bls", map[string]interface{}{
			"keyLabel": "integrationTestKeyBLS",
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
		if resp.Data["baseLabel"].(string) != "integrationTestKeyBLS" {
			assert.FailNow(t, fmt.Errorf("Expected: Key name %s got %s", "integrationTestKeyBLS", resp.Data["baseLabel"]).Error())
		}
		if resp.Data["version"].(string) != "v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key version %s got %s", "v1", resp.Data["version"]).Error())
		}
		if resp.Data["keyLabel"].(string) != "integrationTestKeyBLS_v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key label %s got %s", "integrationTestKeyBLS_v1", resp.Data["keyLabel"]).Error())
		}
	})
	t.Run("D.1 Test Create Key EC Key with name integrationTestKeyEC_prime256v1", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/ec/integration_test_key_ec", map[string]interface{}{
			"keyLabel": "integrationTestKeyEC_prime256v1",
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
		if resp.Data["baseLabel"].(string) != "integrationTestKeyEC_prime256v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key name %s got %s", "integrationTestKeyEC_prime256v1", resp.Data["baseLabel"]).Error())
		}
		if resp.Data["version"].(string) != "v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key version %s got %s", "v1", resp.Data["version"]).Error())
		}
		if resp.Data["curveOid"].(string) != "1.2.840.10045.3.1.7" {
			assert.FailNow(t, fmt.Errorf("Expected: key curve oid %s got %s", "1.2.840.10045.3.1.7", resp.Data["curveOid"]).Error())
		}
		if resp.Data["keyLabel"].(string) != "integrationTestKeyEC_prime256v1_v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key label %s got %s", "integrationTestKeyEC_prime256v1_v1", resp.Data["keyLabel"]).Error())
		}
	})
	t.Run("D.1 Test Create Key ED Key with name integrationTestKeyED_ed25519", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/ed/integration_test_key_ed", map[string]interface{}{
			"keyLabel": "integrationTestKeyED_ed25519",
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
		if resp.Data["baseLabel"].(string) != "integrationTestKeyED_ed25519" {
			assert.FailNow(t, fmt.Errorf("Expected: Key name %s got %s", "integrationTestKeyED_ed25519", resp.Data["baseLabel"]).Error())
		}
		if resp.Data["version"].(string) != "v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key version %s got %s", "v1", resp.Data["version"]).Error())
		}
		if resp.Data["curveOid"].(string) != "1.3.101.112" {
			assert.FailNow(t, fmt.Errorf("Expected: key curve oid %s got %s", "1.3.101.112", resp.Data["curveOid"]).Error())
		}
		if resp.Data["keyLabel"].(string) != "integrationTestKeyED_ed25519_v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key label %s got %s", "integrationTestKeyED_ed25519_v1", resp.Data["keyLabel"]).Error())
		}
	})

	t.Run("D.1 Test Create Key Smart DSA Key with name integrationTestKeyDSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/dsa/integration_test_key_dsa", map[string]interface{}{
			"keyLabel": "integrationTestKeyDSA",
			"keySize":  1024,
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
		if resp.Data["algorithm"].(string) != "DSA" {
			assert.FailNow(t, fmt.Errorf("Expected: Key type %s got %s", "DSA", resp.Data["algorithm"]).Error())
		}
		if resp.Data["baseLabel"].(string) != "integrationTestKeyDSA" {
			assert.FailNow(t, fmt.Errorf("Expected: Key name %s got %s", "integrationTestKeyDSA", resp.Data["baseLabel"]).Error())
		}
		if resp.Data["version"].(string) != "v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key version %s got %s", "v1", resp.Data["version"]).Error())
		}
		if resp.Data["keySize"].(json.Number) != json.Number("1024") {
			assert.FailNow(t, fmt.Errorf("Expected: Key size %s got %s", "1024", resp.Data["keySize"]).Error())
		}
		if resp.Data["keyLabel"].(string) != "integrationTestKeyDSA_v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key label %s got %s", "integrationTestKeyDSA_v1", resp.Data["keyLabel"]).Error())
		}
	})

	t.Run("D.2 Test Verify EC - signature NONE_WITH_ECDSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/sign/integration_test_key_ec", map[string]interface{}{
			"payloadType":        "UNSPECIFIED",
			"payload":            "cGF5bG9hZA==",
			"signatureAlgorithm": "NONE_WITH_ECDSA",
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
		resp, err = client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/verify/integration_test_key_ec", map[string]interface{}{
			"payload":            "cGF5bG9hZA==",
			"keyVersion":         "v1",
			"signatureAlgorithm": "NONE_WITH_ECDSA",
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
	t.Run("D.2 Test Verify EC - signature SHA1_WITH_ECDSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/sign/integration_test_key_ec", map[string]interface{}{
			"payloadType":        "UNSPECIFIED",
			"payload":            "cGF5bG9hZA==",
			"signatureAlgorithm": "SHA1_WITH_ECDSA",
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
		resp, err = client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/verify/integration_test_key_ec", map[string]interface{}{
			"payload":            "cGF5bG9hZA==",
			"keyVersion":         "v1",
			"signatureAlgorithm": "SHA1_WITH_ECDSA",
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
	t.Run("D.2 Test Verify EC - signature SHA224_WITH_ECDSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/sign/integration_test_key_ec", map[string]interface{}{
			"payloadType":        "UNSPECIFIED",
			"payload":            "cGF5bG9hZA==",
			"signatureAlgorithm": "SHA224_WITH_ECDSA",
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
		resp, err = client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/verify/integration_test_key_ec", map[string]interface{}{
			"payload":            "cGF5bG9hZA==",
			"keyVersion":         "v1",
			"signatureAlgorithm": "SHA224_WITH_ECDSA",
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
	t.Run("D.2 Test Verify EC - signature SHA256_WITH_ECDSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/sign/integration_test_key_ec", map[string]interface{}{
			"payloadType":        "UNSPECIFIED",
			"payload":            "cGF5bG9hZA==",
			"signatureAlgorithm": "SHA256_WITH_ECDSA",
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
		resp, err = client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/verify/integration_test_key_ec", map[string]interface{}{
			"payload":            "cGF5bG9hZA==",
			"keyVersion":         "v1",
			"signatureAlgorithm": "SHA256_WITH_ECDSA",
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
	t.Run("D.2 Test Verify EC - signature SHA384_WITH_ECDSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/sign/integration_test_key_ec", map[string]interface{}{
			"payloadType":        "UNSPECIFIED",
			"payload":            "cGF5bG9hZA==",
			"signatureAlgorithm": "SHA384_WITH_ECDSA",
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
		resp, err = client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/verify/integration_test_key_ec", map[string]interface{}{
			"payload":            "cGF5bG9hZA==",
			"keyVersion":         "v1",
			"signatureAlgorithm": "SHA384_WITH_ECDSA",
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
	t.Run("D.2 Test Verify EC - signature SHA512_WITH_ECDSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/sign/integration_test_key_ec", map[string]interface{}{
			"payloadType":        "UNSPECIFIED",
			"payload":            "cGF5bG9hZA==",
			"signatureAlgorithm": "SHA512_WITH_ECDSA",
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
		resp, err = client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/verify/integration_test_key_ec", map[string]interface{}{
			"payload":            "cGF5bG9hZA==",
			"keyVersion":         "v1",
			"signatureAlgorithm": "SHA512_WITH_ECDSA",
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
	t.Run("D.2 Test Verify EC - signature SHA3224_WITH_ECDSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/sign/integration_test_key_ec", map[string]interface{}{
			"payloadType":        "UNSPECIFIED",
			"payload":            "cGF5bG9hZA==",
			"signatureAlgorithm": "SHA3224_WITH_ECDSA",
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
		resp, err = client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/verify/integration_test_key_ec", map[string]interface{}{
			"payload":            "cGF5bG9hZA==",
			"keyVersion":         "v1",
			"signatureAlgorithm": "SHA3224_WITH_ECDSA",
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
	t.Run("D.2 Test Verify EC - signature SHA3256_WITH_ECDSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/sign/integration_test_key_ec", map[string]interface{}{
			"payloadType":        "UNSPECIFIED",
			"payload":            "cGF5bG9hZA==",
			"signatureAlgorithm": "SHA3256_WITH_ECDSA",
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
		resp, err = client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/verify/integration_test_key_ec", map[string]interface{}{
			"payload":            "cGF5bG9hZA==",
			"keyVersion":         "v1",
			"signatureAlgorithm": "SHA3256_WITH_ECDSA",
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
	t.Run("D.2 Test Verify EC - signature SHA3384_WITH_ECDSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/sign/integration_test_key_ec", map[string]interface{}{
			"payloadType":        "UNSPECIFIED",
			"payload":            "cGF5bG9hZA==",
			"signatureAlgorithm": "SHA3384_WITH_ECDSA",
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
		resp, err = client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/verify/integration_test_key_ec", map[string]interface{}{
			"payload":            "cGF5bG9hZA==",
			"keyVersion":         "v1",
			"signatureAlgorithm": "SHA3384_WITH_ECDSA",
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
	t.Run("D.2 Test Verify EC - signature SHA3512_WITH_ECDSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/sign/integration_test_key_ec", map[string]interface{}{
			"payloadType":        "UNSPECIFIED",
			"payload":            "cGF5bG9hZA==",
			"signatureAlgorithm": "SHA3512_WITH_ECDSA",
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
		resp, err = client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/verify/integration_test_key_ec", map[string]interface{}{
			"payload":            "cGF5bG9hZA==",
			"keyVersion":         "v1",
			"signatureAlgorithm": "SHA3512_WITH_ECDSA",
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
	t.Run("D.2 Test Verify EC - signature KECCAK224_WITH_ECDSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/sign/integration_test_key_ec", map[string]interface{}{
			"payloadType":        "UNSPECIFIED",
			"payload":            "cGF5bG9hZA==",
			"signatureAlgorithm": "KECCAK224_WITH_ECDSA",
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
		resp, err = client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/verify/integration_test_key_ec", map[string]interface{}{
			"payload":            "cGF5bG9hZA==",
			"keyVersion":         "v1",
			"signatureAlgorithm": "KECCAK224_WITH_ECDSA",
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
	t.Run("D.2 Test Verify EC - signature KECCAK256_WITH_ECDSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/sign/integration_test_key_ec", map[string]interface{}{
			"payloadType":        "UNSPECIFIED",
			"payload":            "cGF5bG9hZA==",
			"signatureAlgorithm": "KECCAK256_WITH_ECDSA",
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
		resp, err = client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/verify/integration_test_key_ec", map[string]interface{}{
			"payload":            "cGF5bG9hZA==",
			"keyVersion":         "v1",
			"signatureAlgorithm": "KECCAK256_WITH_ECDSA",
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
	t.Run("D.2 Test Verify EC - signature KECCAK384_WITH_ECDSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/sign/integration_test_key_ec", map[string]interface{}{
			"payloadType":        "UNSPECIFIED",
			"payload":            "cGF5bG9hZA==",
			"signatureAlgorithm": "KECCAK384_WITH_ECDSA",
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
		resp, err = client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/verify/integration_test_key_ec", map[string]interface{}{
			"payload":            "cGF5bG9hZA==",
			"keyVersion":         "v1",
			"signatureAlgorithm": "KECCAK384_WITH_ECDSA",
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
	t.Run("D.2 Test Verify EC - signature KECCAK512_WITH_ECDSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/sign/integration_test_key_ec", map[string]interface{}{
			"payloadType":        "UNSPECIFIED",
			"payload":            "cGF5bG9hZA==",
			"signatureAlgorithm": "KECCAK512_WITH_ECDSA",
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
		resp, err = client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/verify/integration_test_key_ec", map[string]interface{}{
			"payload":            "cGF5bG9hZA==",
			"keyVersion":         "v1",
			"signatureAlgorithm": "KECCAK512_WITH_ECDSA",
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
	t.Run("D.2 Test Verify ED - signature EDDSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/sign/integration_test_key_ed", map[string]interface{}{
			"payloadType":        "UNSPECIFIED",
			"payload":            "cGF5bG9hZA==",
			"signatureAlgorithm": "EDDSA",
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
		resp, err = client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/verify/integration_test_key_ed", map[string]interface{}{
			"payload":            "cGF5bG9hZA==",
			"keyVersion":         "v1",
			"signatureAlgorithm": "EDDSA",
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
	t.Run("D.2 Test Verify RSA - signature SHA224_WITH_RSA_PSS", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/sign/integration_test_key_rsa", map[string]interface{}{
			"payloadType":        "UNSPECIFIED",
			"payload":            "cGF5bG9hZA==",
			"signatureAlgorithm": "SHA224_WITH_RSA_PSS",
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
		resp, err = client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/verify/integration_test_key_rsa", map[string]interface{}{
			"payload":            "cGF5bG9hZA==",
			"keyVersion":         "v1",
			"signatureAlgorithm": "SHA224_WITH_RSA_PSS",
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
	t.Run("D.2 Test Verify RSA - signature SHA256_WITH_RSA_PSS", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/sign/integration_test_key_rsa", map[string]interface{}{
			"payloadType":        "UNSPECIFIED",
			"payload":            "cGF5bG9hZA==",
			"signatureAlgorithm": "SHA256_WITH_RSA_PSS",
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
	t.Run("D.2 Test Verify RSA - signature SHA384_WITH_RSA_PSS", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/sign/integration_test_key_rsa", map[string]interface{}{
			"payloadType":        "UNSPECIFIED",
			"payload":            "cGF5bG9hZA==",
			"signatureAlgorithm": "SHA384_WITH_RSA_PSS",
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
		resp, err = client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/verify/integration_test_key_rsa", map[string]interface{}{
			"payload":            "cGF5bG9hZA==",
			"keyVersion":         "v1",
			"signatureAlgorithm": "SHA384_WITH_RSA_PSS",
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
	t.Run("D.2 Test Verify RSA - signature SHA512_WITH_RSA_PSS", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/sign/integration_test_key_rsa", map[string]interface{}{
			"payloadType":        "UNSPECIFIED",
			"payload":            "cGF5bG9hZA==",
			"signatureAlgorithm": "SHA512_WITH_RSA_PSS",
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
		resp, err = client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/verify/integration_test_key_rsa", map[string]interface{}{
			"payload":            "cGF5bG9hZA==",
			"keyVersion":         "v1",
			"signatureAlgorithm": "SHA512_WITH_RSA_PSS",
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
	t.Run("D.2 Test Verify RSA - signature NONE_WITH_RSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/sign/integration_test_key_rsa", map[string]interface{}{
			"payloadType":        "UNSPECIFIED",
			"payload":            "cGF5bG9hZA==",
			"signatureAlgorithm": "NONE_WITH_RSA",
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
		resp, err = client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/verify/integration_test_key_rsa", map[string]interface{}{
			"payload":            "cGF5bG9hZA==",
			"keyVersion":         "v1",
			"signatureAlgorithm": "NONE_WITH_RSA",
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
	t.Run("D.2 Test Verify RSA - signature SHA224_WITH_RSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/sign/integration_test_key_rsa", map[string]interface{}{
			"payloadType":        "UNSPECIFIED",
			"payload":            "cGF5bG9hZA==",
			"signatureAlgorithm": "SHA224_WITH_RSA",
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
		resp, err = client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/verify/integration_test_key_rsa", map[string]interface{}{
			"payload":            "cGF5bG9hZA==",
			"keyVersion":         "v1",
			"signatureAlgorithm": "SHA224_WITH_RSA",
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
	t.Run("D.2 Test Verify RSA - rotate key - signature SHA224_WITH_RSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		_, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_rsa/rotate", map[string]interface{}{})

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/sign/integration_test_key_rsa", map[string]interface{}{
			"payloadType":        "UNSPECIFIED",
			"payload":            "cGF5bG9hZA==",
			"signatureAlgorithm": "SHA224_WITH_RSA",
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
		resp, err = client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/verify/integration_test_key_rsa", map[string]interface{}{
			"payload":            "cGF5bG9hZA==",
			"keyVersion":         "v2",
			"signatureAlgorithm": "SHA224_WITH_RSA",
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
	t.Run("D.2 Test Verify RSA - signature SHA256_WITH_RSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/sign/integration_test_key_rsa", map[string]interface{}{
			"payloadType":        "UNSPECIFIED",
			"payload":            "cGF5bG9hZA==",
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
		resp, err = client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/verify/integration_test_key_rsa", map[string]interface{}{
			"payload":            "cGF5bG9hZA==",
			"keyVersion":         "v2",
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
	t.Run("D.2 Test Verify RSA - signature SHA384_WITH_RSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/sign/integration_test_key_rsa", map[string]interface{}{
			"payloadType":        "UNSPECIFIED",
			"payload":            "cGF5bG9hZA==",
			"signatureAlgorithm": "SHA384_WITH_RSA",
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
		resp, err = client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/verify/integration_test_key_rsa", map[string]interface{}{
			"payload":            "cGF5bG9hZA==",
			"keyVersion":         "v2",
			"signatureAlgorithm": "SHA384_WITH_RSA",
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
	t.Run("D.2 Test Verify RSA - signature SHA512_WITH_RSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/sign/integration_test_key_rsa", map[string]interface{}{
			"payloadType":        "UNSPECIFIED",
			"payload":            "cGF5bG9hZA==",
			"signatureAlgorithm": "SHA512_WITH_RSA",
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
		resp, err = client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/verify/integration_test_key_rsa", map[string]interface{}{
			"payload":            "cGF5bG9hZA==",
			"keyVersion":         "v2",
			"signatureAlgorithm": "SHA512_WITH_RSA",
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
	t.Run("D.2 Test Verify RSA - signature SHA1_WITH_RSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/sign/integration_test_key_rsa", map[string]interface{}{
			"payloadType":        "UNSPECIFIED",
			"payload":            "cGF5bG9hZA==",
			"signatureAlgorithm": "SHA1_WITH_RSA",
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
		resp, err = client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/verify/integration_test_key_rsa", map[string]interface{}{
			"payload":            "cGF5bG9hZA==",
			"keyVersion":         "v2",
			"signatureAlgorithm": "SHA1_WITH_RSA",
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
	t.Run("D.2 Test Verify RSA - signature SHA1_WITH_RSA_PSS", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/sign/integration_test_key_rsa", map[string]interface{}{
			"payloadType":        "UNSPECIFIED",
			"payload":            "cGF5bG9hZA==",
			"signatureAlgorithm": "SHA1_WITH_RSA_PSS",
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
		resp, err = client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/verify/integration_test_key_rsa", map[string]interface{}{
			"payload":            "cGF5bG9hZA==",
			"keyVersion":         "v2",
			"signatureAlgorithm": "SHA1_WITH_RSA_PSS",
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
	t.Run("D.2 Test Verify DSA - signature NONE_WITH_DSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/sign/integration_test_key_dsa", map[string]interface{}{
			"payloadType":        "UNSPECIFIED",
			"payload":            "cGF5bG9hZA==",
			"signatureAlgorithm": "NONE_WITH_DSA",
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
		resp, err = client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/verify/integration_test_key_dsa", map[string]interface{}{
			"payload":            "cGF5bG9hZA==",
			"keyVersion":         "v1",
			"signatureAlgorithm": "NONE_WITH_DSA",
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
	t.Run("D.2 Test Verify DSA - signature SHA224_WITH_DSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/sign/integration_test_key_dsa", map[string]interface{}{
			"payloadType":        "UNSPECIFIED",
			"payload":            "cGF5bG9hZA==",
			"signatureAlgorithm": "SHA224_WITH_DSA",
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
		resp, err = client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/verify/integration_test_key_dsa", map[string]interface{}{
			"payload":            "cGF5bG9hZA==",
			"keyVersion":         "v1",
			"signatureAlgorithm": "SHA224_WITH_DSA",
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
	t.Run("D.2 Test Verify DSA - signature SHA256_WITH_DSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/sign/integration_test_key_dsa", map[string]interface{}{
			"payloadType":        "UNSPECIFIED",
			"payload":            "cGF5bG9hZA==",
			"signatureAlgorithm": "SHA256_WITH_DSA",
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
		resp, err = client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/verify/integration_test_key_dsa", map[string]interface{}{
			"payload":            "cGF5bG9hZA==",
			"keyVersion":         "v1",
			"signatureAlgorithm": "SHA256_WITH_DSA",
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
	t.Run("D.2 Test Verify DSA - signature SHA384_WITH_DSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/sign/integration_test_key_dsa", map[string]interface{}{
			"payloadType":        "UNSPECIFIED",
			"payload":            "cGF5bG9hZA==",
			"signatureAlgorithm": "SHA384_WITH_DSA",
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
		resp, err = client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/verify/integration_test_key_dsa", map[string]interface{}{
			"payload":            "cGF5bG9hZA==",
			"keyVersion":         "v1",
			"signatureAlgorithm": "SHA384_WITH_DSA",
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
	t.Run("D.2 Test Verify DSA - signature SHA512_WITH_DSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/sign/integration_test_key_dsa", map[string]interface{}{
			"payloadType":        "UNSPECIFIED",
			"payload":            "cGF5bG9hZA==",
			"signatureAlgorithm": "SHA512_WITH_DSA",
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
		resp, err = client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/verify/integration_test_key_dsa", map[string]interface{}{
			"payload":            "cGF5bG9hZA==",
			"keyVersion":         "v1",
			"signatureAlgorithm": "SHA512_WITH_DSA",
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
	t.Run("D.2 Test Verify DSA - signature SHA1_WITH_DSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/sign/integration_test_key_dsa", map[string]interface{}{
			"payloadType":        "UNSPECIFIED",
			"payload":            "cGF5bG9hZA==",
			"signatureAlgorithm": "SHA1_WITH_DSA",
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
	t.Run("D.2 Test Verify BLS - signature BLS", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/sign/integration_test_key_bls", map[string]interface{}{
			"payloadType":        "UNSPECIFIED",
			"payload":            "cGF5bG9hZA==",
			"signatureAlgorithm": "BLS",
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
		resp, err = client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/operation/verify/integration_test_key_bls", map[string]interface{}{
			"payload":            "cGF5bG9hZA==",
			"keyVersion":         "v1",
			"signatureAlgorithm": "BLS",
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

	t.Run("D.3 Test Remove Key Smart RSA Key with name integrationTestKeySmartRSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		_, err := client.Delete(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_rsa", vault.WithQueryParameters(url.Values{
			"removeFromHSM": {"true"},
		}))
		if err != nil {
			assert.FailNow(t, err.Error())
		}
	})
	t.Run("D.3 Test Remove Key Smart EC Key with name integrationTestKeyEC", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		_, err := client.Delete(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_ec", vault.WithQueryParameters(url.Values{
			"removeFromHSM": {"true"},
		}))
		if err != nil {
			assert.FailNow(t, err.Error())
		}
	})
	t.Run("D.3 Test Remove Key Smart EC Key with name integrationTestKeyED", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		_, err := client.Delete(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_ed", vault.WithQueryParameters(url.Values{
			"removeFromHSM": {"true"},
		}))
		if err != nil {
			assert.FailNow(t, err.Error())
		}
	})
	t.Run("D.3 Test Remove Key Smart EC Key with name integrationTestKeyDSA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		_, err := client.Delete(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_dsa", vault.WithQueryParameters(url.Values{
			"removeFromHSM": {"true"},
		}))
		if err != nil {
			assert.FailNow(t, err.Error())
		}
	})
	t.Run("D.3 Test Remove Key Smart EC Key with name integrationTestKeyBLS", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		_, err := client.Delete(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_bls", vault.WithQueryParameters(url.Values{
			"removeFromHSM": {"true"},
		}))
		if err != nil {
			assert.FailNow(t, err.Error())
		}
	})

}
