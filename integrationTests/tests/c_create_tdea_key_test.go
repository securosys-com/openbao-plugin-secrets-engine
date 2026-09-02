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
	"fmt"
	"net/url"
	"testing"

	"github.com/hashicorp/vault-client-go"
	"github.com/stretchr/testify/assert"
	integrationClient "securosys.ch/integration/client"
)

func TestCreateTDEAKeyPlugin(t *testing.T) {
	cleanupIntegrationKeysForTest(t)

	t.Run("C.1 Test Create Key TDEA Key with name integrationTestKeyTDEA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/tdea/integration_test_tdea_key", map[string]interface{}{
			"keyLabel": "integrationTestKeyTDEA",
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
		if resp.Data["keyLabel"].(string) != "integrationTestKeyTDEA_v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key label %s got %s", "integrationTestKeyTDEA_v1", resp.Data["keyLabel"]).Error())
		}
	})
	t.Run("C.2 Test List Keys", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, err := client.List(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/")
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: List of keys got %s", "null").Error())
		}
		if resp.Data["key_info"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: List of keys got %s", "null").Error())

		}
		keyInfo := resp.Data["key_info"].(map[string]interface{})
		if keyInfo == nil {
			assert.FailNow(t, fmt.Errorf("Expected: List of keys got %s", "null").Error())
		}
		if keyInfo["integration_test_tdea_key"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: integration_test_tdea_key got %s", "null").Error())
		}
	})
	t.Run("C.3 Read TDEA Key with name integrationTestKeyTDEA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Read(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_tdea_key")
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
		if resp.Data["keyLabel"].(string) != "integrationTestKeyTDEA_v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key label %s got %s", "integrationTestKeyTDEA_v1", resp.Data["keyLabel"]).Error())
		}
	})
	t.Run("C.4 Rotate TDEA Key with name integrationTestKeyTDEA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		_, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_tdea_key/rotate", map[string]interface{}{})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		resp, _ := client.Read(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_tdea_key")
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Key response got %s", "null").Error())
		}
		if resp.Data["algorithm"].(string) != "TDEA" {
			assert.FailNow(t, fmt.Errorf("Expected: Key type %s got %s", "TDEA", resp.Data["algorithm"]).Error())
		}
		if resp.Data["baseLabel"].(string) != "integrationTestKeyTDEA" {
			assert.FailNow(t, fmt.Errorf("Expected: Key name %s got %s", "integrationTestKeyTDEA", resp.Data["baseLabel"]).Error())
		}
		if resp.Data["version"].(string) != "v2" {
			assert.FailNow(t, fmt.Errorf("Expected: Key version %s got %s", "v2", resp.Data["version"]).Error())
		}
		if resp.Data["keyLabel"].(string) != "integrationTestKeyTDEA_v2" {
			assert.FailNow(t, fmt.Errorf("Expected: Key Label %s got %s", "integrationTestKeyTDEA_v2", resp.Data["keyLabel"]).Error())
		}
	})
	t.Run("C.5 Test List Versions of Key integrationTestKeyTDEA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, err := client.List(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_tdea_key")
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: List of key versions got %s", "null").Error())
		}
		if resp.Data["key_info"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: List of key versions got %s", "null").Error())

		}
		keyInfo := resp.Data["key_info"].(map[string]interface{})
		if keyInfo == nil {
			assert.FailNow(t, fmt.Errorf("Expected: List of key versions got %s", "null").Error())
		}
		if keyInfo["v1"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: v1 got %s", "null").Error())
		}
		if keyInfo["v2"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: v2 got %s", "null").Error())
		}
	})
	t.Run("C.6 Test List Versions of Key integrationTestKeyTDEA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, _ := client.Read(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_tdea_key/v2")
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Key response got %s", "null").Error())
		}
		if resp.Data["algorithm"].(string) != "TDEA" {
			assert.FailNow(t, fmt.Errorf("Expected: Key type %s got %s", "TDEA", resp.Data["algorithm"]).Error())
		}
		if resp.Data["version"].(string) != "v2" {
			assert.FailNow(t, fmt.Errorf("Expected: Key version %s got %s", "v2", resp.Data["version"]).Error())
		}
		if resp.Data["keyLabel"].(string) != "integrationTestKeyTDEA_v2" {
			assert.FailNow(t, fmt.Errorf("Expected: Key Label %s got %s", "integrationTestKeyTDEA_v2", resp.Data["keyLabel"]).Error())
		}
	})
	t.Run("C.7 Export TDEA Key with name integrationTestKeyTDEA", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_tdea_key/export", map[string]interface{}{})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp.Data["secretKey"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Key Secret got %s", "null").Error())
		}
	})
	t.Run("C.8 Test Remove Key TDEA Key with name integrationTestKeyTDEA", func(t *testing.T) {
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
