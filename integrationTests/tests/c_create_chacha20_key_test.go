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

func TestCreateCHACHA20KeyPlugin(t *testing.T) {
	cleanupIntegrationKeysForTest(t)

	t.Run("C.1 Test Create Key CHACHA20 Key with name integrationTestKeyCHACHA20", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/chacha20/integration_test_key_chacha20", map[string]interface{}{
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
		if keyInfo["integration_test_key_chacha20"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: integration_test_key_chacha20 got %s", "null").Error())
		}
	})
	t.Run("C.3 Read CHACHA20 Key with name integrationTestKeyCHACHA20", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Read(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_chacha20")
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
	t.Run("C.4 Rotate CHACHA20 Key with name integrationTestKeyCHACHA20", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		_, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_chacha20/rotate", map[string]interface{}{})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		resp, _ := client.Read(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_chacha20")
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Key response got %s", "null").Error())
		}
		if resp.Data["algorithm"].(string) != "ChaCha20" {
			assert.FailNow(t, fmt.Errorf("Expected: Key type %s got %s", "ChaCha20", resp.Data["algorithm"]).Error())
		}
		if resp.Data["baseLabel"].(string) != "integrationTestKeyCHACHA20" {
			assert.FailNow(t, fmt.Errorf("Expected: Key name %s got %s", "integrationTestKeyCHACHA20", resp.Data["baseLabel"]).Error())
		}
		if resp.Data["version"].(string) != "v2" {
			assert.FailNow(t, fmt.Errorf("Expected: Key version %s got %s", "v2", resp.Data["version"]).Error())
		}
		if resp.Data["keyLabel"].(string) != "integrationTestKeyCHACHA20_v2" {
			assert.FailNow(t, fmt.Errorf("Expected: Key Label %s got %s", "integrationTestKeyCHACHA20_v2", resp.Data["keyLabel"]).Error())
		}
	})
	t.Run("C.5 Test List Versions of Key integrationTestKeyCHACHA20", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, err := client.List(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_chacha20")
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
	t.Run("C.6 Test List Versions of Key integrationTestKeyCHACHA20", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, _ := client.Read(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_chacha20/v2")
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Key response got %s", "null").Error())
		}
		if resp.Data["algorithm"].(string) != "ChaCha20" {
			assert.FailNow(t, fmt.Errorf("Expected: Key type %s got %s", "ChaCha20", resp.Data["algorithm"]).Error())
		}
		if resp.Data["version"].(string) != "v2" {
			assert.FailNow(t, fmt.Errorf("Expected: Key version %s got %s", "v2", resp.Data["version"]).Error())
		}
		if resp.Data["keyLabel"].(string) != "integrationTestKeyCHACHA20_v2" {
			assert.FailNow(t, fmt.Errorf("Expected: Key Label %s got %s", "integrationTestKeyCHACHA20_v2", resp.Data["keyLabel"]).Error())
		}
	})
	t.Run("C.7 Export CHACHA20 Key with name integrationTestKeyCHACHA20", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_chacha20/export", map[string]interface{}{})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp.Data["secretKey"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Secret Key got %s", "null").Error())
		}
	})
	t.Run("C.8 Test Remove Key CHACHA20 Key with name integrationTestKeyCHACHA20", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		_, err := client.Delete(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_chacha20", vault.WithQueryParameters(url.Values{
			"removeFromHSM": {"true"},
		}))
		if err != nil {
			assert.FailNow(t, err.Error())
		}
	})
}
