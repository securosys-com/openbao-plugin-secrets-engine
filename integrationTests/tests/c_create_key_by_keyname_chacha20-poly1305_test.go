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

func TestCreateKeyByKeyNameCHACHA20POLY1305Plugin(t *testing.T) {
	cleanupIntegrationKeysForTest(t)

	t.Run("C.1 Test Create Key RSA Key with label integrationTestKeyCHACHA20POLY1305Name using name chacha20-poly1305", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/type/chacha20-poly1305/integration_test_key_aes_name", map[string]interface{}{
			"keyLabel": "integrationTestKeyCHACHA20POLY1305Name",
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
		if resp.Data["baseLabel"].(string) != "integrationTestKeyCHACHA20POLY1305Name" {
			assert.FailNow(t, fmt.Errorf("Expected: Key name %s got %s", "integrationTestKeyCHACHA20POLY1305Name", resp.Data["baseLabel"]).Error())
		}
		if resp.Data["version"].(string) != "v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key version %s got %s", "v1", resp.Data["version"]).Error())
		}
		if resp.Data["keySize"].(json.Number) != json.Number("256") {
			assert.FailNow(t, fmt.Errorf("Expected: Key size %s got %s", "256", resp.Data["keySize"]).Error())
		}
		if resp.Data["keyLabel"].(string) != "integrationTestKeyCHACHA20POLY1305Name_v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key label %s got %s", "integrationTestKeyCHACHA20POLY1305Name_v1", resp.Data["keyLabel"]).Error())
		}
	})
	t.Run("C.2 Test Remove Key RSA Key with name integrationTestKeyCHACHA20POLY1305Name", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		_, err := client.Delete(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_aes_name", vault.WithQueryParameters(url.Values{
			"removeFromHSM": {"true"},
		}))
		if err != nil {
			assert.FailNow(t, err.Error())
		}
	})
}
