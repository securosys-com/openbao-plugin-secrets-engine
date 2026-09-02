/*
Copyright (c) 2026 Securosys SA, authors: Tomasz Madej

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
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/vault-client-go"
	integrationClient "securosys.ch/integration/client"
)

var integrationTestKeyNames = []string{
	"integration_test_camellia_key",
	"integration_test_chacha20_key",
	"integration_test_key_aes",
	"integration_test_key_aes_128",
	"integration_test_key_aes_192",
	"integration_test_key_aes_256",
	"integration_test_key_aes_name",
	"integration_test_key_aes_wrap",
	"integration_test_key_bls",
	"integration_test_key_bls_wrap",
	"integration_test_key_camellia",
	"integration_test_key_chacha20",
	"integration_test_key_dsa",
	"integration_test_key_dsa_1024",
	"integration_test_key_dsa_2048",
	"integration_test_key_dsa_wrap",
	"integration_test_key_ec",
	"integration_test_key_ec_name",
	"integration_test_key_ec_prime256v1",
	"integration_test_key_ec_secp256k1",
	"integration_test_key_ec_secp384r1",
	"integration_test_key_ec_wrap",
	"integration_test_key_ed",
	"integration_test_key_ed_ed25519",
	"integration_test_key_ed_name",
	"integration_test_key_ed_wrap",
	"integration_test_key_rsa",
	"integration_test_key_rsa_2048",
	"integration_test_key_rsa_3072",
	"integration_test_key_rsa_4096",
	"integration_test_key_rsa_name",
	"integration_test_key_rsa_wrap",
	"integration_test_smart_key_rsa",
	"integration_test_tdea_key",
	"unwraped_key_test",
}

func TestMain(m *testing.M) {
	cleanupIntegrationKeys()
	code := m.Run()
	cleanupIntegrationKeys()
	os.Exit(code)
}

func cleanupIntegrationKeysForTest(t *testing.T) {
	t.Helper()
	t.Cleanup(cleanupIntegrationKeys)
}

func cleanupIntegrationKeys() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := integrationClient.InitVaultClient()

	for _, keyName := range integrationTestKeyNames {
		if ctx.Err() != nil {
			return
		}

		_, _ = client.Delete(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/"+keyName, vault.WithQueryParameters(url.Values{
			"removeFromHSM": {"true"},
		}))
	}
}
