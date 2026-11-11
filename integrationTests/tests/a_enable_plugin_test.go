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
	"testing"

	"github.com/hashicorp/vault-client-go/schema"
	"github.com/stretchr/testify/assert"
	integrationClient "securosys.ch/integration/client"
)

func TestEnablePlugin(t *testing.T) {
	cleanupIntegrationKeysForTest(t)

	t.Run("A.1 Test Enable Plugin", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		_, err := client.System.MountsEnableSecretsEngine(ctx, integrationClient.VaultConfig.SecretsEnginePath, schema.MountsEnableSecretsEngineRequest{
			Type: "securosys-hsm",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
	})
}
