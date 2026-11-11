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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	integrationClient "securosys.ch/integration/client"
	testHelpers "securosys.ch/test-helpers"
)

func TestConfigPlugin(t *testing.T) {
	cleanupIntegrationKeysForTest(t)

	t.Run("B.1 Test Config Plugin", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/config", testHelpers.ConfigParams)
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data["result"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Connection successful got %s", "null").Error())
		}

		if !strings.Contains(resp.Data["result"].(string), "Connection successful:") {
			assert.FailNow(t, fmt.Errorf("Expected: Connection successful  got %s", resp.Data["result"]).Error())
		}
	})
}
