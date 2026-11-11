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

package tests

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	testHelpers "securosys.ch/test-helpers"
)

func TestIntegrationMariaDB(t *testing.T) {
	testHelpers.RequireTSBConfig(t)

	testEnv, err := testHelpers.NewTestEnv()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      "integrations/mariadb/test",
			Storage:   testEnv.Storage,
		})
		_ = testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_rsa_2048")
	})

	t.Run("A) add config", testEnv.AddConfig)

	t.Run("B) Test Creating RSA key", func(t *testing.T) {
		now := time.Now().UTC()
		timeStr := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02dZ", now.Year(), int(now.Month()), now.Day(), now.Hour(), now.Minute(), now.Second())
		err := testHelpers.TestKeyCreateWithoutCleanup(testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_RSA_2048_" + timeStr,
			"keySize":    2048,
			"attributes": `{"decrypt": true,"sign": false,"unwrap": true,"derive": true,"sensitive": false,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
		}, "custom_rsa_2048", "rsa")

		assert.NoError(t, err)

	})
	t.Run("C)Add generate secret", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "integrations/mariadb/test",
			Data: map[string]interface{}{
				"keyName":         "custom_rsa_2048",
				"cipherAlgorithm": "RSA",
			},
			Storage: testEnv.Storage,
		})
		assert.NoError(t, err)

	})
	t.Run("D)Read secret", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "integrations/mariadb/test/v1?key_name=custom_rsa_2048&cipher_algorithm=RSA",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})
		assert.NoError(t, err)

	})
	t.Run("E) Rotate secret", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "integrations/mariadb/test",
			Data: map[string]interface{}{
				"keyName":         "custom_rsa_2048",
				"cipherAlgorithm": "RSA",
			},
			Storage: testEnv.Storage,
		})
		assert.NoError(t, err)

	})
	t.Run("F) List secret", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "integrations/mariadb",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})
		assert.NoError(t, err)

	})
	t.Run("G) Delete secret", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      "integrations/mariadb/test",
			Storage:   testEnv.Storage,
		})
		assert.NoError(t, err)

	})
	t.Run("H) Test Delete RSA key", func(t *testing.T) {
		err = testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_rsa_2048")
		assert.NoError(t, err)
	})
}
