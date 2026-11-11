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
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	testHelpers "securosys.ch/test-helpers"
)

func TestDSAKey(t *testing.T) {
	testHelpers.RequireTSBConfig(t)

	testEnv, err := testHelpers.NewTestEnv()
	if err != nil {
		t.Fatal(err)
	}
	t.Run("add config", testEnv.AddConfig)

	t.Run("Test Creating DSA key = KeySize 1024", func(t *testing.T) {
		now := time.Now().UTC()
		timeStr := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02dZ", now.Year(), int(now.Month()), now.Day(), now.Hour(), now.Minute(), now.Second())
		err := testHelpers.TestKeyCreate(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_DSA_1024_" + timeStr,
			"keySize":    1024,
			"attributes": `{"decrypt": true,"sign": false,"unwrap": true,"derive": true,"sensitive": false,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
		}, "custom_dsa_1024", "dsa")

		assert.NoError(t, err)

		err = testHelpers.TestKeyRead(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"baseLabel": "TEST_SECUROSYS_SECRETS_ENGINE_DSA_1024_" + timeStr,
			"keySize":   1024,
			"algorithm": "DSA",
		}, "custom_dsa_1024")
		if err != nil {
			testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_dsa_1024")
		}
		assert.NoError(t, err)
		err = testHelpers.TestKeyReadXML(t, testEnv.Backend, testEnv.Storage, []string{
			"xml", "keyLabel", "xmlSignature",
		}, "custom_dsa_1024")
		if err != nil {
			testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_dsa_1024")
		}
		assert.NoError(t, err)
		err = testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_dsa_1024")

		assert.NoError(t, err)
	})
	t.Run("Test Creating DSA key = KeySize 2048", func(t *testing.T) {
		now := time.Now().UTC()
		timeStr := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02dZ", now.Year(), int(now.Month()), now.Day(), now.Hour(), now.Minute(), now.Second())
		err := testHelpers.TestKeyCreate(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_DSA_2048_" + timeStr,
			"keySize":    2048,
			"attributes": `{"decrypt": true,"sign": false,"unwrap": true,"derive": true,"sensitive": false,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
		}, "custom_dsa_2048", "dsa")

		assert.NoError(t, err)

		err = testHelpers.TestKeyRead(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"baseLabel": "TEST_SECUROSYS_SECRETS_ENGINE_DSA_2048_" + timeStr,
			"keySize":   2048,
			"algorithm": "DSA",
		}, "custom_dsa_2048")
		if err != nil {
			testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_dsa_2048")
		}
		assert.NoError(t, err)
		err = testHelpers.TestKeyReadXML(t, testEnv.Backend, testEnv.Storage, []string{
			"xml", "keyLabel", "xmlSignature",
		}, "custom_dsa_2048")
		if err != nil {
			testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_dsa_2048")
		}
		assert.NoError(t, err)
		err = testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_dsa_2048")

		assert.NoError(t, err)
	})
}
