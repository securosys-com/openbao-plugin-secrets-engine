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

func TestECKey(t *testing.T) {
	testHelpers.RequireTSBConfig(t)

	testEnv, err := testHelpers.NewTestEnv()
	if err != nil {
		t.Fatal(err)
	}
	t.Run("add config", testEnv.AddConfig)

	t.Run("Test Creating EC key = curveOid secp256k1", func(t *testing.T) {
		now := time.Now().UTC()
		timeStr := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02dZ", now.Year(), int(now.Month()), now.Day(), now.Hour(), now.Minute(), now.Second())
		err := testHelpers.TestKeyCreate(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_EC_secp256k1_" + timeStr,
			"curveOid":   "1.3.132.0.10",
			"attributes": `{"decrypt": true,"sign": false,"unwrap": true,"derive": true,"sensitive": false,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
		}, "custom_ec_secp256k1", "ec")

		assert.NoError(t, err)

		err = testHelpers.TestKeyRead(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"baseLabel": "TEST_SECUROSYS_SECRETS_ENGINE_EC_secp256k1_" + timeStr,
			"curveOid":  "1.3.132.0.10",
			"algorithm": "EC",
		}, "custom_ec_secp256k1")
		if err != nil {
			testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_ec_secp256k1")
		}
		assert.NoError(t, err)
		err = testHelpers.TestKeyReadXML(t, testEnv.Backend, testEnv.Storage, []string{
			"xml", "keyLabel", "xmlSignature",
		}, "custom_ec_secp256k1")
		if err != nil {
			testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_ec_")
		}

		assert.NoError(t, err)
		err = testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_ec_secp256k1")

		assert.NoError(t, err)
	})
	t.Run("Test Creating EC key = curveOid secp384r1", func(t *testing.T) {
		now := time.Now().UTC()
		timeStr := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02dZ", now.Year(), int(now.Month()), now.Day(), now.Hour(), now.Minute(), now.Second())
		err := testHelpers.TestKeyCreate(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_EC_secp384r1_" + timeStr,
			"curveOid":   "1.3.132.0.34",
			"attributes": `{"decrypt": true,"sign": false,"unwrap": true,"derive": true,"sensitive": false,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
		}, "custom_ec_secp384r1", "ec")

		assert.NoError(t, err)

		err = testHelpers.TestKeyRead(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"baseLabel": "TEST_SECUROSYS_SECRETS_ENGINE_EC_secp384r1_" + timeStr,
			"curveOid":  "1.3.132.0.34",
			"algorithm": "EC",
		}, "custom_ec_secp384r1")
		if err != nil {
			testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_ec_secp384r1")
		}
		assert.NoError(t, err)
		err = testHelpers.TestKeyReadXML(t, testEnv.Backend, testEnv.Storage, []string{
			"xml", "keyLabel", "xmlSignature",
		}, "custom_ec_secp384r1")
		if err != nil {
			testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_ec_secp384r1")
		}
		assert.NoError(t, err)

		err = testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_ec_secp384r1")

		assert.NoError(t, err)
	})
	t.Run("Test Creating EC key = curveOid (prime256v1 / secp256r1)", func(t *testing.T) {
		now := time.Now().UTC()
		timeStr := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02dZ", now.Year(), int(now.Month()), now.Day(), now.Hour(), now.Minute(), now.Second())
		err := testHelpers.TestKeyCreate(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_EC_prime256v1_secp256r1_" + timeStr,
			"curveOid":   "1.2.840.10045.3.1.7",
			"attributes": `{"decrypt": true,"sign": false,"unwrap": true,"derive": true,"sensitive": false,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
		}, "custom_ec_prime256v1_secp256r1", "ec")

		assert.NoError(t, err)

		err = testHelpers.TestKeyRead(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"baseLabel": "TEST_SECUROSYS_SECRETS_ENGINE_EC_prime256v1_secp256r1_" + timeStr,
			"curveOid":  "1.2.840.10045.3.1.7",
			"algorithm": "EC",
		}, "custom_ec_prime256v1_secp256r1")
		if err != nil {
			testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_ec_prime256v1_secp256r1")
		}
		assert.NoError(t, err)

		err = testHelpers.TestKeyReadXML(t, testEnv.Backend, testEnv.Storage, []string{
			"xml", "keyLabel", "xmlSignature",
		}, "custom_ec_prime256v1_secp256r1")
		if err != nil {
			testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_ec_prime256v1_secp256r1")
		}
		assert.NoError(t, err)
		err = testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_ec_prime256v1_secp256r1")

		assert.NoError(t, err)
	})
}
