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

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	backend "securosys.ch/backend"
	testHelpers "securosys.ch/test-helpers"
)

func TestKeys(t *testing.T) {
	testEnv := getSharedTestEnv(t)
	var err error
	t.Run("Test keys list", func(t *testing.T) {
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "keys/",
			Storage:   testEnv.Storage,
		})
		if len(resp.Data["keys"].([]string)) < 11 {
			assert.FailNow(t, fmt.Sprintf("Expected 11 keys, but got %d", len(resp.Data["keys"].([]string))))

		}
		if err != nil {
			assert.FailNow(t, err.Error())
		}

	})
	t.Run("Test keys hsm list", func(t *testing.T) {
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "keys_hsm/",
			Storage:   testEnv.Storage,
		})
		if len(resp.Data["keys"].([]string)) < 11 {
			assert.FailNow(t, fmt.Sprintf("Expected 11 keys, but got %d", len(resp.Data["keys"].([]string))))
		}
		if err != nil {
			assert.FailNow(t, err.Error())
		}

	})
	t.Run("Test Export Keys", func(t *testing.T) {
		_, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/test_aes_256/export",
			Storage:   testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/test_camellia/export",
			Storage:   testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/test_chacha20/export",
			Storage:   testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/test_tdea/export",
			Storage:   testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}

	})
	t.Run("Test Register Keys", func(t *testing.T) {
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "keys/test_aes_256",
			Storage:   testEnv.Storage,
		})
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/test_aes_256_2/register",
			Data: map[string]interface{}{
				"keyLabel": resp.Data["keyLabel"],
			},
			Storage: testEnv.Storage,
		})
		err = testHelpers.TestKeyRead(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"keyLabel":  resp.Data["keyLabel"],
			"keySize":   resp.Data["keySize"],
			"algorithm": resp.Data["algorithm"],
		}, "test_aes_256_2")

		if err != nil {
			assert.FailNow(t, err.Error())
		}

	})
	t.Run("Test Read Keys", func(t *testing.T) {
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "keys/test_aes_256",
			Storage:   testEnv.Storage,
		})
		err = testHelpers.TestKeyRead(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"keyLabel":  resp.Data["keyLabel"],
			"keySize":   resp.Data["keySize"],
			"algorithm": resp.Data["algorithm"],
		}, "test_aes_256")

		if err != nil {
			assert.FailNow(t, err.Error())
		}

	})
	t.Run("Test Block Keys", func(t *testing.T) {
		_, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/test_rsa_2048_modify/block",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		key, err := backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "test_rsa_2048_modify")
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if key.GetActiveVersion().Policy.KeyStatus.Blocked == false {
			assert.FailNow(t, fmt.Sprintf("Key %s is not blocked!", "test_rsa_2048_modify"))
		}
	})
	t.Run("Test UnBlock Keys", func(t *testing.T) {
		_, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/test_rsa_2048_modify/unblock",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {
			assert.FailNow(t, err.Error())
		}
		key, err := backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "test_rsa_2048_modify")
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if key.GetActiveVersion().Policy.KeyStatus.Blocked == true {
			assert.FailNow(t, fmt.Sprintf("Key %s is blocked!", "test_rsa_2048_modify"))
		}

	})
	t.Run("Test Modify Keys", func(t *testing.T) {
		key, err := backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "test_rsa_2048_modify")
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		groupsLenBefore := len(key.GetActiveVersion().Policy.RuleUse.Tokens[0].Groups)
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/test_rsa_2048_modify/modify",
			Data: map[string]interface{}{
				"simplePolicy": `{"MICHAL NOWAK":"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAouyYMgsCbxdr6cN7EDIR4ZcB82/fAIZusqyNXpX6gcRTwnrxZfIlyATdAm7ascxgYIK+L2M9UFVKTPUxus/Hzfuq0Fro5tdH+DWwfYQtcB5vap3UTw3yNpi6/MUe1x1Odwwi3no3jE2OuF1k6wjyrbWBkyktF3g8BmOD0DFpGl4IIlE8u1NgOMyAzlIuzAiyl4aCHrddhfV6gFtrRqfpUMz0twXYYoHlK0khzVEVn757WZZcIQFZmjKMfp/Yl/CAkBrTGVnFHMmNOYq7L9vhoR71rPmU9u2sy6IaT97qox/e7HSW47N2YNSiuJeq08I3Tn/kyw6+pSjAMu4A48PrfQIDAQAB"}`,
			},
			Storage: testEnv.Storage,
		})

		if err != nil {
			assert.FailNow(t, err.Error())
		}
		key, err = backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "test_rsa_2048_modify")
		if groupsLenBefore == len(key.GetActiveVersion().Policy.RuleUse.Tokens[0].Groups) {
			assert.FailNow(t, fmt.Sprintf("Modify for the %s was not changed policy", "test_rsa_2048"))
		}
		if *key.GetActiveVersion().Policy.RuleUse.Tokens[0].Groups[0].Approvals[0].Name != "MICHAL NOWAK" && *key.GetActiveVersion().Policy.RuleUse.Tokens[0].Groups[0].Approvals[0].Value != "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAouyYMgsCbxdr6cN7EDIR4ZcB82/fAIZusqyNXpX6gcRTwnrxZfIlyATdAm7ascxgYIK+L2M9UFVKTPUxus/Hzfuq0Fro5tdH+DWwfYQtcB5vap3UTw3yNpi6/MUe1x1Odwwi3no3jE2OuF1k6wjyrbWBkyktF3g8BmOD0DFpGl4IIlE8u1NgOMyAzlIuzAiyl4aCHrddhfV6gFtrRqfpUMz0twXYYoHlK0khzVEVn757WZZcIQFZmjKMfp/Yl/CAkBrTGVnFHMmNOYq7L9vhoR71rPmU9u2sy6IaT97qox/e7HSW47N2YNSiuJeq08I3Tn/kyw6+pSjAMu4A48PrfQIDAQAB" {
			assert.FailNow(t, fmt.Sprintf("Modify for the %s was not changed policy. Expected approval name MICHAL NOWAK", "test_rsa_2048"))
		}

	})
	t.Run("Test Rotate Keys", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/test_aes_256_rotate/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {
			assert.FailNow(t, err.Error())
		}
		key, err := backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "test_aes_256_rotate")
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Got error: %s", "test_aes_256_rotate", err.Error()))

		}
		if key.CurrentVersion != "v2" {
			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Expected key version 'v2' got '%s'", "test_aes_256_rotate", key.CurrentVersion))

		}

	})
	t.Run("Test Key Version List", func(t *testing.T) {
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "keys/test_aes_256_rotate/",
			Storage:   testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if len(resp.Data["keys"].([]string)) < 2 {
			assert.FailNow(t, fmt.Sprintf("Expected 2 key versions, but got %d", len(resp.Data["keys"].([]string))))
		}

	})
	t.Run("Test Read Key Version v2", func(t *testing.T) {
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "keys/test_aes_256_rotate/v2",
			Storage:   testEnv.Storage,
		})

		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp.Data["version"] != "v2" {
			assert.FailNow(t, fmt.Sprintf("Wrong key version. Expected v2 got %s", resp.Data["version"]))
		}

	})
	t.Run("Test Key Delete Version - Active", func(t *testing.T) {
		_, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      "keys/test_aes_256_rotate/v2",
			Storage:   testEnv.Storage,
		})
		if err == nil {
			assert.FailNow(t, fmt.Sprintf("Expected error on deleting current active key version"))
		}

	})
	t.Run("Test Key Delete Version", func(t *testing.T) {
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      "keys/test_aes_256_rotate/v1",
			Storage:   testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		resp, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ListOperation,
			Path:      "keys/test_aes_256_rotate/",
			Storage:   testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if len(resp.Data["keys"].([]string)) != 1 {
			assert.FailNow(t, fmt.Sprintf("Expected 1 key version, but got %d", len(resp.Data["keys"].([]string))))
		}

	})
	t.Run("Test Update Password", func(t *testing.T) {
		_, err := backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "test_rsa_2048_pass")
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/test_rsa_2048_pass/update-password",
			Data: map[string]interface{}{
				"password":    "",
				"newPassword": "pass",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/test_rsa_2048_pass/update-password",
			Data: map[string]interface{}{
				"password":    "pass",
				"newPassword": "",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}

	})
}
