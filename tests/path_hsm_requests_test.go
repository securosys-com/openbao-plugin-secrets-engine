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
	"github.com/stretchr/testify/require"
)

func TestRequests(t *testing.T) {

	testEnv := getSharedTestEnv(t)

	t.Run("Test Create async operation - decrypt", func(t *testing.T) {
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/encrypt/test_rsa_2048_policy",
			Data: map[string]interface{}{
				"cipherAlgorithm": "RSA_PADDING_OAEP_WITH_SHA512",
				"payload":         "cGF5bG9hZA==",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on encrypt RSA - cipher RSA_PADDING_OAEP_WITH_SHA512 - %s", err.Error()))
		}
		resp, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/decrypt/test_rsa_2048_policy",
			Data: map[string]interface{}{
				"keyVersion":                resp.Data["keyVersion"],
				"cipherAlgorithm":           "RSA_PADDING_OAEP_WITH_SHA512",
				"encryptedPayload":          resp.Data["encryptedPayload"],
				"initializationVector":      resp.Data["initializationVector"],
				"messageAuthenticationCode": resp.Data["messageAuthenticationCode"],
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			if resp != nil {
				removeRequest(t, testEnv.Backend, testEnv.Storage, resp.Data["id"].(string))
			}
			assert.FailNow(t, err.Error())
		}
		if resp.Data["type"].(string) != "Decrypt" {
			removeRequest(t, testEnv.Backend, testEnv.Storage, resp.Data["id"].(string))
			assert.FailNow(t, err.Error())
		}
		trackRequest(t, testEnv.Backend, testEnv.Storage, resp, "Decrypt")
	})
	t.Run("Test Create async operation - unwrap", func(t *testing.T) {
		now := time.Now().UTC()
		timeStr := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02dZ", now.Year(), int(now.Month()), now.Day(), now.Hour(), now.Minute(), now.Second())
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/wrap/test_aes_128/test_rsa_2048_policy",
			Data: map[string]interface{}{
				"wrapMethod": "RSA_WRAP_OAEP",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on wrap RSA - wrap method RSA_WRAP_OAEP - %s", err.Error()))
		}
		resp, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/unwrap/unwraped_key_test/test_rsa_2048_policy",
			Data: map[string]interface{}{
				"keyVersion": resp.Data["keyVersion"],
				"keyLabel":   "unwraped_key_test_" + timeStr,
				"wrappedKey": resp.Data["wrappedKey"],
				"wrapMethod": "RSA_WRAP_OAEP",
				"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": false,"sensitive": true,"extractable": false,"modifiable": true,"destroyable": true}`,
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp.Data["type"].(string) != "UnWrap" {
			removeRequest(t, testEnv.Backend, testEnv.Storage, resp.Data["id"].(string))
			assert.FailNow(t, err.Error())
		}
		trackRequest(t, testEnv.Backend, testEnv.Storage, resp, "UnWrap")
	})
	t.Run("Test Create async operation - sign", func(t *testing.T) {
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/sign/test_rsa_2048_policy",
			Data: map[string]interface{}{
				"payloadType":        "UNSPECIFIED",
				"payload":            "cGF5bG9hZA==",
				"signatureAlgorithm": "SHA512_WITH_RSA_PSS",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on sign RSA - signature SHA512_WITH_RSA_PSS - %s", err.Error()))
		}
		if resp.Data["type"].(string) != "Sign" {
			assert.FailNow(t, err.Error())
		}
		trackRequest(t, testEnv.Backend, testEnv.Storage, resp, "Sign")
	})
	t.Run("Test Create async operation - block", func(t *testing.T) {
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/test_rsa_2048_policy/block",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on block RSA - %s", err.Error()))
		}
		if resp.Data["type"].(string) != "Block" {
			assert.FailNow(t, err.Error())
		}
		trackRequest(t, testEnv.Backend, testEnv.Storage, resp, "Block")
	})
	t.Run("Test Create async operation - unblock", func(t *testing.T) {
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/test_rsa_2048_policy/unblock",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on unblock RSA - %s", err.Error()))
		}
		if resp.Data["type"].(string) != "UnBlock" {
			assert.FailNow(t, err.Error())
		}
		trackRequest(t, testEnv.Backend, testEnv.Storage, resp, "UnBlock")
	})
	t.Run("Test Create async operation - modify", func(t *testing.T) {
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/test_rsa_2048_policy/modify",
			Data: map[string]interface{}{
				"simplePolicy": `{"MICHAL NOWAK":"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAouyYMgsCbxdr6cN7EDIR4ZcB82/fAIZusqyNXpX6gcRTwnrxZfIlyATdAm7ascxgYIK+L2M9UFVKTPUxus/Hzfuq0Fro5tdH+DWwfYQtcB5vap3UTw3yNpi6/MUe1x1Odwwi3no3jE2OuF1k6wjyrbWBkyktF3g8BmOD0DFpGl4IIlE8u1NgOMyAzlIuzAiyl4aCHrddhfV6gFtrRqfpUMz0twXYYoHlK0khzVEVn757WZZcIQFZmjKMfp/Yl/CAkBrTGVnFHMmNOYq7L9vhoR71rPmU9u2sy6IaT97qox/e7HSW47N2YNSiuJeq08I3Tn/kyw6+pSjAMu4A48PrfQIDAQAB","TOMMAD":"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhXglPuzN4MeMxkSptpmXK2klFGiGCODDVR1gM7ykxdc/JIQ2IPmA0Dq1a0ERNTVlFWhXNCWVUzSoWZ0St4hA+GMB8ZA1n9pM8V/e8RP6ej0aCBOfbOan7Q9GuHvs08RBF29hqsoVAFyAOoCxfs0Dv26Eb+PQgtPl6hTYjcSUVqWfHPoTjm+L6jLvdoFtE02muPon8Vno3wb9aGy1GYn/2ZSDtYg8HYV6Due7XKBJbmOMt5S6UHxc5Q+94v6xdjjijYM8sR1E7Hm4dTlocg4vlIHOXIdjFqSJlx87t21a+hyLEk15VjQUsKvUSu/jKTr4MvZwqar6EwGYRRCdwdWD1QIDAQAB"}`,
			},
			Storage: testEnv.Storage,
		})

		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on modify RSA - %s", err.Error()))
		}
		if resp.Data["type"].(string) != "Modify" {
			assert.FailNow(t, err.Error())
		}

		trackRequest(t, testEnv.Backend, testEnv.Storage, resp, "Modify")
	})
}
func removeRequest(t *testing.T, b logical.Backend, s logical.Storage, id string) {
	t.Helper()

	if id == "" {
		return
	}
	_, _ = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "requests/" + id,
		Data:      map[string]interface{}{},
		Storage:   s,
	})
}

func trackRequest(t *testing.T, b logical.Backend, s logical.Storage, resp *logical.Response, requestType string) {
	t.Helper()

	require.NotNil(t, resp)
	require.False(t, resp.IsError(), "create request failed: %v", resp.Error())
	require.Equal(t, requestType, resp.Data["type"])

	requestID, ok := resp.Data["id"].(string)
	require.True(t, ok, "request response should contain id string")
	require.NotEmpty(t, requestID)
	require.NotEmpty(t, resp.Data["status"], "request %s should have status", requestID)

	t.Cleanup(func() {
		removeRequest(t, b, s, requestID)
	})
}
