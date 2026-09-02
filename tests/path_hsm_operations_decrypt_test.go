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
)

func TestOperationsDecrypt(t *testing.T) {
	testEnv := getSharedTestEnv(t)
	var err error
	t.Run("Test Decrypt AES - cipher AES", func(t *testing.T) {
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/encrypt/test_aes_256",
			Data: map[string]interface{}{
				"cipherAlgorithm": "AES",
				"payload":         "cGF5bG9hZA==",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on encrypt AES - cipher AES - %s", err.Error()))
		}
		resp, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/decrypt/test_aes_256",
			Data: map[string]interface{}{
				"cipherAlgorithm":           "AES",
				"keyVersion":                "v1",
				"encryptedPayload":          resp.Data["encryptedPayload"],
				"initializationVector":      resp.Data["initializationVector"],
				"messageAuthenticationCode": resp.Data["messageAuthenticationCode"],
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt AES - cipher AES - %s", err.Error()))
		}
		if resp.Data["payload"] != "cGF5bG9hZA==" {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt AES - wrong payload. Expected '%s' got '%s'", "cGF5bG9hZA==", resp.Data["payload"]))
		}
	})
	t.Run("Test Decrypt AES - cipher AES - alternative", func(t *testing.T) {
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/encrypt/test_aes_256",
			Data: map[string]interface{}{
				"cipherAlgorithm": "AES",
				"payload":         "cGF5bG9hZA==",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on encrypt AES - cipher AES - %s", err.Error()))
		}
		resp, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/decrypt/test_aes_256/v1",
			Data: map[string]interface{}{
				"cipherAlgorithm":           "AES",
				"encryptedPayload":          resp.Data["encryptedPayload"],
				"initializationVector":      resp.Data["initializationVector"],
				"messageAuthenticationCode": resp.Data["messageAuthenticationCode"],
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt AES - cipher AES - %s", err.Error()))
		}
		if resp.Data["payload"] != "cGF5bG9hZA==" {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt AES - wrong payload. Expected '%s' got '%s'", "cGF5bG9hZA==", resp.Data["payload"]))
		}
	})
	t.Run("Test Decrypt AES -  after rotate - cipher AES_GCM - 96", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/type_aes/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/encrypt/type_aes",
			Data: map[string]interface{}{
				"payload": "cGF5bG9hZA==",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on encrypt AES - cipher AES_GCM - %s", err.Error()))
		}
		resp, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/decrypt/type_aes",
			Data: map[string]interface{}{
				"keyVersion":                "v2",
				"encryptedPayload":          resp.Data["encryptedPayload"],
				"initializationVector":      resp.Data["initializationVector"],
				"messageAuthenticationCode": resp.Data["messageAuthenticationCode"],
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt AES - cipher AES_GCM - %s", err.Error()))
		}
		if resp.Data["payload"] != "cGF5bG9hZA==" {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt AES - wrong payload. Expected '%s' got '%s'", "cGF5bG9hZA==", resp.Data["payload"]))
		}
	})
	t.Run("Test Decrypt AES -  before rotate - cipher AES_GCM - 96", func(t *testing.T) {
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/encrypt/type_aes",
			Data: map[string]interface{}{
				"payload": "cGF5bG9hZA==",
			},
			Storage: testEnv.Storage,
		})
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/type_aes/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on encrypt AES - cipher AES - %s", err.Error()))
		}
		resp, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/decrypt/type_aes",
			Data: map[string]interface{}{
				"keyVersion":                resp.Data["keyVersion"],
				"encryptedPayload":          resp.Data["encryptedPayload"],
				"initializationVector":      resp.Data["initializationVector"],
				"messageAuthenticationCode": resp.Data["messageAuthenticationCode"],
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt AES - cipher AES_GCM - %s", err.Error()))
		}
		if resp.Data["payload"] != "cGF5bG9hZA==" {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt AES - wrong payload. Expected '%s' got '%s'", "cGF5bG9hZA==", resp.Data["payload"]))
		}
	})
	t.Run("Test Decrypt AES - cipher AES_GCM", func(t *testing.T) {
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/encrypt/test_aes_256",
			Data: map[string]interface{}{
				"cipherAlgorithm": "AES_GCM",
				"payload":         "cGF5bG9hZA==",
				"tagLength":       -1,
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on encrypt AES - cipher AES_GCM - %s", err.Error()))
		}
		resp, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/decrypt/test_aes_256",
			Data: map[string]interface{}{
				"cipherAlgorithm":           "AES_GCM",
				"keyVersion":                "v1",
				"encryptedPayload":          resp.Data["encryptedPayload"],
				"initializationVector":      resp.Data["initializationVector"],
				"messageAuthenticationCode": resp.Data["messageAuthenticationCode"],
				"tagLength":                 -1,
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt AES - cipher AES_GCM - %s", err.Error()))
		}
		if resp.Data["payload"] != "cGF5bG9hZA==" {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt AES - wrong payload. Expected '%s' got '%s'", "cGF5bG9hZA==", resp.Data["payload"]))
		}
	})
	t.Run("Test Decrypt AES - cipher CTR", func(t *testing.T) {
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/encrypt/test_aes_256",
			Data: map[string]interface{}{
				"cipherAlgorithm": "AES_CTR",
				"payload":         "cGF5bG9hZA==",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on encrypt AES - cipher AES_CTR - %s", err.Error()))
		}
		resp, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/decrypt/test_aes_256",
			Data: map[string]interface{}{
				"cipherAlgorithm":           "AES_CTR",
				"keyVersion":                "v1",
				"encryptedPayload":          resp.Data["encryptedPayload"],
				"initializationVector":      resp.Data["initializationVector"],
				"messageAuthenticationCode": resp.Data["messageAuthenticationCode"],
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt AES - cipher AES_CTR - %s", err.Error()))
		}
		if resp.Data["payload"] != "cGF5bG9hZA==" {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt AES - wrong payload. Expected '%s' got '%s'", "cGF5bG9hZA==", resp.Data["payload"]))
		}

	})
	t.Run("Test Decrypt AES - cipher ECB", func(t *testing.T) {
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/encrypt/test_aes_256",
			Data: map[string]interface{}{
				"cipherAlgorithm": "AES_ECB",
				"payload":         "cGF5bG9hZA==",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on encrypt AES - cipher AES_ECB - %s", err.Error()))
		}
		resp, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/decrypt/test_aes_256",
			Data: map[string]interface{}{
				"cipherAlgorithm":           "AES_ECB",
				"keyVersion":                "v1",
				"encryptedPayload":          resp.Data["encryptedPayload"],
				"initializationVector":      resp.Data["initializationVector"],
				"messageAuthenticationCode": resp.Data["messageAuthenticationCode"],
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt AES - cipher AES_ECB - %s", err.Error()))
		}
		if resp.Data["payload"] != "cGF5bG9hZA==" {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt AES - wrong payload. Expected '%s' got '%s'", "cGF5bG9hZA==", resp.Data["payload"]))
		}
	})
	t.Run("Test Decrypt AES - cipher AES_CBC_NO_PADDING", func(t *testing.T) {
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/encrypt/test_aes_256",
			Data: map[string]interface{}{
				"cipherAlgorithm": "AES_CBC_NO_PADDING",
				"payload":         "cGF5bG9hZA==",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on encrypt AES - cipher AES_CBC_NO_PADDING - %s", err.Error()))
		}
		resp, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/decrypt/test_aes_256",
			Data: map[string]interface{}{
				"cipherAlgorithm":           "AES_CBC_NO_PADDING",
				"keyVersion":                "v1",
				"encryptedPayload":          resp.Data["encryptedPayload"],
				"initializationVector":      resp.Data["initializationVector"],
				"messageAuthenticationCode": resp.Data["messageAuthenticationCode"],
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt AES - cipher AES_CBC_NO_PADDING - %s", err.Error()))
		}
		if resp.Data["payload"] != "cGF5bG9hZA==" {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt AES - wrong payload. Expected '%s' got '%s'", "cGF5bG9hZA==", resp.Data["payload"]))
		}

	})
	t.Run("Test Decrypt AES - wrong AES cipher algorithm", func(t *testing.T) {

		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/decrypt/test_aes_256",
			Data: map[string]interface{}{
				"cipherAlgorithm":      "RSA",
				"encryptedPayload":     "ELfKnNiGDj3cI74XYSLQEA==",
				"initializationVector": "waDAws/4fsRjf420RVq5Hg==",
			},
			Storage: testEnv.Storage,
		})
		assert.Error(t, err)

	})
	t.Run("Test Decrypt AES - wrong tagLength ", func(t *testing.T) {

		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/decrypt/test_aes_256",
			Data: map[string]interface{}{
				"cipherAlgorithm":      "AES_GCM",
				"keyVersion":           "v1",
				"encryptedPayload":     "ELfKnNiGDj3cI74XYSLQEA==",
				"initializationVector": "waDAws/4fsRjf420RVq5Hg==",
				"tagLength":            256,
			},
			Storage: testEnv.Storage,
		})

		assert.Error(t, err)

	})

	t.Run("Test Decrypt - No encryptedPayload", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/decrypt/test_aes_256",
			Data: map[string]interface{}{
				"cipherAlgorithm":      "AES",
				"keyVersion":           "v1",
				"initializationVector": "waDAws/4fsRjf420RVq5Hg==",
			},
			Storage: testEnv.Storage,
		})
		assert.Error(t, err)

	})
	t.Run("Test Decrypt - Wrong payload format", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/decrypt/test_aes_256",
			Data: map[string]interface{}{
				"cipherAlgorithm":      "AES",
				"encryptedPayload":     "test",
				"initializationVector": "waDAws/4fsRjf420RVq5Hg==",
			},
			Storage: testEnv.Storage,
		})
		assert.Error(t, err)

	})
	t.Run("Test Decrypt - Wrong key name", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/decrypt/test_aes_2562",
			Data: map[string]interface{}{
				"cipherAlgorithm":      "AES",
				"keyVersion":           "v1",
				"encryptedPayload":     "ELfKnNiGDj3cI74XYSLQEA==",
				"initializationVector": "waDAws/4fsRjf420RVq5Hg==",
			},
			Storage: testEnv.Storage,
		})
		assert.Error(t, err)

	})
	t.Run("Test Decrypt - Wrong key algorithm", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/decrypt/test_ec_secp256k1",
			Data: map[string]interface{}{
				"cipherAlgorithm":      "AES",
				"keyVersion":           "v1",
				"encryptedPayload":     "ELfKnNiGDj3cI74XYSLQEA==",
				"initializationVector": "waDAws/4fsRjf420RVq5Hg==",
			},
			Storage: testEnv.Storage,
		})
		assert.Error(t, err)

	})
	t.Run("Test Decrypt - No cipher algorithm", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/decrypt/test_aes_256",
			Data: map[string]interface{}{
				"keyVersion":           "v1",
				"encryptedPayload":     "ELfKnNiGDj3cI74XYSLQEA==",
				"initializationVector": "waDAws/4fsRjf420RVq5Hg==",
			},
			Storage: testEnv.Storage,
		})
		assert.Error(t, err)

	})
	t.Run("Test Decrypt - wrong AAD ", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/decrypt/test_aes_256",
			Data: map[string]interface{}{
				"cipherAlgorithm":              "AES",
				"keyVersion":                   "v1",
				"encryptedPayload":             "ELfKnNiGDj3cI74XYSLQEA==",
				"initializationVector":         "waDAws/4fsRjf420RVq5Hg==",
				"additionalAuthenticationData": "wrong_base64",
			},
			Storage: testEnv.Storage,
		})
		assert.Error(t, err)

	})
	t.Run("Test Decrypt RSA - cipher RSA_PADDING_OAEP_WITH_SHA512", func(t *testing.T) {
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/encrypt/test_rsa_2048",
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
			Path:      "operation/decrypt/test_rsa_2048",
			Data: map[string]interface{}{
				"cipherAlgorithm":           "RSA_PADDING_OAEP_WITH_SHA512",
				"keyVersion":                "v1",
				"encryptedPayload":          resp.Data["encryptedPayload"],
				"initializationVector":      resp.Data["initializationVector"],
				"messageAuthenticationCode": resp.Data["messageAuthenticationCode"],
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt RSA - cipher RSA_PADDING_OAEP_WITH_SHA512 - %s", err.Error()))
		}
		if resp.Data["payload"] != "cGF5bG9hZA==" {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt RSA - wrong payload. Expected '%s' got '%s'", "cGF5bG9hZA==", resp.Data["payload"]))
		}
	})
	t.Run("Test Decrypt RSA - cipher RSA", func(t *testing.T) {
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/encrypt/test_rsa_2048",
			Data: map[string]interface{}{
				"cipherAlgorithm": "RSA",
				"payload":         "cGF5bG9hZA==",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on encrypt RSA - cipher RSA - %s", err.Error()))
		}
		resp, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/decrypt/test_rsa_2048",
			Data: map[string]interface{}{
				"cipherAlgorithm":           "RSA",
				"keyVersion":                "v1",
				"encryptedPayload":          resp.Data["encryptedPayload"],
				"initializationVector":      resp.Data["initializationVector"],
				"messageAuthenticationCode": resp.Data["messageAuthenticationCode"],
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt RSA - cipher RSA - %s", err.Error()))
		}
		if resp.Data["payload"] != "cGF5bG9hZA==" {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt RSA - wrong payload. Expected '%s' got '%s'", "cGF5bG9hZA==", resp.Data["payload"]))
		}
	})
	t.Run("Test Decrypt RSA - cipher RSA_PADDING_OAEP_WITH_SHA224", func(t *testing.T) {
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/encrypt/test_rsa_2048",
			Data: map[string]interface{}{
				"cipherAlgorithm": "RSA_PADDING_OAEP_WITH_SHA224",
				"payload":         "cGF5bG9hZA==",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on encrypt RSA - cipher RSA_PADDING_OAEP_WITH_SHA224 - %s", err.Error()))
		}
		resp, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/decrypt/test_rsa_2048",
			Data: map[string]interface{}{
				"cipherAlgorithm":           "RSA_PADDING_OAEP_WITH_SHA224",
				"keyVersion":                "v1",
				"encryptedPayload":          resp.Data["encryptedPayload"],
				"initializationVector":      resp.Data["initializationVector"],
				"messageAuthenticationCode": resp.Data["messageAuthenticationCode"],
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt RSA - cipher RSA_PADDING_OAEP_WITH_SHA224 - %s", err.Error()))
		}
		if resp.Data["payload"] != "cGF5bG9hZA==" {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt RSA - wrong payload. Expected '%s' got '%s'", "cGF5bG9hZA==", resp.Data["payload"]))
		}
	})
	t.Run("Test Decrypt RSA - cipher RSA_PADDING_OAEP_WITH_SHA256", func(t *testing.T) {
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/encrypt/test_rsa_2048",
			Data: map[string]interface{}{
				"cipherAlgorithm": "RSA_PADDING_OAEP_WITH_SHA256",
				"payload":         "cGF5bG9hZA==",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on encrypt RSA - cipher RSA_PADDING_OAEP_WITH_SHA256 - %s", err.Error()))
		}
		resp, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/decrypt/test_rsa_2048",
			Data: map[string]interface{}{
				"cipherAlgorithm":           "RSA_PADDING_OAEP_WITH_SHA256",
				"keyVersion":                "v1",
				"encryptedPayload":          resp.Data["encryptedPayload"],
				"initializationVector":      resp.Data["initializationVector"],
				"messageAuthenticationCode": resp.Data["messageAuthenticationCode"],
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt RSA - cipher RSA_PADDING_OAEP_WITH_SHA256 - %s", err.Error()))
		}
		if resp.Data["payload"] != "cGF5bG9hZA==" {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt RSA - wrong payload. Expected '%s' got '%s'", "cGF5bG9hZA==", resp.Data["payload"]))
		}

	})
	t.Run("Test Decrypt RSA - cipher RSA_PADDING_OAEP_WITH_SHA1", func(t *testing.T) {
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/encrypt/test_rsa_2048",
			Data: map[string]interface{}{
				"cipherAlgorithm": "RSA_PADDING_OAEP_WITH_SHA1",
				"payload":         "cGF5bG9hZA==",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on encrypt RSA - cipher RSA_PADDING_OAEP_WITH_SHA1 - %s", err.Error()))
		}
		resp, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/decrypt/test_rsa_2048",
			Data: map[string]interface{}{
				"cipherAlgorithm":           "RSA_PADDING_OAEP_WITH_SHA1",
				"keyVersion":                "v1",
				"encryptedPayload":          resp.Data["encryptedPayload"],
				"initializationVector":      resp.Data["initializationVector"],
				"messageAuthenticationCode": resp.Data["messageAuthenticationCode"],
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt RSA - cipher RSA_PADDING_OAEP_WITH_SHA1 - %s", err.Error()))
		}
		if resp.Data["payload"] != "cGF5bG9hZA==" {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt RSA - wrong payload. Expected '%s' got '%s'", "cGF5bG9hZA==", resp.Data["payload"]))
		}

	})
	t.Run("Test Decrypt RSA - cipher RSA_PADDING_OAEP", func(t *testing.T) {
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/encrypt/test_rsa_2048",
			Data: map[string]interface{}{
				"cipherAlgorithm": "RSA_PADDING_OAEP",
				"payload":         "cGF5bG9hZA==",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on encrypt RSA - cipher RSA_PADDING_OAEP - %s", err.Error()))
		}
		resp, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/decrypt/test_rsa_2048",
			Data: map[string]interface{}{
				"cipherAlgorithm":           "RSA_PADDING_OAEP",
				"keyVersion":                "v1",
				"encryptedPayload":          resp.Data["encryptedPayload"],
				"initializationVector":      resp.Data["initializationVector"],
				"messageAuthenticationCode": resp.Data["messageAuthenticationCode"],
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt RSA - cipher RSA_PADDING_OAEP - %s", err.Error()))
		}
		if resp.Data["payload"] != "cGF5bG9hZA==" {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt RSA - wrong payload. Expected '%s' got '%s'", "cGF5bG9hZA==", resp.Data["payload"]))
		}
	})
	t.Run("Test Decrypt RSA - cipher RSA_PADDING_OAEP_WITH_SHA384", func(t *testing.T) {
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/encrypt/test_rsa_2048",
			Data: map[string]interface{}{
				"cipherAlgorithm": "RSA_PADDING_OAEP_WITH_SHA384",
				"payload":         "cGF5bG9hZA==",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on encrypt RSA - cipher RSA_PADDING_OAEP_WITH_SHA384 - %s", err.Error()))
		}
		resp, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/decrypt/test_rsa_2048",
			Data: map[string]interface{}{
				"cipherAlgorithm":           "RSA_PADDING_OAEP_WITH_SHA384",
				"keyVersion":                "v1",
				"encryptedPayload":          resp.Data["encryptedPayload"],
				"initializationVector":      resp.Data["initializationVector"],
				"messageAuthenticationCode": resp.Data["messageAuthenticationCode"],
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt RSA - cipher RSA_PADDING_OAEP_WITH_SHA384 - %s", err.Error()))
		}
		if resp.Data["payload"] != "cGF5bG9hZA==" {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt RSA - wrong payload. Expected '%s' got '%s'", "cGF5bG9hZA==", resp.Data["payload"]))
		}

	})
	t.Run("Test Decrypt RSA - cipher RSA_NO_PADDING", func(t *testing.T) {
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/encrypt/test_rsa_2048",
			Data: map[string]interface{}{
				"cipherAlgorithm": "RSA_NO_PADDING",
				"payload":         "cGF5bG9hZA==",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on encrypt RSA - cipher RSA_NO_PADDING - %s", err.Error()))
		}
		resp, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/decrypt/test_rsa_2048",
			Data: map[string]interface{}{
				"cipherAlgorithm":           "RSA_NO_PADDING",
				"keyVersion":                "v1",
				"encryptedPayload":          resp.Data["encryptedPayload"],
				"initializationVector":      resp.Data["initializationVector"],
				"messageAuthenticationCode": resp.Data["messageAuthenticationCode"],
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt RSA - cipher RSA_NO_PADDING - %s", err.Error()))
		}
		if resp.Data["payload"] != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcGF5bG9hZA==" {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt RSA - wrong payload. Expected '%s' got '%s'", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcGF5bG9hZA", resp.Data["payload"]))
		}
	})
	t.Run("Test Decrypt CHACHA20 - cipher CHACHA20_AEAD", func(t *testing.T) {
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/encrypt/test_chacha20",
			Data: map[string]interface{}{
				"cipherAlgorithm":              "CHACHA20_AEAD",
				"payload":                      "cGF5bG9hZA==",
				"additionalAuthenticationData": "QWRkaXRpb25hbCBBdXRoZW50aWNhdGlvbiBEYXRh",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on encrypt CHACHA20 - cipher CHACHA20_AEAD - %s", err.Error()))
		}
		resp, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/decrypt/test_chacha20",
			Data: map[string]interface{}{
				"cipherAlgorithm":              "CHACHA20_AEAD",
				"keyVersion":                   "v1",
				"encryptedPayload":             resp.Data["encryptedPayload"],
				"initializationVector":         resp.Data["initializationVector"],
				"messageAuthenticationCode":    resp.Data["messageAuthenticationCode"],
				"additionalAuthenticationData": "QWRkaXRpb25hbCBBdXRoZW50aWNhdGlvbiBEYXRh",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt CHACHA20 - cipher CHACHA20_AEAD - %s", err.Error()))
		}
		if resp.Data["payload"] != "cGF5bG9hZA==" {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt CHACHA20 - wrong payload. Expected '%s' got '%s'", "cGF5bG9hZA==", resp.Data["payload"]))
		}
	})
	t.Run("Test Decrypt CHACHA20 - cipher CHACHA20", func(t *testing.T) {
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/encrypt/test_chacha20",
			Data: map[string]interface{}{
				"cipherAlgorithm": "CHACHA20",
				"payload":         "cGF5bG9hZA==",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on encrypt CHACHA20 - cipher CHACHA20 - %s", err.Error()))
		}
		resp, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/decrypt/test_chacha20",
			Data: map[string]interface{}{
				"cipherAlgorithm":           "CHACHA20",
				"keyVersion":                "v1",
				"encryptedPayload":          resp.Data["encryptedPayload"],
				"initializationVector":      resp.Data["initializationVector"],
				"messageAuthenticationCode": resp.Data["messageAuthenticationCode"],
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt CHACHA20 - cipher CHACHA20 - %s", err.Error()))
		}
		if resp.Data["payload"] != "cGF5bG9hZA==" {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt CHACHA20 - wrong payload. Expected '%s' got '%s'", "cGF5bG9hZA==", resp.Data["payload"]))
		}

	})
	t.Run("Test Decrypt CHACHA20 - wrong CHACHA20 cipher algorithm", func(t *testing.T) {

		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/decrypt/test_chacha20",
			Data: map[string]interface{}{
				"cipherAlgorithm":      "CHACHA20_TEST",
				"keyVersion":           "v1",
				"encryptedPayload":     "ELfKnNiGDj3cI74XYSLQEA==",
				"initializationVector": "waDAws/4fsRjf420RVq5Hg==",
			},
			Storage: testEnv.Storage,
		})
		assert.Error(t, err)

	})
	t.Run("Test Decrypt CAMELLIA - cipher CAMELLIA", func(t *testing.T) {
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/encrypt/test_camellia",
			Data: map[string]interface{}{
				"cipherAlgorithm": "CAMELLIA",
				"payload":         "cGF5bG9hZA==",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on encrypt CAMELLIA - cipher CAMELLIA - %s", err.Error()))
		}
		resp, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/decrypt/test_camellia",
			Data: map[string]interface{}{
				"cipherAlgorithm":           "CAMELLIA",
				"keyVersion":                "v1",
				"encryptedPayload":          resp.Data["encryptedPayload"],
				"initializationVector":      resp.Data["initializationVector"],
				"messageAuthenticationCode": resp.Data["messageAuthenticationCode"],
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt CAMELLIA - cipher CAMELLIA - %s", err.Error()))
		}
		if resp.Data["payload"] != "cGF5bG9hZA==" {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt CAMELLIA - wrong payload. Expected '%s' got '%s'", "cGF5bG9hZA==", resp.Data["payload"]))
		}
	})
	t.Run("Test Decrypt CAMELLIA - cipher CAMELLIA_CBC_NO_PADDING", func(t *testing.T) {
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/encrypt/test_camellia",
			Data: map[string]interface{}{
				"cipherAlgorithm": "CAMELLIA_CBC_NO_PADDING",
				"payload":         "cGF5bG9hZA==",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on encrypt CAMELLIA - cipher CAMELLIA_CBC_NO_PADDING - %s", err.Error()))
		}
		resp, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/decrypt/test_camellia",
			Data: map[string]interface{}{
				"cipherAlgorithm":           "CAMELLIA_CBC_NO_PADDING",
				"keyVersion":                "v1",
				"encryptedPayload":          resp.Data["encryptedPayload"],
				"initializationVector":      resp.Data["initializationVector"],
				"messageAuthenticationCode": resp.Data["messageAuthenticationCode"],
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt CAMELLIA - cipher CAMELLIA_CBC_NO_PADDING - %s", err.Error()))
		}
		if resp.Data["payload"] != "cGF5bG9hZA==" {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt CAMELLIA - wrong payload. Expected '%s' got '%s'", "cGF5bG9hZA==", resp.Data["payload"]))
		}
	})
	t.Run("Test Decrypt CAMELLIA - cipher CAMELLIA_ECB", func(t *testing.T) {
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/encrypt/test_camellia",
			Data: map[string]interface{}{
				"cipherAlgorithm": "CAMELLIA_ECB",
				"payload":         "cGF5bG9hZA==",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on encrypt CAMELLIA - cipher CAMELLIA_ECB - %s", err.Error()))
		}
		resp, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/decrypt/test_camellia",
			Data: map[string]interface{}{
				"cipherAlgorithm":           "CAMELLIA_ECB",
				"keyVersion":                "v1",
				"encryptedPayload":          resp.Data["encryptedPayload"],
				"initializationVector":      resp.Data["initializationVector"],
				"messageAuthenticationCode": resp.Data["messageAuthenticationCode"],
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt CAMELLIA - cipher CAMELLIA_ECB - %s", err.Error()))
		}
		if resp.Data["payload"] != "cGF5bG9hZA==" {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt CAMELLIA - wrong payload. Expected '%s' got '%s'", "cGF5bG9hZA==", resp.Data["payload"]))
		}

	})
	t.Run("Test Decrypt CAMELLIA - wrong CAMELLIA cipher algorithm", func(t *testing.T) {

		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/decrypt/test_camellia",
			Data: map[string]interface{}{
				"cipherAlgorithm":      "CHACHA20",
				"keyVersion":           "v1",
				"encryptedPayload":     "ELfKnNiGDj3cI74XYSLQEA==",
				"initializationVector": "waDAws/4fsRjf420RVq5Hg==",
			},
			Storage: testEnv.Storage,
		})
		assert.Error(t, err)

	})
	t.Run("Test Decrypt TDEA - cipher TDEA_CBC", func(t *testing.T) {
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/encrypt/test_tdea",
			Data: map[string]interface{}{
				"cipherAlgorithm": "TDEA_CBC",
				"payload":         "cGF5bG9hZA==",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on encrypt CAMELLIA - cipher CAMELLIA_ECB - %s", err.Error()))
		}
		resp, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/decrypt/test_tdea",
			Data: map[string]interface{}{
				"cipherAlgorithm":           "TDEA_CBC",
				"keyVersion":                "v1",
				"encryptedPayload":          resp.Data["encryptedPayload"],
				"initializationVector":      resp.Data["initializationVector"],
				"messageAuthenticationCode": resp.Data["messageAuthenticationCode"],
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt TDEA - cipher TDEA_CBC - %s", err.Error()))
		}
		if resp.Data["payload"] != "cGF5bG9hZA==" {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt TDEA - wrong payload. Expected '%s' got '%s'", "cGF5bG9hZA==", resp.Data["payload"]))
		}

	})
	t.Run("Test Decrypt TDEA - cipher TDEA_CBC_NO_PADDING", func(t *testing.T) {
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/encrypt/test_tdea",
			Data: map[string]interface{}{
				"cipherAlgorithm": "TDEA_CBC_NO_PADDING",
				"payload":         "cGF5bG9hZA==",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on encrypt CAMELLIA - cipher CAMELLIA_ECB - %s", err.Error()))
		}
		resp, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/decrypt/test_tdea",
			Data: map[string]interface{}{
				"cipherAlgorithm":           "TDEA_CBC_NO_PADDING",
				"keyVersion":                "v1",
				"encryptedPayload":          resp.Data["encryptedPayload"],
				"initializationVector":      resp.Data["initializationVector"],
				"messageAuthenticationCode": resp.Data["messageAuthenticationCode"],
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt TDEA - cipher TDEA_CBC_NO_PADDING - %s", err.Error()))
		}
		if resp.Data["payload"] != "cGF5bG9hZA==" {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt TDEA - wrong payload. Expected '%s' got '%s'", "cGF5bG9hZA==", resp.Data["payload"]))
		}

	})
	t.Run("Test Decrypt TDEA - cipher TDEA_ECB", func(t *testing.T) {
		resp, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/encrypt/test_tdea",
			Data: map[string]interface{}{
				"cipherAlgorithm": "TDEA_ECB",
				"payload":         "cGF5bG9hZA==",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on encrypt CAMELLIA - cipher CAMELLIA_ECB - %s", err.Error()))
		}
		resp, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/decrypt/test_tdea",
			Data: map[string]interface{}{
				"cipherAlgorithm":           "TDEA_ECB",
				"keyVersion":                "v1",
				"encryptedPayload":          resp.Data["encryptedPayload"],
				"initializationVector":      resp.Data["initializationVector"],
				"messageAuthenticationCode": resp.Data["messageAuthenticationCode"],
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt TDEA - cipher TDEA_ECB - %s", err.Error()))
		}
		if resp.Data["payload"] != "cGF5bG9hZA==" {
			assert.FailNow(t, fmt.Sprintf("Error on decrypt TDEA - wrong payload. Expected '%s' got '%s'", "cGF5bG9hZA==", resp.Data["payload"]))
		}
	})
	t.Run("Test Decrypt TDEA - wrong TDEA cipher algorithm", func(t *testing.T) {

		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/decrypt/test_tdea",
			Data: map[string]interface{}{
				"cipherAlgorithm":      "AES",
				"keyVersion":           "v1",
				"encryptedPayload":     "ELfKnNiGDj3cI74XYSLQEA==",
				"initializationVector": "waDAws/4fsRjf420RVq5Hg==",
			},
			Storage: testEnv.Storage,
		})
		assert.Error(t, err)

	})
}
