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

func TestOperationsWrap(t *testing.T) {
	testEnv := getSharedTestEnv(t)
	var err error
	t.Run("Test Wrap AES - wrap method AES_WRAP", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/wrap/test_aes_128/test_aes_256",
			Data: map[string]interface{}{
				"wrapMethod": "AES_WRAP",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on wrap AES - wrap method AES_WRAP - %s", err.Error()))
		}
	})
	t.Run("Test Wrap AES - wrap method AES_WRAP_DSA", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/wrap/test_dsa_1024/test_aes_256",
			Data: map[string]interface{}{
				"wrapMethod": "AES_WRAP_DSA",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on wrap AES - wrap method AES_WRAP_DSA - %s", err.Error()))
		}
	})
	t.Run("Test Wrap AES - wrap method AES_WRAP_EC", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/wrap/test_ec_secp256k1/test_aes_256",
			Data: map[string]interface{}{
				"wrapMethod": "AES_WRAP_EC",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on wrap AES - wrap method AES_WRAP_EC - %s", err.Error()))
		}
	})
	t.Run("Test Wrap AES - wrap method AES_WRAP_ED", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/wrap/test_ed_ed25519/test_aes_256",
			Data: map[string]interface{}{
				"wrapMethod": "AES_WRAP_ED",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on wrap AES - wrap method AES_WRAP_ED - %s", err.Error()))
		}
	})
	t.Run("Test Wrap AES - wrap method AES_WRAP_RSA", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/wrap/test_rsa_2048/test_aes_256",
			Data: map[string]interface{}{
				"wrapMethod": "AES_WRAP_RSA",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on wrap AES - wrap method AES_WRAP_RSA - %s", err.Error()))
		}
	})
	t.Run("Test Wrap AES - wrap method AES_WRAP_BLS", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/wrap/test_bls/test_aes_256",
			Data: map[string]interface{}{
				"wrapMethod": "AES_WRAP_BLS",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on wrap AES - wrap method AES_WRAP_BLS - %s", err.Error()))
		}
	})
	t.Run("Test Wrap AES - wrap method AES_WRAP_PAD", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/wrap/test_aes_128/test_aes_256",
			Data: map[string]interface{}{
				"wrapMethod": "AES_WRAP_PAD",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on wrap AES - wrap method AES_WRAP_PAD - %s", err.Error()))
		}
	})
	t.Run("Test Wrap AES - wrap method AES_WRAP_PAD_DSA", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/wrap/test_dsa_1024/test_aes_256",
			Data: map[string]interface{}{
				"wrapMethod": "AES_WRAP_PAD_DSA",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on wrap AES - wrap method AES_WRAP_PAD_DSA - %s", err.Error()))
		}
	})
	t.Run("Test Wrap AES - wrap method AES_WRAP_PAD_EC", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/wrap/test_ec_secp256k1/test_aes_256",
			Data: map[string]interface{}{
				"wrapMethod": "AES_WRAP_PAD_EC",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on wrap AES - wrap method AES_WRAP_PAD_EC - %s", err.Error()))
		}
	})
	t.Run("Test Wrap AES - wrap method AES_WRAP_PAD_ED", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/wrap/test_ed_ed25519/test_aes_256",
			Data: map[string]interface{}{
				"wrapMethod": "AES_WRAP_PAD_ED",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on wrap AES - wrap method AES_WRAP_PAD_ED - %s", err.Error()))
		}
	})
	t.Run("Test Wrap AES - wrap method AES_WRAP_PAD_RSA", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/wrap/test_rsa_2048/test_aes_256",
			Data: map[string]interface{}{
				"wrapMethod": "AES_WRAP_PAD_RSA",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on wrap AES - wrap method AES_WRAP_PAD_RSA - %s", err.Error()))
		}
	})
	t.Run("Test Wrap AES - wrap method AES_WRAP_PAD_BLS", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/wrap/test_bls/test_aes_256",
			Data: map[string]interface{}{
				"wrapMethod": "AES_WRAP_PAD_BLS",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on wrap AES - wrap method AES_WRAP_PAD_BLS - %s", err.Error()))
		}
	})
	t.Run("Test Wrap RSA - wrap method RSA_WRAP_PAD", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/wrap/test_aes_128/test_rsa_2048",
			Data: map[string]interface{}{
				"wrapMethod": "RSA_WRAP_PAD",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on wrap RSA - wrap method RSA_WRAP_PAD - %s", err.Error()))
		}
	})
	t.Run("Test Wrap RSA - rotate key - wrap method RSA_WRAP_PAD", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/type_rsa_2048/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/wrap/test_aes_128/type_rsa_2048",
			Data: map[string]interface{}{
				"wrapMethod": "RSA_WRAP_PAD",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on wrap RSA - wrap method RSA_WRAP_PAD - %s", err.Error()))
		}
	})
	t.Run("Test Wrap RSA - wrap method RSA_WRAP_OAEP", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/wrap/test_aes_128/test_rsa_2048",
			Data: map[string]interface{}{
				"wrapMethod": "RSA_WRAP_OAEP",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on wrap RSA - wrap method RSA_WRAP_OAEP - %s", err.Error()))
		}
	})
}
