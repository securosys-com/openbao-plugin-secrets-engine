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
	"github.com/stretchr/testify/require"
)

func TestOperationsSign(t *testing.T) {
	testEnv := getSharedTestEnv(t)
	var err error
	t.Run("Test Sign EC - signature NONE_WITH_ECDSA", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/sign/test_ec_secp256k1",
			Data: map[string]interface{}{
				"payloadType":        "UNSPECIFIED",
				"payload":            "cGF5bG9hZA==",
				"signatureAlgorithm": "NONE_WITH_ECDSA",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on sign EC - signature NONE_WITH_ECDSA - %s", err.Error()))
		}
	})
	t.Run("Test Sign EC - signature SHA1_WITH_ECDSA", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/sign/test_ec_secp256k1",
			Data: map[string]interface{}{
				"payloadType":        "UNSPECIFIED",
				"payload":            "cGF5bG9hZA==",
				"signatureAlgorithm": "SHA1_WITH_ECDSA",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on sign EC - signature SHA1_WITH_ECDSA - %s", err.Error()))
		}
	})
	t.Run("Test Sign EC - signature SHA224_WITH_ECDSA", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/sign/test_ec_secp256k1",
			Data: map[string]interface{}{
				"payloadType":        "UNSPECIFIED",
				"payload":            "cGF5bG9hZA==",
				"signatureAlgorithm": "SHA224_WITH_ECDSA",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on sign EC - signature SHA224_WITH_ECDSA - %s", err.Error()))
		}
	})
	t.Run("Test Sign EC - signature SHA256_WITH_ECDSA", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/sign/test_ec_secp256k1",
			Data: map[string]interface{}{
				"payloadType":        "UNSPECIFIED",
				"payload":            "cGF5bG9hZA==",
				"signatureAlgorithm": "SHA256_WITH_ECDSA",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on sign EC - signature SHA256_WITH_ECDSA - %s", err.Error()))
		}
	})
	t.Run("Test Sign EC - signature SHA384_WITH_ECDSA", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/sign/test_ec_secp256k1",
			Data: map[string]interface{}{
				"payloadType":        "UNSPECIFIED",
				"payload":            "cGF5bG9hZA==",
				"signatureAlgorithm": "SHA384_WITH_ECDSA",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on sign EC - signature SHA384_WITH_ECDSA - %s", err.Error()))
		}
	})
	t.Run("Test Sign EC - signature SHA512_WITH_ECDSA", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/sign/test_ec_secp256k1",
			Data: map[string]interface{}{
				"payloadType":        "UNSPECIFIED",
				"payload":            "cGF5bG9hZA==",
				"signatureAlgorithm": "SHA512_WITH_ECDSA",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on sign EC - signature SHA512_WITH_ECDSA - %s", err.Error()))
		}
	})
	t.Run("Test Sign EC - signature SHA3224_WITH_ECDSA", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/sign/test_ec_secp256k1",
			Data: map[string]interface{}{
				"payloadType":        "UNSPECIFIED",
				"payload":            "cGF5bG9hZA==",
				"signatureAlgorithm": "SHA3224_WITH_ECDSA",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on sign EC - signature SHA3224_WITH_ECDSA - %s", err.Error()))
		}
	})
	t.Run("Test Sign EC - signature SHA3256_WITH_ECDSA", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/sign/test_ec_secp256k1",
			Data: map[string]interface{}{
				"payloadType":        "UNSPECIFIED",
				"payload":            "cGF5bG9hZA==",
				"signatureAlgorithm": "SHA3256_WITH_ECDSA",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on sign EC - signature SHA3256_WITH_ECDSA - %s", err.Error()))
		}
	})
	t.Run("Test Sign EC - signature SHA3384_WITH_ECDSA", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/sign/test_ec_secp256k1",
			Data: map[string]interface{}{
				"payloadType":        "UNSPECIFIED",
				"payload":            "cGF5bG9hZA==",
				"signatureAlgorithm": "SHA3384_WITH_ECDSA",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on sign EC - signature SHA3384_WITH_ECDSA - %s", err.Error()))
		}
	})
	t.Run("Test Sign EC - signature SHA3512_WITH_ECDSA", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/sign/test_ec_secp256k1",
			Data: map[string]interface{}{
				"payloadType":        "UNSPECIFIED",
				"payload":            "cGF5bG9hZA==",
				"signatureAlgorithm": "SHA3512_WITH_ECDSA",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on sign EC - signature SHA3512_WITH_ECDSA - %s", err.Error()))
		}
	})
	t.Run("Test Sign EC - signature KECCAK224_WITH_ECDSA", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/sign/test_ec_secp256k1",
			Data: map[string]interface{}{
				"payloadType":        "UNSPECIFIED",
				"payload":            "cGF5bG9hZA==",
				"signatureAlgorithm": "KECCAK224_WITH_ECDSA",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on sign EC - signature KECCAK224_WITH_ECDSA - %s", err.Error()))
		}
	})
	t.Run("Test Sign EC - signature KECCAK256_WITH_ECDSA", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/sign/test_ec_secp256k1",
			Data: map[string]interface{}{
				"payloadType":        "UNSPECIFIED",
				"payload":            "cGF5bG9hZA==",
				"signatureAlgorithm": "KECCAK256_WITH_ECDSA",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on sign EC - signature KECCAK256_WITH_ECDSA - %s", err.Error()))
		}
	})
	t.Run("Test Sign EC - signature KECCAK384_WITH_ECDSA", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/sign/test_ec_secp256k1",
			Data: map[string]interface{}{
				"payloadType":        "UNSPECIFIED",
				"payload":            "cGF5bG9hZA==",
				"signatureAlgorithm": "KECCAK384_WITH_ECDSA",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on sign EC - signature KECCAK384_WITH_ECDSA - %s", err.Error()))
		}
	})
	t.Run("Test Sign EC - signature KECCAK512_WITH_ECDSA", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/sign/test_ec_secp256k1",
			Data: map[string]interface{}{
				"payloadType":        "UNSPECIFIED",
				"payload":            "cGF5bG9hZA==",
				"signatureAlgorithm": "KECCAK512_WITH_ECDSA",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on sign EC - signature KECCAK512_WITH_ECDSA - %s", err.Error()))
		}
	})
	t.Run("Test Sign ED - signature EDDSA", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/sign/test_ed_ed25519",
			Data: map[string]interface{}{
				"payloadType":        "UNSPECIFIED",
				"payload":            "cGF5bG9hZA==",
				"signatureAlgorithm": "EDDSA",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on sign ED - signature EDDSA - %s", err.Error()))
		}
	})
	t.Run("Test Sign RSA - signature SHA224_WITH_RSA_PSS", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/sign/test_rsa_2048",
			Data: map[string]interface{}{
				"payloadType":        "UNSPECIFIED",
				"payload":            "cGF5bG9hZA==",
				"signatureAlgorithm": "SHA224_WITH_RSA_PSS",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on sign RSA - signature SHA224_WITH_RSA_PSS - %s", err.Error()))
		}
	})
	t.Run("Test Sign RSA - signature SHA256_WITH_RSA_PSS", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/sign/test_rsa_2048",
			Data: map[string]interface{}{
				"payloadType":        "UNSPECIFIED",
				"payload":            "cGF5bG9hZA==",
				"signatureAlgorithm": "SHA256_WITH_RSA_PSS",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on sign RSA - signature SHA256_WITH_RSA_PSS - %s", err.Error()))
		}
	})
	t.Run("Test Sign RSA - signature SHA384_WITH_RSA_PSS", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/sign/test_rsa_2048",
			Data: map[string]interface{}{
				"payloadType":        "UNSPECIFIED",
				"payload":            "cGF5bG9hZA==",
				"signatureAlgorithm": "SHA384_WITH_RSA_PSS",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on sign RSA - signature SHA384_WITH_RSA_PSS - %s", err.Error()))
		}
	})
	t.Run("Test Sign RSA - signature SHA512_WITH_RSA_PSS", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/sign/test_rsa_2048",
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
	})
	t.Run("Test Sign RSA - signature NONE_WITH_RSA", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/sign/test_rsa_2048",
			Data: map[string]interface{}{
				"payloadType":        "UNSPECIFIED",
				"payload":            "cGF5bG9hZA==",
				"signatureAlgorithm": "NONE_WITH_RSA",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on sign RSA - signature NONE_WITH_RSA - %s", err.Error()))
		}
	})
	t.Run("Test Sign RSA - signature SHA224_WITH_RSA", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/sign/test_rsa_2048",
			Data: map[string]interface{}{
				"payloadType":        "UNSPECIFIED",
				"payload":            "cGF5bG9hZA==",
				"signatureAlgorithm": "SHA224_WITH_RSA",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on sign RSA - signature SHA224_WITH_RSA - %s", err.Error()))
		}
	})
	t.Run("Test Sign RSA - rotate key - signature SHA224_WITH_RSA", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/type_rsa_2048/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/sign/type_rsa_2048",
			Data: map[string]interface{}{
				"payloadType":        "UNSPECIFIED",
				"payload":            "cGF5bG9hZA==",
				"signatureAlgorithm": "SHA224_WITH_RSA",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on sign RSA - signature SHA224_WITH_RSA - %s", err.Error()))
		}
	})
	t.Run("Test Sign RSA - signature SHA256_WITH_RSA", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/sign/test_rsa_2048",
			Data: map[string]interface{}{
				"payloadType":        "UNSPECIFIED",
				"payload":            "cGF5bG9hZA==",
				"signatureAlgorithm": "SHA256_WITH_RSA",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on sign RSA - signature SHA256_WITH_RSA - %s", err.Error()))
		}
	})
	t.Run("Test Sign RSA - signature SHA384_WITH_RSA", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/sign/test_rsa_2048",
			Data: map[string]interface{}{
				"payloadType":        "UNSPECIFIED",
				"payload":            "cGF5bG9hZA==",
				"signatureAlgorithm": "SHA384_WITH_RSA",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on sign RSA - signature SHA384_WITH_RSA - %s", err.Error()))
		}
	})
	t.Run("Test Sign RSA - signature SHA512_WITH_RSA", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/sign/test_rsa_2048",
			Data: map[string]interface{}{
				"payloadType":        "UNSPECIFIED",
				"payload":            "cGF5bG9hZA==",
				"signatureAlgorithm": "SHA512_WITH_RSA",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on sign RSA - signature SHA512_WITH_RSA - %s", err.Error()))
		}
	})
	// t.Run("Test Sign RSA - signature NONESHA224_WITH_RSA", func(t *testing.T) {
	// 	_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
	// 		Operation: logical.UpdateOperation,
	// 		Path:      "operation/sign/test_rsa_2048",
	// 		Data: map[string]interface{}{
	// 			"payloadType":        "UNSPECIFIED",
	// 			"payload":            "cGF5bG9hZA==",
	// 			"signatureAlgorithm": "NONESHA224_WITH_RSA",
	// 		},
	// 		Storage: testEnv.Storage,
	// 	})
	// 	if err != nil {
	// 		assert.FailNow(t, fmt.Sprintf("Error on sign RSA - signature NONESHA224_WITH_RSA - %s", err.Error()))
	// 	}
	// })
	// t.Run("Test Sign RSA - signature NONESHA256_WITH_RSA", func(t *testing.T) {
	// 	_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
	// 		Operation: logical.UpdateOperation,
	// 		Path:      "operation/sign/test_rsa_2048",
	// 		Data: map[string]interface{}{
	// 			"payloadType":        "UNSPECIFIED",
	// 			"payload":            "cGF5bG9hZA==",
	// 			"signatureAlgorithm": "NONESHA256_WITH_RSA",
	// 		},
	// 		Storage: testEnv.Storage,
	// 	})
	// 	if err != nil {
	// 		assert.FailNow(t, fmt.Sprintf("Error on sign RSA - signature NONESHA256_WITH_RSA - %s", err.Error()))
	// 	}
	// })
	// t.Run("Test Sign RSA - signature NONESHA384_WITH_RSA", func(t *testing.T) {
	// 	_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
	// 		Operation: logical.UpdateOperation,
	// 		Path:      "operation/sign/test_rsa_2048",
	// 		Data: map[string]interface{}{
	// 			"payloadType":        "UNSPECIFIED",
	// 			"payload":            "cGF5bG9hZA==",
	// 			"signatureAlgorithm": "NONESHA384_WITH_RSA",
	// 		},
	// 		Storage: testEnv.Storage,
	// 	})
	// 	if err != nil {
	// 		assert.FailNow(t, fmt.Sprintf("Error on sign RSA - signature NONESHA384_WITH_RSA - %s", err.Error()))
	// 	}
	// })
	// t.Run("Test Sign RSA - signature NONESHA512_WITH_RSA", func(t *testing.T) {
	// 	_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
	// 		Operation: logical.UpdateOperation,
	// 		Path:      "operation/sign/test_rsa_2048",
	// 		Data: map[string]interface{}{
	// 			"payloadType":        "UNSPECIFIED",
	// 			"payload":            "cGF5bG9hZA==",
	// 			"signatureAlgorithm": "NONESHA512_WITH_RSA",
	// 		},
	// 		Storage: testEnv.Storage,
	// 	})
	// 	if err != nil {
	// 		assert.FailNow(t, fmt.Sprintf("Error on sign RSA - signature NONESHA512_WITH_RSA - %s", err.Error()))
	// 	}
	// })
	t.Run("Test Sign RSA - signature SHA1_WITH_RSA", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/sign/test_rsa_2048",
			Data: map[string]interface{}{
				"payloadType":        "UNSPECIFIED",
				"payload":            "cGF5bG9hZA==",
				"signatureAlgorithm": "SHA1_WITH_RSA",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on sign RSA - signature SHA1_WITH_RSA - %s", err.Error()))
		}
	})
	// t.Run("Test Sign RSA - signature NONESHA1_WITH_RSA", func(t *testing.T) {
	// 	_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
	// 		Operation: logical.UpdateOperation,
	// 		Path:      "operation/sign/test_rsa_2048",
	// 		Data: map[string]interface{}{
	// 			"payloadType":        "UNSPECIFIED",
	// 			"payload":            "cGF5bG9hZA==",
	// 			"signatureAlgorithm": "NONESHA1_WITH_RSA",
	// 		},
	// 		Storage: testEnv.Storage,
	// 	})
	// 	if err != nil {
	// 		assert.FailNow(t, fmt.Sprintf("Error on sign RSA - signature NONESHA1_WITH_RSA - %s", err.Error()))
	// 	}
	// })
	t.Run("Test Sign RSA - signature SHA1_WITH_RSA_PSS", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/sign/test_rsa_2048",
			Data: map[string]interface{}{
				"payloadType":        "UNSPECIFIED",
				"payload":            "cGF5bG9hZA==",
				"signatureAlgorithm": "SHA1_WITH_RSA_PSS",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on sign RSA - signature SHA1_WITH_RSA_PSS - %s", err.Error()))
		}
	})
	t.Run("Test Sign DSA - signature NONE_WITH_DSA", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/sign/test_dsa_1024",
			Data: map[string]interface{}{
				"payloadType":        "UNSPECIFIED",
				"payload":            "cGF5bG9hZA==",
				"signatureAlgorithm": "NONE_WITH_DSA",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on sign DSA - signature NONE_WITH_DSA - %s", err.Error()))
		}
	})
	t.Run("Test Sign DSA - signature SHA224_WITH_DSA", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/sign/test_dsa_1024",
			Data: map[string]interface{}{
				"payloadType":        "UNSPECIFIED",
				"payload":            "cGF5bG9hZA==",
				"signatureAlgorithm": "SHA224_WITH_DSA",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on sign DSA - signature SHA224_WITH_DSA - %s", err.Error()))
		}
	})
	t.Run("Test Sign DSA - signature SHA256_WITH_DSA", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/sign/test_dsa_1024",
			Data: map[string]interface{}{
				"payloadType":        "UNSPECIFIED",
				"payload":            "cGF5bG9hZA==",
				"signatureAlgorithm": "SHA256_WITH_DSA",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on sign DSA - signature SHA256_WITH_DSA - %s", err.Error()))
		}
	})
	t.Run("Test Sign DSA - signature SHA384_WITH_DSA", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/sign/test_dsa_1024",
			Data: map[string]interface{}{
				"payloadType":        "UNSPECIFIED",
				"payload":            "cGF5bG9hZA==",
				"signatureAlgorithm": "SHA384_WITH_DSA",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on sign DSA - signature SHA384_WITH_DSA - %s", err.Error()))
		}
	})
	t.Run("Test Sign DSA - signature SHA512_WITH_DSA", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/sign/test_dsa_1024",
			Data: map[string]interface{}{
				"payloadType":        "UNSPECIFIED",
				"payload":            "cGF5bG9hZA==",
				"signatureAlgorithm": "SHA512_WITH_DSA",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on sign DSA - signature SHA512_WITH_DSA - %s", err.Error()))
		}
	})
	t.Run("Test Sign DSA - signature SHA1_WITH_DSA", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/sign/test_dsa_1024",
			Data: map[string]interface{}{
				"payloadType":        "UNSPECIFIED",
				"payload":            "cGF5bG9hZA==",
				"signatureAlgorithm": "SHA1_WITH_DSA",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on sign DSA - signature SHA1_WITH_DSA - %s", err.Error()))
		}
	})
	// t.Run("Test Sign ISS - signature ISS_KERL", func(t *testing.T) {
	// 	_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
	// 		Operation: logical.UpdateOperation,
	// 		Path:      "operation/sign/test_iss_1",
	// 		Data: map[string]interface{}{
	// 			"payloadType":        "UNSPECIFIED",
	// 			"payload":            "cGF5bG9hZA==",
	// 			"signatureAlgorithm": "ISS_KERL",
	// 		},
	// 		Storage: testEnv.Storage,
	// 	})
	// 	if err != nil {
	// 		assert.FailNow(t, fmt.Sprintf("Error on sign ISS - signature ISS_KERL - %s", err.Error()))
	// 	}
	// })
	t.Run("Test Sign BLS - signature BLS", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "operation/sign/test_bls",
			Data: map[string]interface{}{
				"payloadType":        "UNSPECIFIED",
				"payload":            "cGF5bG9hZA==",
				"signatureAlgorithm": "BLS",
			},
			Storage: testEnv.Storage,
		})
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Error on sign BLS - signature BLS - %s", err.Error()))
		}
	})
	t.Run("Test Sign PQC", func(t *testing.T) {
		keyNames := preparePQCSignatureTestKeys(t, testEnv.Backend, testEnv.Storage)

		for _, tc := range pqcSignatureCases() {
			tc := tc
			t.Run(safeTestName(tc.name), func(t *testing.T) {
				payload := payloadForPQCSignature(t, testEnv.Backend, testEnv.Storage, keyNames[tc.keyAlgorithm], tc.signatureAlgorithm)
				_, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
					Operation: logical.UpdateOperation,
					Path:      "operation/sign/" + keyNames[tc.keyAlgorithm],
					Data: map[string]interface{}{
						"payloadType":        "UNSPECIFIED",
						"payload":            payload,
						"signatureAlgorithm": tc.signatureAlgorithm,
					},
					Storage: testEnv.Storage,
				})
				require.NoError(t, err, "Error on sign PQC %s - signature %s", tc.keyAlgorithm, tc.signatureAlgorithm)
			})
		}
	})
}
