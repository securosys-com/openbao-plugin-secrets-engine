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
)

func TestRotateKeys(t *testing.T) {
	testEnv := getSharedTestEnv(t)
	var err error
	t.Run("Test Rotate Key - AES", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/test_aes_256/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {

			assert.FailNow(t, err.Error())
		}
		key, err := backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "test_aes_256")
		if err != nil {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Got error: %s", "test_aes_256", err.Error()))

		}
		if key.CurrentVersion != "v2" {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Expected key version 'v2' got '%s'", "test_aes_256", key.CurrentVersion))

		}
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/test_aes_256/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {

			assert.FailNow(t, err.Error())
		}
		key, err = backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "test_aes_256")
		if err != nil {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Got error: %s", "test_aes_256", err.Error()))

		}
		if key.CurrentVersion != "v3" {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Expected key version 'v3' got '%s'", "test_aes_256", key.CurrentVersion))

		}

	})
	t.Run("Test Rotate Key - BLS", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/test_bls/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {

			assert.FailNow(t, err.Error())
		}
		key, err := backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "test_bls")
		if err != nil {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Got error: %s", "test_bls", err.Error()))

		}
		if key.CurrentVersion != "v2" {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Expected key version 'v2' got '%s'", "test_bls", key.CurrentVersion))

		}
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/test_bls/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {

			assert.FailNow(t, err.Error())
		}
		key, err = backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "test_bls")
		if err != nil {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Got error: %s", "test_bls", err.Error()))

		}
		if key.CurrentVersion != "v3" {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Expected key version 'v3' got '%s'", "test_bls", key.CurrentVersion))

		}

	})
	t.Run("Test Rotate Key - CAMELLIA", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/test_camellia/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {

			assert.FailNow(t, err.Error())
		}
		key, err := backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "test_camellia")
		if err != nil {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Got error: %s", "test_camellia", err.Error()))

		}
		if key.CurrentVersion != "v2" {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Expected key version 'v2' got '%s'", "test_camellia", key.CurrentVersion))

		}
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/test_camellia/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {

			assert.FailNow(t, err.Error())
		}
		key, err = backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "test_camellia")
		if err != nil {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Got error: %s", "test_camellia", err.Error()))

		}
		if key.CurrentVersion != "v3" {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Expected key version 'v3' got '%s'", "test_camellia", key.CurrentVersion))

		}

	})
	t.Run("Test Rotate Key - CHACHA20", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/test_chacha20/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {

			assert.FailNow(t, err.Error())
		}
		key, err := backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "test_chacha20")
		if err != nil {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Got error: %s", "test_chacha20", err.Error()))

		}
		if key.CurrentVersion != "v2" {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Expected key version 'v2' got '%s'", "test_chacha20", key.CurrentVersion))

		}
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/test_chacha20/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {

			assert.FailNow(t, err.Error())
		}
		key, err = backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "test_chacha20")
		if err != nil {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Got error: %s", "test_chacha20", err.Error()))

		}
		if key.CurrentVersion != "v3" {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Expected key version 'v3' got '%s'", "test_chacha20", key.CurrentVersion))

		}

	})
	t.Run("Test Rotate Key - DSA", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/test_dsa_1024/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {

			assert.FailNow(t, err.Error())
		}
		key, err := backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "test_dsa_1024")
		if err != nil {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Got error: %s", "test_dsa_1024", err.Error()))

		}
		if key.CurrentVersion != "v2" {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Expected key version 'v2' got '%s'", "test_dsa_1024", key.CurrentVersion))

		}
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/test_dsa_1024/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {

			assert.FailNow(t, err.Error())
		}
		key, err = backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "test_dsa_1024")
		if err != nil {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Got error: %s", "test_dsa_1024", err.Error()))

		}
		if key.CurrentVersion != "v3" {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Expected key version 'v3' got '%s'", "test_dsa_1024", key.CurrentVersion))

		}

	})
	t.Run("Test Rotate Key - EC", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/test_ec_secp256k1/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {

			assert.FailNow(t, err.Error())
		}
		key, err := backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "test_ec_secp256k1")
		if err != nil {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Got error: %s", "test_ec_secp256k1", err.Error()))

		}
		if key.CurrentVersion != "v2" {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Expected key version 'v2' got '%s'", "test_ec_secp256k1", key.CurrentVersion))

		}
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/test_ec_secp256k1/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {

			assert.FailNow(t, err.Error())
		}
		key, err = backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "test_ec_secp256k1")
		if err != nil {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Got error: %s", "test_ec_secp256k1", err.Error()))

		}
		if key.CurrentVersion != "v3" {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Expected key version 'v3' got '%s'", "test_ec_secp256k1", key.CurrentVersion))

		}

	})
	t.Run("Test Rotate Key - ED", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/test_ed_ed25519/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {

			assert.FailNow(t, err.Error())
		}
		key, err := backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "test_ed_ed25519")
		if err != nil {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Got error: %s", "test_ed_ed25519", err.Error()))

		}
		if key.CurrentVersion != "v2" {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Expected key version 'v2' got '%s'", "test_ed_ed25519", key.CurrentVersion))

		}
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/test_ed_ed25519/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {

			assert.FailNow(t, err.Error())
		}
		key, err = backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "test_ed_ed25519")
		if err != nil {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Got error: %s", "test_ed_ed25519", err.Error()))

		}
		if key.CurrentVersion != "v3" {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Expected key version 'v3' got '%s'", "test_ed_ed25519", key.CurrentVersion))

		}

	})
	t.Run("Test Rotate Key - TDEA", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/test_tdea/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {

			assert.FailNow(t, err.Error())
		}
		key, err := backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "test_tdea")
		if err != nil {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Got error: %s", "test_tdea", err.Error()))

		}
		if key.CurrentVersion != "v2" {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Expected key version 'v2' got '%s'", "test_tdea", key.CurrentVersion))

		}
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/test_tdea/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {

			assert.FailNow(t, err.Error())
		}
		key, err = backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "test_tdea")
		if err != nil {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Got error: %s", "test_tdea", err.Error()))

		}
		if key.CurrentVersion != "v3" {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Expected key version 'v3' got '%s'", "test_tdea", key.CurrentVersion))

		}

	})
	t.Run("Test Rotate Key - RSA", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/test_rsa_2048/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {

			assert.FailNow(t, err.Error())
		}
		key, err := backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "test_rsa_2048")
		if err != nil {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Got error: %s", "test_rsa_2048", err.Error()))

		}
		if key.CurrentVersion != "v2" {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Expected key version 'v2' got '%s'", "test_rsa_2048", key.CurrentVersion))

		}
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/test_rsa_2048/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {

			assert.FailNow(t, err.Error())
		}
		key, err = backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "test_rsa_2048")
		if err != nil {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Got error: %s", "test_rsa_2048", err.Error()))

		}
		if key.CurrentVersion != "v3" {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Expected key version 'v3' got '%s'", "test_rsa_2048", key.CurrentVersion))

		}

	})
	t.Run("Test Rotate Key - RSA with Policy", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/test_rsa_2048_policy/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {

			assert.FailNow(t, err.Error())
		}
		key, err := backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "test_rsa_2048_policy")
		if err != nil {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Got error: %s", "test_rsa_2048_policy", err.Error()))

		}
		if key.CurrentVersion != "v2" {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Expected key version 'v2' got '%s'", "test_rsa_2048_policy", key.CurrentVersion))

		}
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/test_rsa_2048_policy/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {

			assert.FailNow(t, err.Error())
		}
		key, err = backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "test_rsa_2048_policy")
		if err != nil {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Got error: %s", "test_rsa_2048_policy", err.Error()))

		}
		if key.CurrentVersion != "v3" {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Expected key version 'v3' got '%s'", "test_rsa_2048_policy", key.CurrentVersion))

		}

	})
	t.Run("Test Rotate Key - OPENBAO AES256-GCM96", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/type_aes/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {

			assert.FailNow(t, err.Error())
		}
		key, err := backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "type_aes")
		if err != nil {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Got error: %s", "type_aes", err.Error()))

		}
		if key.CurrentVersion != "v2" {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Expected key version 'v2' got '%s'", "type_aes", key.CurrentVersion))

		}
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/type_aes/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {

			assert.FailNow(t, err.Error())
		}
		key, err = backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "type_aes")
		if err != nil {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Got error: %s", "type_aes", err.Error()))

		}
		if key.CurrentVersion != "v3" {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Expected key version 'v3' got '%s'", "type_aes", key.CurrentVersion))

		}

	})
	t.Run("Test Rotate Key - OPENBAO RSA-2048", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/type_rsa_2048/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {

			assert.FailNow(t, err.Error())
		}
		key, err := backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "type_rsa_2048")
		if err != nil {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Got error: %s", "type_rsa_2048", err.Error()))

		}
		if key.CurrentVersion != "v2" {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Expected key version 'v2' got '%s'", "type_rsa_2048", key.CurrentVersion))

		}
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/type_rsa_2048/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {

			assert.FailNow(t, err.Error())
		}
		key, err = backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "type_rsa_2048")
		if err != nil {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Got error: %s", "type_rsa_2048", err.Error()))

		}
		if key.CurrentVersion != "v3" {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Expected key version 'v3' got '%s'", "type_rsa_2048", key.CurrentVersion))

		}

	})
	t.Run("Test Rotate Key - OPENBAO RSA-3072", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/type_rsa_3072/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {

			assert.FailNow(t, err.Error())
		}
		key, err := backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "type_rsa_3072")
		if err != nil {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Got error: %s", "type_rsa_3072", err.Error()))

		}
		if key.CurrentVersion != "v2" {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Expected key version 'v2' got '%s'", "type_rsa_3072", key.CurrentVersion))

		}
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/type_rsa_3072/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {

			assert.FailNow(t, err.Error())
		}
		key, err = backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "type_rsa_3072")
		if err != nil {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Got error: %s", "type_rsa_3072", err.Error()))

		}
		if key.CurrentVersion != "v3" {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Expected key version 'v3' got '%s'", "type_rsa_3072", key.CurrentVersion))

		}

	})
	t.Run("Test Rotate Key - OPENBAO RSA-4096", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/type_rsa_4096/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {

			assert.FailNow(t, err.Error())
		}
		key, err := backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "type_rsa_4096")
		if err != nil {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Got error: %s", "type_rsa_4096", err.Error()))

		}
		if key.CurrentVersion != "v2" {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Expected key version 'v2' got '%s'", "type_rsa_4096", key.CurrentVersion))

		}
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/type_rsa_4096/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {

			assert.FailNow(t, err.Error())
		}
		key, err = backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "type_rsa_4096")
		if err != nil {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Got error: %s", "type_rsa_4096", err.Error()))

		}
		if key.CurrentVersion != "v3" {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Expected key version 'v3' got '%s'", "type_rsa_4096", key.CurrentVersion))

		}

	})
	t.Run("Test Rotate Key - OPENBAO ECDSA-P256", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/type_ec_p256/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {
			assert.FailNow(t, err.Error())
		}
		key, err := backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "type_ec_p256")
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Got error: %s", "type_ec_p256", err.Error()))

		}
		if key.CurrentVersion != "v2" {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Expected key version 'v2' got '%s'", "type_ec_p256", key.CurrentVersion))

		}
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/type_ec_p256/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {
			assert.FailNow(t, err.Error())
		}
		key, err = backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "type_ec_p256")
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Got error: %s", "type_ec_p256", err.Error()))

		}
		if key.CurrentVersion != "v3" {
			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Expected key version 'v3' got '%s'", "type_ec_p256", key.CurrentVersion))
		}

	})
	t.Run("Test Rotate Key - OPENBAO ECDSA-P384", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/type_ec_p384/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {

			assert.FailNow(t, err.Error())
		}
		key, err := backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "type_ec_p384")
		if err != nil {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Got error: %s", "type_ec_p384", err.Error()))

		}
		if key.CurrentVersion != "v2" {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Expected key version 'v2' got '%s'", "type_ec_p384", key.CurrentVersion))

		}
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/type_ec_p384/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {

			assert.FailNow(t, err.Error())
		}
		key, err = backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "type_ec_p384")
		if err != nil {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Got error: %s", "type_ec_p384", err.Error()))

		}
		if key.CurrentVersion != "v3" {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Expected key version 'v3' got '%s'", "type_ec_p384", key.CurrentVersion))

		}

	})
	t.Run("Test Rotate Key - OPENBAO ECDSA-P521", func(t *testing.T) {
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/type_ec_p521/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {

			assert.FailNow(t, err.Error())
		}
		key, err := backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "type_ec_p521")
		if err != nil {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Got error: %s", "type_ec_p521", err.Error()))

		}
		if key.CurrentVersion != "v2" {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Expected key version 'v2' got '%s'", "type_ec_p521", key.CurrentVersion))

		}
		_, err = testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "keys/type_ec_p521/rotate",
			Data:      map[string]interface{}{},
			Storage:   testEnv.Storage,
		})

		if err != nil {

			assert.FailNow(t, err.Error())
		}
		key, err = backend.Backend(&testEnv.Conf).GetKey(context.Background(), testEnv.Storage, "type_ec_p521")
		if err != nil {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Got error: %s", "type_ec_p521", err.Error()))

		}
		if key.CurrentVersion != "v3" {

			assert.FailNow(t, fmt.Sprintf("Rotate not working for the %s key. Expected key version 'v3' got '%s'", "type_ec_p521", key.CurrentVersion))

		}

	})
}
