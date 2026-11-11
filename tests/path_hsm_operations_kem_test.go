// SPDX-FileCopyrightText: Copyright 2026 Securosys SA
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
	securosysBackend "securosys.ch/backend"
	helpers "securosys.ch/helpers"
	testHelpers "securosys.ch/test-helpers"
)

func TestMLKEMEncapsulateAndDecapsulate(t *testing.T) {
	testHelpers.RequireTSBConfig(t)

	testEnv, err := testHelpers.NewTestEnv()
	require.NoError(t, err)
	require.NoError(t, testEnv.AddConfigRaw())

	for _, algorithm := range []string{"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"} {
		algorithm := algorithm
		t.Run(algorithm, func(t *testing.T) {
			timestamp := time.Now().UTC().Format("2006-01-02T15:04:05Z")
			keyName := "kem_" + safeKeyName(algorithm)
			keyLabel := "TEST_SECUROSYS_SECRETS_ENGINE_KEM_" + strings.ToUpper(safeKeyName(algorithm)) + "_" + timestamp

			t.Cleanup(func() {
				_ = testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, keyName)
			})

			createResponse, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "keys/ml-kem/" + keyName,
				Data: map[string]interface{}{
					"algorithm":  algorithm,
					"keyLabel":   keyLabel,
					"attributes": pqcWrapAttributes,
				},
				Storage: testEnv.Storage,
			})
			require.NoError(t, err)
			require.False(t, createResponse.IsError(), "create ML-KEM response: %v", createResponse)
			require.Equal(t, algorithm, createResponse.Data["algorithm"])

			encapsulation, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "operation/encapsulate/" + keyName,
				Storage:   testEnv.Storage,
			})
			require.NoError(t, err)
			require.NotNil(t, encapsulation)
			require.False(t, encapsulation.IsError(), "encapsulation response: %v", encapsulation)
			require.NotEmpty(t, encapsulation.Data["sharedSecret"])
			require.NotEmpty(t, encapsulation.Data["ciphertext"])
			require.Equal(t, "v1", encapsulation.Data["keyVersion"])

			decapsulation, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "operation/decapsulate/" + keyName,
				Data: map[string]interface{}{
					"ciphertext": encapsulation.Data["ciphertext"],
				},
				Storage: testEnv.Storage,
			})
			require.NoError(t, err)
			require.NotNil(t, decapsulation)
			require.False(t, decapsulation.IsError(), "decapsulation response: %v", decapsulation)
			require.Equal(t, encapsulation.Data["sharedSecret"], decapsulation.Data["sharedSecret"])
			require.Equal(t, "v1", decapsulation.Data["keyVersion"])

			require.NoError(t, testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, keyName))
		})
	}
}

func TestMLKEMCreationRejectsNonKEMAlgorithm(t *testing.T) {
	testEnv, err := testHelpers.NewTestEnv()
	require.NoError(t, err)

	response, err := testEnv.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "keys/ml-kem/not_a_kem",
		Data: map[string]interface{}{
			"algorithm":  "ML-DSA-44",
			"keyLabel":   "unused",
			"attributes": pqcSignAttributes,
		},
		Storage: testEnv.Storage,
	})
	require.NoError(t, err)
	require.True(t, response.IsError())
	require.Contains(t, fmt.Sprint(response.Data["error"]), "ML-KEM key algorithm")
}

func TestKEMOperationsRejectNonKEMKey(t *testing.T) {
	testEnv, err := testHelpers.NewTestEnv()
	require.NoError(t, err)

	key := &helpers.KeyEntry{
		BaseLabel:      "ml_dsa_key",
		Algorithm:      "ML-DSA-44",
		Attributes:     map[string]bool{"sign": true},
		CurrentVersion: "v1",
		Versions: map[string]helpers.KeyVersion{
			"v1": {KeyLabel: "ml_dsa_key_v1", PublicKey: "unused", Version: "v1"},
		},
	}
	require.NoError(t, securosysBackend.SetKey(context.Background(), testEnv.Storage, "ml_dsa_key", key))

	for _, request := range []*logical.Request{
		{
			Operation: logical.UpdateOperation,
			Path:      "operation/encapsulate/ml_dsa_key",
			Storage:   testEnv.Storage,
		},
		{
			Operation: logical.UpdateOperation,
			Path:      "operation/decapsulate/ml_dsa_key",
			Data:      map[string]interface{}{"ciphertext": "Y2lwaGVydGV4dA=="},
			Storage:   testEnv.Storage,
		},
	} {
		response, err := testEnv.Backend.HandleRequest(context.Background(), request)
		require.Error(t, err)
		require.Nil(t, response)
		require.Contains(t, err.Error(), "require an ML-KEM key")
	}
}
