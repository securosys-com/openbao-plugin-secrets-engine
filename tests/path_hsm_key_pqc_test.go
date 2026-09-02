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
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
	testHelpers "securosys.ch/test-helpers"
)

func TestCreatePQCKeys(t *testing.T) {
	testHelpers.RequireTSBConfig(t)

	testEnv, err := testHelpers.NewTestEnv()
	if err != nil {
		t.Fatal(err)
	}
	require.NoError(t, testEnv.AddConfigRaw())

	testCases := []struct {
		algorithm         string
		expectedAlgorithm string
		attributes        string
	}{
		{"ML-DSA-44", "ML-DSA-44", pqcSignAttributes},
		{"ML-DSA-65", "ML-DSA-65", pqcSignAttributes},
		{"ML-DSA-87", "ML-DSA-87", pqcSignAttributes},
		{"SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128s", pqcSignAttributes},
		{"SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-128f", pqcSignAttributes},
		{"SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192s", pqcSignAttributes},
		{"SLH-DSA-SHA2-192f", "SLH-DSA-SHA2-192f", pqcSignAttributes},
		{"SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256s", pqcSignAttributes},
		{"SLH-DSA-SHA2-256f", "SLH-DSA-SHA2-256f", pqcSignAttributes},
		{"SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128s", pqcSignAttributes},
		{"SLH-DSA-SHAKE-128f", "SLH-DSA-SHAKE-128f", pqcSignAttributes},
		{"SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192s", pqcSignAttributes},
		{"SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-192f", pqcSignAttributes},
		{"SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256s", pqcSignAttributes},
		{"SLH-DSA-SHAKE-256f", "SLH-DSA-SHAKE-256f", pqcSignAttributes},
		{"ML-KEM-512", "ML-KEM-512", pqcWrapAttributes},
		{"ML-KEM-768", "ML-KEM-768", pqcWrapAttributes},
		{"ML-KEM-1024", "ML-KEM-1024", pqcWrapAttributes},
		{"LMS", "HSS-LMS", pqcSignAttributes},
		{"XMSS-SHA256_10_256", "XMSS", pqcSignAttributes},
		{"XMSS-SHAKE256_10_256", "XMSS", pqcSignAttributes},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.algorithm, func(t *testing.T) {
			now := time.Now().UTC()
			timeStr := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02dZ", now.Year(), int(now.Month()), now.Day(), now.Hour(), now.Minute(), now.Second())
			keyName := "custom_pqc_" + safeKeyName(tc.algorithm)
			keyLabel := "TEST_SECUROSYS_SECRETS_ENGINE_PQC_" + strings.ToUpper(safeKeyName(tc.algorithm)) + "_" + timeStr

			t.Cleanup(func() {
				_ = testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, keyName)
			})

			err := testKeyPQCCreate(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
				"algorithm":  tc.algorithm,
				"keyLabel":   keyLabel,
				"attributes": tc.attributes,
			}, keyName)
			require.NoError(t, err)

			err = testHelpers.TestKeyRead(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
				"baseLabel": keyLabel,
				"algorithm": tc.expectedAlgorithm,
			}, keyName)
			require.NoError(t, err)

			err = testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, keyName)
			require.NoError(t, err)
		})
	}
}

const pqcSignAttributes = `{"decrypt": false,"sign": true,"unwrap": false,"derive": false,"sensitive": true,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`
const pqcWrapAttributes = `{"decrypt": false,"sign": false,"unwrap": true,"derive": false,"sensitive": true,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`

func safeKeyName(value string) string {
	replacer := strings.NewReplacer("-", "_")
	return replacer.Replace(strings.ToLower(value))
}

func testKeyPQCCreate(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}, keyName string) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "keys/pqc/" + keyName,
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		return err
	}

	if resp != nil && resp.IsError() {
		return resp.Error()
	}
	return nil
}
