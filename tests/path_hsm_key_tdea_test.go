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
	testHelpers "securosys.ch/test-helpers"
)

func TestTDEAKey(t *testing.T) {
	testHelpers.RequireTSBConfig(t)

	testEnv, err := testHelpers.NewTestEnv()
	if err != nil {
		t.Fatal(err)
	}
	t.Run("add config", testEnv.AddConfig)

	t.Run("Test Creating TDEA key", func(t *testing.T) {
		now := time.Now().UTC()
		timeStr := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02dZ", now.Year(), int(now.Month()), now.Day(), now.Hour(), now.Minute(), now.Second())
		err := testTDEAKeyCreate(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_TDEA_" + timeStr,
			"keySize":    0,
			"attributes": `{"decrypt": true,"sign": false,"unwrap": true,"derive": true,"sensitive": false,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
		}, "custom_tdea")

		assert.NoError(t, err)

		err = testTDEAKeyRead(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"baseLabel": "TEST_SECUROSYS_SECRETS_ENGINE_TDEA_" + timeStr,
			"keySize":   192,
			"algorithm": "TDEA",
		}, "custom_tdea")
		if err != nil {
			testTDEAKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_tdea")
		}
		assert.NoError(t, err)

		err = testTDEAKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_tdea")

		assert.NoError(t, err)
	})
}

func testTDEAKeyDelete(t *testing.T, b logical.Backend, s logical.Storage, keyName string) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "keys/" + keyName,
		Data:      map[string]interface{}{"removeFromHSM": true},
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

func testTDEAKeyCreate(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}, keyName string) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/tdea/" + keyName,
		Data:      d,
		Storage:   s,
	})

	if err != nil {
		return fmt.Errorf(err.Error())
	}

	if resp != nil && resp.IsError() {
		return resp.Error()
	}
	return nil
}

func testTDEAKeyRead(t *testing.T, b logical.Backend, s logical.Storage, expected map[string]interface{}, keyName string) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "keys/" + keyName,
		Storage:   s,
	})

	if err != nil {
		return err
	}
	if resp == nil && expected == nil {
		return nil
	}

	if resp.IsError() {
		return resp.Error()
	}

	for k, expectedV := range expected {
		actualV, ok := resp.Data[k]
		if !ok {
			return fmt.Errorf(`expected data["%s"] = %v but was not included in read output`, k, expectedV)
		}
		result, err := testHelpers.AreEqual(expectedV, actualV)
		if err != nil {
			return fmt.Errorf(`unexpected error: %s`, err.Error())
		}
		if !result {
			return fmt.Errorf(`expected data["%s"] = %v, instead got %v`, k, expectedV, actualV)
		}
	}

	return nil
}
