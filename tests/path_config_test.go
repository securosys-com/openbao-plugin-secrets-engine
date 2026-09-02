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
	testHelpers "securosys.ch/test-helpers"
)

func TestConfig(t *testing.T) {
	testHelpers.RequireTSBConfig(t)

	b, reqStorage := testHelpers.GetTestBackend(t)

	t.Run("Test Configuration", func(t *testing.T) {
		err := testConfigCreate(t, b, reqStorage, testHelpers.ConfigParams)

		if err != nil {
			assert.FailNow(t, err.Error())
		}

		err = testConfigRead(t, b, reqStorage, map[string]interface{}{
			"restapi": testHelpers.ConfigParams["restapi"],
			"auth":    testHelpers.ConfigParams["auth"],
		})

		assert.NoError(t, err)

		err = testConfigUpdate(t, b, reqStorage, map[string]interface{}{
			"restapi":     "https://primusdev.cloudshsm.com",
			"auth":        "TOKEN",
			"bearertoken": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJwcmltdXNkZXYiLCJ2ZXIiOjEsIm5iZiI6MTY2NDU0NzE0NSwib25ib2FyZFBhcnRpdGlvbiI6InRydWUiLCJpc3MiOiJTZWN1cm9zeXMgQ2xvdWQgQXV0aG9yaXphdGlvbiBTZXJ2aWNlIERFViIsInBhdFRTQiI6InBoakVWQllcL3Zadzd5N3gwWW1XQklUZWg5V3FGOTc0dVdNYTZPWDJiTDJoV0ZLTTg3MGdqTE1xOHZCU0R3ZUpTbWUxS1JSSllSXC9DOVlDXC85MUg2RndWTXZtOFhGcDRodlpuNlhKVkRvcDMyc1BHNTV1NmFCSzJzbGRJVnJaYTRDRThcL2NBZ0xVbVlubmZoZWZLRHVHalBYNWRHV25GUWRVWWVVakpaN1c0TDVkS2RDckNZUHpsZmRuU1BcL0p1YytsWGdlcm1JaWVtRVZDZGt1R043WWl4ZnIxM2FOaiIsImV4cCI6MzMyMjE0OTkxNDUsImlhdCI6MTY2NDU0NzE0NSwibm9uY2UiOnsic2FsdCI6IjNubzAxdTdlNDhoSEUwdUs3M1N3R3c9PSIsIml2IjoiUTlKZGxFT1R0Uyt1NjR6QiJ9fQ.DWoebl3J4ItyYWLU3uBlHxXROuLRtUi1vGsHzsn5ebZbQv_MDFwIcxl8sTJ_sOM1u5bU6wDRfEl3iphuq6KZiHik-PM7LsIsHtYmw-mIaqy1q05zjmVmamQW24fzzn-Doiwuv1PzxnekUOdS3hoV-M57_2RHzHriBAQWgN0B7mE-gz-TIEKDq9haXkw9swg9j9h-QFGhEcHfiayb8gISZIM_DRBC3a4ne5llxHl5yDvMXv8Ibxg8X8dv3HmG8KCJGZrts90R9fFDkJwUvEAiByDqq6rWzteN_feUrXR4loZvPJl05EV4dvHXIU26UAL_0HtfEReCdiwrmnebJITLKw",
		})

		assert.NoError(t, err)

		err = testConfigRead(t, b, reqStorage, map[string]interface{}{
			"restapi": "https://primusdev.cloudshsm.com",
			"auth":    "TOKEN",
		})

		assert.NoError(t, err)

		err = testConfigDelete(t, b, reqStorage)

		assert.NoError(t, err)
	})
}

func testConfigDelete(t *testing.T, b logical.Backend, s logical.Storage) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "config",
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

func testConfigCreate(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
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

func testConfigUpdate(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
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

func testConfigRead(t *testing.T, b logical.Backend, s logical.Storage, expected map[string]interface{}) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
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
			return fmt.Errorf(`expected data["%s"] = %v but was not included in read output"`, k, expectedV)
		} else if expectedV != actualV {
			return fmt.Errorf(`expected data["%s"] = %v, instead got %v"`, k, expectedV, actualV)
		}
	}

	return nil
}
