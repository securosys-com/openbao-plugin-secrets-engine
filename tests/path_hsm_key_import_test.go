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

func TestIMPORTKey(t *testing.T) {
	testHelpers.RequireTSBConfig(t)

	testEnv, err := testHelpers.NewTestEnv()
	if err != nil {
		t.Fatal(err)
	}
	t.Run("add config", testEnv.AddConfig)

	t.Run("Test Creating IMPORT key = AES", func(t *testing.T) {
		now := time.Now().UTC()
		timeStr := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02dZ", now.Year(), int(now.Month()), now.Day(), now.Hour(), now.Minute(), now.Second())
		err := testIMPORTKeyCreate(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_IMPORT_AES_" + timeStr,
			"attributes": `{"decrypt": true,"sign": false,"unwrap": true,"derive": true,"sensitive": false,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
			"secretKey":  "SkBOY1JmVWpYbjJyNXU3eCFBJUQqRy1LYVBkU2dWa1k=",
			"algorithm":  "AES",
		}, "custom_import_aes")

		assert.NoError(t, err)

		err = testHelpers.TestKeyRead(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"baseLabel": "TEST_SECUROSYS_SECRETS_ENGINE_IMPORT_AES_" + timeStr,
			"algorithm": "AES",
			"keySize":   256,
		}, "custom_import_aes")
		if err != nil {
			testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_import_aes")
		}
		assert.NoError(t, err)

		err = testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_import_aes")

		assert.NoError(t, err)
	})
	t.Run("Test Creating IMPORT key = RSA", func(t *testing.T) {
		now := time.Now().UTC()
		timeStr := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02dZ", now.Year(), int(now.Month()), now.Day(), now.Hour(), now.Minute(), now.Second())
		err := testIMPORTKeyCreate(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_IMPORT_RSA_" + timeStr,
			"attributes": `{"decrypt": true,"sign": false,"unwrap": true,"derive": true,"sensitive": false,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
			"privateKey": "MIIJQQIBADANBgkqhkiG9w0BAQEFAASCCSswggknAgEAAoICAQDRXA17OUcb+f6SCPfZWSSuaykszAHwHaI6KZHi8A/PIfa8NXroj5KVVm6zpf3AXq4qKDNMweUrGDoiiE07YBxF44k/NqrU/kywN+vYpwEuYjq1qYyNIrDAuMLz41MOrZPJ9lUg6hlOs7fgC+sf2vyBRSEf00hkUVk80SdM/3vMt0MxLmZDtRjuO2NOYXlqU6w6rQfuuhqfck73uKevvJ6cvM0kYrNXpwEP5pScQ8jSjaDoJNqi7nmgZ53eu+wrhqmrcOt2WC1DzJr20FTKYgxlEC3f4NcPa2kCSZ8OkVFCpcXOyDliiBSoN+Ik6H+4BSZoTKQ41G6loE/rENEG1UI32YPV4ZQGUVuK4PBGwBQ++nwKSoWKDFxDTLdSL643zwchSM9/rHBWGzrOtOvzMnjX/sYd23aW/wQFbK30+U204ujq5GS9n1Uv9w8KQbU89tZk3riSdxO47byKtcOQZLs8mRV6x65CQKZy3vuMi0Z4cyqE8oH/B8WcbSzm3AkRKpfCYP4jsLVMpkWkxDGvXg0CX++IfW6dZxD6lRDqk9evMBvpPe3EujHplVVCuHeUGdxoZPqdg7b1uP+fTyEx49QM9w0E5NchoxTUn5+qaN4VDKXfrddsvDJe6KxQ7KO2bg9D7EwmzxauI+VVa+XRCJMpsoXaQ7mpY49QxfHvaALZFwIDAQABAoICAA04DLndEfpYPJSn8E5O7Jv+tCjZ8L1igZ2+hjGYCsd/U37quYn5lr3LKU46it0cnU6YHzUXgQrJitInXQkEtoRLK51MLFkqfVkbDs8tLEvrc92IiRFYQWTJxbV0gwgIOa6k2Rcs8NAhVNjWp8/pGcxnuwGxa366DDJk2mBoOT7hy2JNlbNsudhA87I9QVdPVS6XQkr2gTvUEdxeUmgsNq+a1DEZ8kz0hIKmgnejaAizXJeLzCpBeHiCUlt/7heJdykWBigAxUrknlw7Jz9oFXREI0FhhvK4S3cTgvF+h2z33peB2O25veQpMyQ1cesCmDw5qpzT/PCEQMeM1kXiLT4QR5tlsJgiyP9wb3OL/XCc4UieikUWyDR2LBd2WbgkcEr49Pfs48Yd7DyaQvWFj/7P961T7jSm9ng5J7OWP55kWJw9BSRCmxePcQfHyGgk0PU+2so3lalzjjtEQ/14BHNNvk3itq4T7FiEyUamBYW2KVxsoJ3EH4p1a7VHOSbfPn3N/ZsKjIbCMSxDPJUpnl0N/thFyzLxNBd5brKdE22Y7Nsi4EED/6oJCADuOfbauJci4Tiygr9kN9c6kCQPf6qjp2VsSDaIqX4w4bsYh+GyaqfZc0dVSIwN76qVAn/r9AkUfCx8cVywGDlbaoTyQbEImR34pPcZaWcrH2sUnqIRAoIBAQDoJnyPnZHqjLqNazqKLLtUBKs5yoAObHoQXNQ0IO4p0aSQ1bM2z0+N9ND27iNO/ySPjCm7aPSbeEQTUoXYBw47rz5duvatm1/iwJDrSgMFK4SBZ1UEBc+zW51R4AYhkkoHgXNGNMtocH+/A17Y/D+KAiwfbWdK/JiZpTfUE0xsHSOCJiarD4ARJjp2hOzfGel32e+i8ekRcnJTgNEftxbw1heV+bCYyGGoTDa0Qzi9lqpIyopydx55iF4l2WrpeGBpla4yCymCC6T+AY8CfvIMOwQDq+X9dloBBrqzKXQDX8OOLjH26Lvp6zPlFNnrB1x3iZTeEgvbtSDeh+9cGwPLAoIBAQDm3ixTUwQ3OZR5spT32pvhvW8pTFKOn0in13u6ZWpsowaaCVWQAJuLBjywx4Hn1fszbxPyy+WgWjB7oqhMAy2FwX6lBAWRYRZTX3kp3S/4R+M40H5C7iv3tQOB4LXwY4OxhnEb+taTRCbGRugURkeH1qXo6p+cSWl5UdE/PcY0T39KCA5VuoFPOAJ3sPEhUHkGCJa15TY6Ne/47AdnIgmv1xNfu2qaYR15WB0TvUKyDXQmznoHQvCtQ1JVvSjfJ3NuSKAXSgA9vWjlTa7fEqgeNv+KTSH+N0vlj4fUcijGvohgwvQwCb8ouNWznVjQq2WmQEm+EI4qKBoYQGn1R85lAoIBAFPT+eyeGF+au45vZu8YIfi/ytiOb9lFgHpCGvpL3dRJ+GO4VwN2rqJzAbX43dUbuqb/FN6wkotFTUew59XPDmus5xdPeN3Nmj02Dd54lkiaozlbB87xDkQU0+UJwQ0EVykIrIhwbfbjkK132Rr/Uy5RhH9AsSjZt3zbtSImadUsXHMVtabVbQhERp4fd61EHRMDJk4vjlqXegL/JASQx37lwBSO2h8BVIpCIwrKr0V+jzTDtmSI8P8vp9eA/+MYbbAStZkqgK2N6OEzzOE418xkzxlITD9PKkbumCIz2MmTHflMYwxmk9xu6wlQkzQUL2aWzqO13oRSjnDsoxkeRCsCggEARRvIpQC6yFVCLtPYaAFWnFJ6jiA8rljcBPIqJXfqTa7XcRDOPhcQeKNbU4fFSULyuUjM7ec/S6rzzG66dlaVL+7mHDuB9yza5AY2XOPLUkUirYUr5pkpLDNRY3WCwPzpFSErhraluNuzx7K+EiOfkfgdHgXt1XjcS+bD/mxdgpcxgVW8BMmZn78ibfXXmKNgNwAnLTf57Z7rwNXWuXak87AsKoINvTzI9+P6gEgtSONiG6O/P6E4LoVyhhvjujkzApZW5eHPBKxIVCvW5wvMq47HG/1O6axf2c4HWP77WdL7PAvf0Ol6AZSi0+uMBJrqCMRBztVh2Ri8BvpxPW1LSQKCAQBIxJbJhLCMfl9GH/tFnLGeQ3a5Kh7hFegN64+/N0jvfIw4OK0bjPctdUekqyTItd6QJCt/JiMK0YroZSsvqpb9cC+OT51q/MVvxj7SPEtIpCLma8jpvg4lY39dA3xmh2ByTR0TNsgsYZDX8fJ85MxF2h3hY/16l2l2o4N/hbki/hYs5+s8M9qcRF0/9ahsCK/P/Z4FnyI/jptoQtUzQZZfwIeI8uMAWzEvapvniG71rPXHqTjGObxfi0JhLtiQsPr+TSOsDVlUSkb4zrO+dBZJNZOzxj0BwTeleZavYqQkWTeqkTs//yUdDtJBR/zpOP09mBE0dE/3wiPngmw99lDf",
			"publicKey":  "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0VwNezlHG/n+kgj32VkkrmspLMwB8B2iOimR4vAPzyH2vDV66I+SlVZus6X9wF6uKigzTMHlKxg6IohNO2AcReOJPzaq1P5MsDfr2KcBLmI6tamMjSKwwLjC8+NTDq2TyfZVIOoZTrO34AvrH9r8gUUhH9NIZFFZPNEnTP97zLdDMS5mQ7UY7jtjTmF5alOsOq0H7roan3JO97inr7yenLzNJGKzV6cBD+aUnEPI0o2g6CTaou55oGed3rvsK4apq3DrdlgtQ8ya9tBUymIMZRAt3+DXD2tpAkmfDpFRQqXFzsg5YogUqDfiJOh/uAUmaEykONRupaBP6xDRBtVCN9mD1eGUBlFbiuDwRsAUPvp8CkqFigxcQ0y3Ui+uN88HIUjPf6xwVhs6zrTr8zJ41/7GHdt2lv8EBWyt9PlNtOLo6uRkvZ9VL/cPCkG1PPbWZN64kncTuO28irXDkGS7PJkVeseuQkCmct77jItGeHMqhPKB/wfFnG0s5twJESqXwmD+I7C1TKZFpMQxr14NAl/viH1unWcQ+pUQ6pPXrzAb6T3txLox6ZVVQrh3lBncaGT6nYO29bj/n08hMePUDPcNBOTXIaMU1J+fqmjeFQyl363XbLwyXuisUOyjtm4PQ+xMJs8WriPlVWvl0QiTKbKF2kO5qWOPUMXx72gC2RcCAwEAAQ==",
			"algorithm":  "RSA",
		}, "custom_import_rsa")

		assert.NoError(t, err)

		err = testHelpers.TestKeyRead(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"baseLabel": "TEST_SECUROSYS_SECRETS_ENGINE_IMPORT_RSA_" + timeStr,
			"algorithm": "RSA",
		}, "custom_import_rsa")
		if err != nil {
			testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_import_rsa")
		}
		assert.NoError(t, err)

		err = testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_import_rsa")

		assert.NoError(t, err)
	})
}

func testIMPORTKeyCreate(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}, keyName string) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/" + keyName + "/import",
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
