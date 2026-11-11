/*
Copyright (c) 2023 Securosys SA, authors: Tomasz Madej, Mikolaj Szargut

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

package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	helpers "securosys.ch/helpers"
)

// Function thats send wrap request to TSB
func (c *TSBClient) Wrap(wrapKeyName string, wrapKeyPassword string, keyToBeWrapped string, keyToBeWrappedPassword string, wrapMethod string) (*helpers.WrapResponse, int, error) {
	keyToBeWrappedPasswordJson, _ := json.Marshal(helpers.StringToCharArray(keyToBeWrappedPassword))
	wrapKeyPasswordJson, _ := json.Marshal(helpers.StringToCharArray(wrapKeyPassword))
	keyToBeWrappedPasswordString := ""
	if len(keyToBeWrappedPasswordJson) > 2 {
		keyToBeWrappedPasswordString = `"keyToBeWrappedPassword": ` + string(keyToBeWrappedPasswordJson) + `,`

	}
	wrapKeyPasswordString := ""
	if len(wrapKeyPasswordJson) > 2 {
		wrapKeyPasswordString = `"wrapKeyPassword": ` + string(wrapKeyPasswordJson) + `,`

	}

	var jsonStr = []byte(`{
		"wrapKeyRequest": {
		"keyToBeWrapped": "` + keyToBeWrapped + `",
		` + keyToBeWrappedPasswordString + `
		  "wrapKeyName": "` + wrapKeyName + `",
		  ` + wrapKeyPasswordString + `
		  "wrapMethod":"` + wrapMethod + `"
		}
	  }`)

	req, err := http.NewRequest("POST", c.HostURL+"/v1/wrap", bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, 500, err
	}
	body, code, errRes := c.doRequest(req, KeyOperationTokenName)
	if errRes != nil {
		return nil, code, errRes
	}
	var response helpers.WrapResponse
	// response.KeyID = signKeyName
	// response.CertificateRequest = string(body)
	json.Unmarshal(body, &response)
	return &response, code, nil

}

// Function thats sends asynchronous unwrap request to TSB
func (c *TSBClient) AsyncUnWrap(wrappedKey string, label string, attributes map[string]bool, unwrapKeyName string, unwrapKeyPassword string, wrapMethod string, policy *helpers.Policy, customMetaData map[string]string) (string, int, error) {
	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(unwrapKeyPassword))
	var additionalMetaDataInfo map[string]string = make(map[string]string)
	additionalMetaDataInfo["wrapped key"] = wrappedKey
	additionalMetaDataInfo["new key label"] = label
	additionalMetaDataInfo["wrap method"] = wrapMethod
	additionalMetaDataInfo["attributes"] = fmt.Sprintf("%v", attributes)
	var policyString string
	if policy == nil {
		policyString = string(`,"policy":null`)
	} else {
		policyJson, _ := json.Marshal(*policy)
		policyString = string(`,"policy":` + string(policyJson))
	}

	if attributes["extractable"] {
		policyString = string(`,"policy":null`)
	}
	//Only for asychronous unwrap
	policyString = string(``)
	metaDataB64, metaDataSignature, err := c.PrepareMetaData("UnWrap", additionalMetaDataInfo, customMetaData)
	if err != nil {
		return "", 500, err
	}
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"unwrapKeyPassword": ` + string(charsPasswordJson) + `,`

	}
	metaDataSignatureString := "null"
	if metaDataSignature != nil {
		metaDataSignatureString = `"` + *metaDataSignature + `"`

	}
	requestJson := `{
		"wrappedKey": "` + wrappedKey + `",
		"label": "` + label + `",
		"unwrapKeyName": "` + unwrapKeyName + `",
		` + passwordString + `
		"wrapMethod": "` + wrapMethod + `",
		"attributes": ` + helpers.PrepareAttributes(attributes) + `,
		"metaData": "` + metaDataB64 + `",
		"metaDataSignature": ` + metaDataSignatureString + `` + policyString + `
		}`
	var jsonStr = []byte(helpers.MinifyJson(`{
			"unwrapKeyRequest": ` + requestJson + `,
			"requestSignature":` + string(c.GenerateRequestSignature(requestJson)) + `
		}`))
	req, err := http.NewRequest("POST", c.HostURL+"/v1/unwrap", bytes.NewBuffer(jsonStr))
	if err != nil {
		return "", 500, err
	}
	body, code, errRes := c.doRequest(req, KeyOperationTokenName)
	if errRes != nil {
		return "", code, errRes
	}
	var result map[string]interface{}
	errJSON := json.Unmarshal(body, &result)
	if errJSON != nil {
		return "", code, errJSON
	}
	return result["unwrapRequestId"].(string), code, nil
}

// Function thats sends unwrap request to TSB
func (c *TSBClient) UnWrap(wrappedKey string, label string, attributes map[string]bool, unwrapKeyName string, unwrapKeyPassword string, wrapMethod string, policy *helpers.Policy) (int, error) {
	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(unwrapKeyPassword))
	var policyString string
	if policy == nil {
		policyString = string(`,"policy":null`)
	} else {
		policyJson, _ := json.Marshal(policy)
		policyString = string(`,"policy":` + string(policyJson))
	}
	if attributes["extractable"] {
		policyString = string(`,"policy":null`)
	}
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"unwrapKeyPassword": ` + string(charsPasswordJson) + `,`

	}

	var jsonStr = []byte(`{
		"unwrapKeyRequest": {
		"wrappedKey": "` + wrappedKey + `",
		"label": "` + label + `",
		"unwrapKeyName": "` + unwrapKeyName + `",
		` + passwordString + `
		"wrapMethod": "` + wrapMethod + `",
		"attributes": ` + helpers.PrepareAttributes(attributes) + policyString + `
		}}`)
	req, err := http.NewRequest("POST", c.HostURL+"/v1/synchronousUnwrap", bytes.NewBuffer(jsonStr))
	if err != nil {
		return 500, err
	}
	_, code, err := c.doRequest(req, KeyOperationTokenName)
	return code, err
}
