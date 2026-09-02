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
	"net/http"

	helpers "securosys.ch/helpers"
)

// Function thats send request modify key to TSB
func (c *TSBClient) Modify(label string, password string, policy helpers.Policy) (int, error) {
	policyJson, _ := json.Marshal(policy)
	policyString := string(`,"policy":` + string(policyJson))

	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"keyPassword": ` + string(charsPasswordJson) + `,`

	}

	var jsonStr = []byte(`{
		"modifyRequest":{
			` + passwordString + `
			"modifyKeyName": "` + label + `"
			` + policyString + `}
		}`)

	req, err := http.NewRequest("POST", c.HostURL+"/v1/synchronousModify", bytes.NewBuffer(jsonStr))
	if err != nil {
		return 500, err
	}
	_, code, errRes := c.doRequest(req, KeyManagementTokenName)
	if errRes != nil {
		return code, errRes
	}
	return code, nil

}

// Function thats send asynchronous request modify key to TSB
func (c *TSBClient) AsyncModify(label string, password string, policy helpers.Policy, customMetaData map[string]string) (string, int, error) {
	var additionalMetaDataInfo map[string]string = make(map[string]string)
	metaDataB64, metaDataSignature, err := c.PrepareMetaData("Modify", additionalMetaDataInfo, customMetaData)
	if err != nil {
		return "", 500, err
	}
	policyJson, _ := json.Marshal(policy)
	policyString := string(`,"policy":` + string(policyJson))

	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"keyPassword": ` + string(charsPasswordJson) + `,`

	}
	metaDataSignatureString := "null"
	if metaDataSignature != nil {
		metaDataSignatureString = `"` + *metaDataSignature + `"`

	}
	requestJson := `{"modifyKeyName": "` + label + `",
		` + passwordString + `
		"metaData": "` + metaDataB64 + `",
		"metaDataSignature": ` + metaDataSignatureString + `
		  ` + policyString + `}`
	var jsonStr = []byte(helpers.MinifyJson(`{
		"modifyRequest":` + requestJson + `,
		"requestSignature":` + string(c.GenerateRequestSignature(requestJson)) + `
		}`))
	req, err := http.NewRequest("POST", c.HostURL+"/v1/modify", bytes.NewBuffer(jsonStr))
	if err != nil {
		return "", 500, err
	}
	body, code, errRes := c.doRequest(req, KeyManagementTokenName)
	if errRes != nil {
		return "", code, errRes
	}
	var result map[string]interface{}
	errJSON := json.Unmarshal(body, &result)
	if errJSON != nil {
		return "", code, errJSON
	}
	return result["modifyKeyRequestId"].(string), code, nil

}
