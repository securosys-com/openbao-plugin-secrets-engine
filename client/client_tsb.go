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

package client

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"time"

	helpers "securosys.ch/helpers"
)

// HostURL - Default Securosys TSB URL
const HostURL string = ""

// TSBClient struct
type TSBClient struct {
	HostURL    string
	HTTPClient *http.Client
	Auth       AuthStruct
}
type AuthStruct struct {
	AuthType    string `json:"auth"`
	CertPath    string `json:"certpath"`
	KeyPath     string `json:"keypath"`
	BearerToken string `json:"bearertoken"`
	BasicToken  string `json:"basictoken"`
	Username    string `json:"username"`
	Password    string `json:"password"`
}

// Function inicialize new client for accessing TSB
func NewTSBClient(data map[string]string) (*TSBClient, error) {
	c := TSBClient{
		HTTPClient: &http.Client{Timeout: 9999999 * time.Second},
		// Default Hashicups URL
		HostURL: data["restapi"],
		Auth: AuthStruct{
			AuthType:    data["auth"],
			CertPath:    data["certpath"],
			KeyPath:     data["keypath"],
			BearerToken: data["bearertoken"],
			BasicToken:  data["basictoken"],
			Username:    data["username"],
			Password:    data["password"],
		},
	}

	return &c, nil
}

// Function thats send request modify key to TSB
func (c *TSBClient) Modify(label string, password string, policy helpers.Policy) (string, error) {
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
		return "", err
	}
	_, errRes, _ := c.doRequest(req)
	if errRes != nil {
		return "", errRes
	}
	return label, nil

}

// Function thats send asynchronous request modify key to TSB
func (c *TSBClient) AsyncModify(label string, password string, policy helpers.Policy, customMetaData map[string]string) (string, error) {
	var additionalMetaDataInfo map[string]string = make(map[string]string)
	metaDataB64, metaDataSignature, err := helpers.PrepareMetaData("Modify", additionalMetaDataInfo, customMetaData)
	policyJson, _ := json.Marshal(policy)
	policyString := string(`,"policy":` + string(policyJson))

	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"keyPassword": ` + string(charsPasswordJson) + `,`

	}
	var jsonStr = []byte(`{
		"modifyRequest":{
			"modifyKeyName": "` + label + `",
			` + passwordString + `
			"metaData": "` + metaDataB64 + `",
			"metaDataSignature": "` + metaDataSignature + `"
			  ` + policyString + `}
		}`)
	req, err := http.NewRequest("POST", c.HostURL+"/v1/modify", bytes.NewBuffer(jsonStr))
	if err != nil {
		return "", err
	}
	body, errRes, _ := c.doRequest(req)
	if errRes != nil {
		return "", errRes
	}
	var result map[string]interface{}
	errJSON := json.Unmarshal(body, &result)
	if errJSON != nil {
		return "", errJSON
	}
	return result["modifyKeyRequestId"].(string), nil

}

// Function thats send wrap request to TSB
func (c *TSBClient) Wrap(wrapKeyName string, wrapKeyPassword string, keyToBeWrapped string, keyToBeWrappedPassword string, wrapMethod string) (map[string]interface{}, error) {
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
		return nil, err
	}
	body, errRes, _ := c.doRequest(req)
	if errRes != nil {
		return nil, errRes
	}
	var response map[string]interface{}
	json.Unmarshal(body, &response)
	return response, nil

}

// Function thats send encrypt request to TSB
func (c *TSBClient) Encrypt(label string, password string, payload string, cipherAlgorithm string, tagLength int, additionalAuthenticationData string) (map[string]interface{}, error) {
	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	additionalAuthenticationDataString := `"` + additionalAuthenticationData + `"`
	if additionalAuthenticationData == "" {
		additionalAuthenticationDataString = "null"
	}
	tagLengthString := ""
	if tagLength != -1 && cipherAlgorithm == "AES_GSM" {
		tagLengthString = `"tagLength":` + strconv.Itoa(tagLength) + `,`
	}
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"keyPassword": ` + string(charsPasswordJson) + `,`

	}

	var jsonStr = []byte(`{
		"encryptRequest": {
		  "payload": "` + payload + `",
		  ` + passwordString + `
		  "encryptKeyName": "` + label + `",
		  "cipherAlgorithm": "` + cipherAlgorithm + `",
		  ` + tagLengthString + `
		  "additionalAuthenticationData":` + additionalAuthenticationDataString + `
		}
	  }`)
	req, err := http.NewRequest("POST", c.HostURL+"/v1/encrypt", bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, err
	}
	body, errRes, _ := c.doRequest(req)
	if errRes != nil {
		return nil, errRes
	}
	var response map[string]interface{}
	json.Unmarshal(body, &response)
	if !helpers.ContainsKey(response, "encryptedPayload") || !helpers.ContainsKey(response, "initializationVector") {
		return nil, fmt.Errorf("Error on encrypt response. Need encryptedPayload, initializationVector found %s", string(body[:]))
	}
	return response, nil

}

// Function thats send block request to TSB
func (c *TSBClient) Block(label string, password string) (map[string]interface{}, error) {
	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"keyPassword": ` + string(charsPasswordJson) + `,`

	}

	var jsonStr = []byte(`{
		"blockRequest": {
		  ` + passwordString + `
		  "blockKeyName": "` + label + `"
		}
	  }`)

	req, err := http.NewRequest("POST", c.HostURL+"/v1/synchronousBlock", bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, err
	}
	body, errRes, _ := c.doRequest(req)
	if errRes != nil {
		return nil, errRes
	}
	var response map[string]interface{}
	json.Unmarshal(body, &response)
	return response, nil

}

// Function thats send asynchronous block request to TSB
func (c *TSBClient) AsyncBlock(label string, password string, customMetaData map[string]string) (string, error) {
	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	var additionalMetaDataInfo map[string]string = make(map[string]string)
	metaDataB64, metaDataSignature, err := helpers.PrepareMetaData("Block", additionalMetaDataInfo, customMetaData)
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"keyPassword": ` + string(charsPasswordJson) + `,`

	}

	var jsonStr = []byte(`{
		"blockRequest": {
		  "blockKeyName": "` + label + `",
		  ` + passwordString + `	  
		  "metaData": "` + metaDataB64 + `",
		  "metaDataSignature": "` + metaDataSignature + `"

		}
	  }`)

	req, err := http.NewRequest("POST", c.HostURL+"/v1/block", bytes.NewBuffer(jsonStr))
	if err != nil {
		return "", err
	}
	body, errRes, _ := c.doRequest(req)
	if errRes != nil {
		return "", errRes
	}
	var result map[string]interface{}
	errJSON := json.Unmarshal(body, &result)
	if errJSON != nil {
		return "", errJSON
	}
	return result["blockKeyRequestId"].(string), nil

}

// Function thats send unblock request to TSB
func (c *TSBClient) UnBlock(label string, password string) (map[string]interface{}, error) {
	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"keyPassword": ` + string(charsPasswordJson) + `,`

	}

	var jsonStr = []byte(`{
		"unblockRequest": {
		` + passwordString + `
		  "unblockKeyName": "` + label + `"
		}
	  }`)

	req, err := http.NewRequest("POST", c.HostURL+"/v1/synchronousUnblock", bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, err
	}
	body, errRes, _ := c.doRequest(req)
	if errRes != nil {
		return nil, errRes
	}
	var response map[string]interface{}
	json.Unmarshal(body, &response)
	return response, nil

}

// Function thats send asynchronous unblock request to TSB
func (c *TSBClient) AsyncUnBlock(label string, password string, customMetaData map[string]string) (string, error) {
	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	var additionalMetaDataInfo map[string]string = make(map[string]string)
	metaDataB64, metaDataSignature, err := helpers.PrepareMetaData("UnBlock", additionalMetaDataInfo, customMetaData)
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"keyPassword": ` + string(charsPasswordJson) + `,`

	}

	var jsonStr = []byte(`{
		"unblockRequest": {
		  "unblockKeyName": "` + label + `",
		  ` + passwordString + `
		  "metaData": "` + metaDataB64 + `",
		  "metaDataSignature": "` + metaDataSignature + `"
		}
	  }`)

	req, err := http.NewRequest("POST", c.HostURL+"/v1/unblock", bytes.NewBuffer(jsonStr))
	if err != nil {
		return "", err
	}
	body, errRes, _ := c.doRequest(req)
	if errRes != nil {
		return "", errRes
	}
	var result map[string]interface{}
	errJSON := json.Unmarshal(body, &result)
	if errJSON != nil {
		return "", errJSON
	}
	return result["unblockKeyRequestId"].(string), nil
}

// Function thats sends sign request to TSB
func (c *TSBClient) Sign(label string, password string, payload string, payloadType string, signatureAlgorithm string) (map[string]interface{}, error) {
	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"keyPassword": ` + string(charsPasswordJson) + `,`

	}

	var jsonStr = []byte(`{
		"signRequest": {
		  "payload": "` + payload + `",
		  "payloadType": "` + payloadType + `",
		  ` + passwordString + `
		  "signKeyName": "` + label + `",
		  "signatureAlgorithm": "` + signatureAlgorithm + `"
		}
	  }`)

	req, err := http.NewRequest("POST", c.HostURL+"/v1/synchronousSign", bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, err
	}
	body, errRes, _ := c.doRequest(req)
	if errRes != nil {
		return nil, errRes
	}
	var response map[string]interface{}
	json.Unmarshal(body, &response)
	if !helpers.ContainsKey(response, "signature") {
		return nil, fmt.Errorf("Error on sign response. Need signature found %s", string(body[:]))
	}

	return response, nil

}

// Function thats sends asynchronous sign request to TSB
func (c *TSBClient) AsyncSign(label string, password string, payload string, payloadType string, signatureAlgorithm string, customMetaData map[string]string) (string, error) {
	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	var additionalMetaDataInfo map[string]string = make(map[string]string)
	additionalMetaDataInfo["payload"] = payload
	additionalMetaDataInfo["payload type"] = payloadType
	additionalMetaDataInfo["signature algorithm"] = signatureAlgorithm

	metaDataB64, metaDataSignature, err := helpers.PrepareMetaData("Sign", additionalMetaDataInfo, customMetaData)
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"keyPassword": ` + string(charsPasswordJson) + `,`

	}

	var jsonStr = []byte(`{
		"signRequest": {
		  "payload": "` + payload + `",
		  "payloadType": "` + payloadType + `",
		  ` + passwordString + `
		  "signKeyName": "` + label + `",
		  "signatureAlgorithm": "` + signatureAlgorithm + `",
		  "metaData": "` + metaDataB64 + `",
		  "metaDataSignature": "` + metaDataSignature + `"
		}
	  }`)

	req, err := http.NewRequest("POST", c.HostURL+"/v1/sign", bytes.NewBuffer(jsonStr))
	if err != nil {
		return "", err
	}
	body, errRes, _ := c.doRequest(req)
	if errRes != nil {
		return "", errRes
	}
	var result map[string]interface{}
	errJSON := json.Unmarshal(body, &result)
	if errJSON != nil {
		return "", errJSON
	}
	return result["signRequestId"].(string), nil

}

// Function thats sends verify request to TSB
func (c *TSBClient) Verify(label string, password string, payload string, signatureAlgorithm string, signature string) (map[string]interface{}, error) {
	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"masterKeyPassword": ` + string(charsPasswordJson) + `,`

	}

	var jsonStr = []byte(`{
		"verifySignatureRequest": {
		  "payload": "` + payload + `",
		  ` + passwordString + `	
		  "signKeyName": "` + label + `",
		  "signatureAlgorithm": "` + signatureAlgorithm + `",
		  "signature": "` + signature + `"
		}
	  }`)

	req, err := http.NewRequest("POST", c.HostURL+"/v1/verify", bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, err
	}
	body, errRes, _ := c.doRequest(req)
	if errRes != nil {
		return nil, errRes
	}
	var response map[string]interface{}
	json.Unmarshal(body, &response)
	return response, nil

}

// Function thats sends asynchronous decrypt request to TSB
func (c *TSBClient) AsyncDecrypt(label string, password string, cipertext string, vector string, cipherAlgorithm string, tagLength int, additionalAuthenticationData string, customMetaData map[string]string) (string, error) {
	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))

	var additionalMetaDataInfo map[string]string = make(map[string]string)
	additionalMetaDataInfo["encrypted payload"] = cipertext
	additionalMetaDataInfo["cipher algorithm"] = cipherAlgorithm
	additionalMetaDataInfo["tag length"] = strconv.Itoa(tagLength)
	additionalMetaDataInfo["additional authentication data"] = additionalAuthenticationData
	additionalMetaDataInfo["initialization vector"] = vector

	metaDataB64, metaDataSignature, err := helpers.PrepareMetaData("Decrypt", additionalMetaDataInfo, customMetaData)
	if err != nil {
		return "", err
	}
	vectorString := `"` + vector + `"`
	if vector == "" {
		vectorString = "null"
	}
	additionalAuthenticationDataString := `"` + additionalAuthenticationData + `"`
	if additionalAuthenticationData == "" {
		additionalAuthenticationDataString = "null"
	}
	tagLengthString := ""
	if tagLength != -1 && cipherAlgorithm == "AES_GSM" {
		tagLengthString = `"tagLength":` + strconv.Itoa(tagLength) + `,`
	}
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"keyPassword": ` + string(charsPasswordJson) + `,`

	}

	var jsonStr = []byte(`{
		"decryptRequest": {
		  "encryptedPayload": "` + cipertext + `",
		  ` + passwordString + `
		  "decryptKeyName": "` + label + `",
		  "metaData": "` + metaDataB64 + `",
		  "metaDataSignature": "` + metaDataSignature + `",
		  "cipherAlgorithm": "` + cipherAlgorithm + `",
		  "initializationVector": ` + vectorString + `,
		  ` + tagLengthString + `
		  "additionalAuthenticationData":` + additionalAuthenticationDataString + `
		}
	  }`)
	req, err := http.NewRequest("POST", c.HostURL+"/v1/decrypt", bytes.NewBuffer(jsonStr))
	if err != nil {
		return "", err
	}
	body, errRes, _ := c.doRequest(req)
	if errRes != nil {
		return "", errRes
	}
	var result map[string]interface{}
	errJSON := json.Unmarshal(body, &result)
	if errJSON != nil {
		return "", errJSON
	}
	return result["decryptRequestId"].(string), nil
	// return response, nil

}

// Function thats sends decrypt request to TSB
func (c *TSBClient) Decrypt(label string, password string, cipertext string, vector string, cipherAlgorithm string, tagLength int, additionalAuthenticationData string) (map[string]interface{}, error) {
	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	vectorString := `"` + vector + `"`
	if vector == "" {
		vectorString = "null"
	}
	additionalAuthenticationDataString := `"` + additionalAuthenticationData + `"`
	if additionalAuthenticationData == "" {
		additionalAuthenticationDataString = "null"
	}
	tagLengthString := ""
	if tagLength != -1 && cipherAlgorithm == "AES_GSM" {
		tagLengthString = `"tagLength":` + strconv.Itoa(tagLength) + `,`
	}
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"keyPassword": ` + string(charsPasswordJson) + `,`

	}

	var jsonStr = []byte(`{
		"decryptRequest": {
		  "encryptedPayload": "` + cipertext + `",
		  ` + passwordString + `	
		  "decryptKeyName": "` + label + `",
		  "cipherAlgorithm": "` + cipherAlgorithm + `",
		  "initializationVector": ` + vectorString + `,
		  ` + tagLengthString + `
		  "additionalAuthenticationData":` + additionalAuthenticationDataString + `
		}
	  }`)
	req, err := http.NewRequest("POST", c.HostURL+"/v1/synchronousDecrypt", bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, err
	}
	body, errRes, _ := c.doRequest(req)
	if errRes != nil {
		return nil, errRes
	}
	var response map[string]interface{}
	json.Unmarshal(body, &response)
	if !helpers.ContainsKey(response, "payload") {
		return nil, fmt.Errorf("Error on decrypt response. Need payload found %s", string(body[:]))
	}
	return response, nil

}

// Function thats sends export request to TSB
func (c *TSBClient) ExportKey(label string, password string) (map[string]interface{}, error) {
	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"password": ` + string(charsPasswordJson) + `,`

	}

	var jsonStr = []byte(`{
		` + passwordString + `
		  "label": "` + label + `"
		  
	  }`)

	req, err := http.NewRequest("POST", c.HostURL+"/v1/key/export/plain", bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, err
	}
	body, errRes, _ := c.doRequest(req)
	if errRes != nil {
		return nil, errRes
	}

	var response map[string]interface{}
	json.Unmarshal(body, &response)

	return response, nil

}

// Function thats sends get request to TSB
func (c *TSBClient) GetRequest(id string) (*helpers.RequestResponse, error, int) {
	req, err := http.NewRequest("GET", c.HostURL+"/v1/request/"+id, bytes.NewBuffer(nil))
	if err != nil {
		return nil, err, 500
	}
	body, errRes, code := c.doRequest(req)
	if errRes != nil {
		return nil, errRes, code
	}
	var requestResponse helpers.RequestResponse
	errJSON := json.Unmarshal(body, &requestResponse)
	if errJSON != nil {
		return nil, errJSON, code
	}
	return &requestResponse, nil, code
}

// Function thats sends import key request to TSB
func (c *TSBClient) ImportKey(label string, privateKey string, publicKey string, secretKey string, certificate string, attributes map[string]bool, keytype string, policy helpers.Policy) (map[string]interface{}, error) {
	policyJson, _ := json.Marshal(policy)
	policyString := string(`,"policy":` + string(policyJson))
	var privateKeyString string
	if privateKey == "" {
		privateKeyString = ""
	} else {
		privateKeyString = `"privateKey": "` + privateKey + `",`
	}
	var publicKeyString string
	if publicKey == "" {
		publicKeyString = ""
	} else {
		publicKeyString = `"publicKey": "` + publicKey + `",`
	}
	var secretKeyString string
	if secretKey == "" {
		secretKeyString = ""
	} else {
		secretKeyString = `"secretKey": "` + secretKey + `",`
	}
	var certificateString string
	if certificate == "" {
		certificateString = ""
	} else {
		certificateString = `"certificate": "` + certificate + `",`
	}
	var jsonStr = []byte(`{
	"label": "` + label + `",
    "algorithm": "` + keytype + `",	
	` + privateKeyString + `
	` + publicKeyString + `
	` + secretKeyString + `
	` + certificateString + `
	"attributes": ` + helpers.PrepareAttributes(attributes) + policyString + `}`)

	req, err := http.NewRequest("POST", c.HostURL+"/v1/key/import/plain", bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, err
	}
	body, errRes, _ := c.doRequest(req)
	if errRes != nil {
		return nil, errRes
	}
	var response map[string]interface{}
	json.Unmarshal(body, &response)
	return response, nil

}

// Function thats sends get key attribute request to TSB
func (c *TSBClient) GetKey(label string, password string) (helpers.KeyAttributes, error) {

	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"password": ` + string(charsPasswordJson) + `,`

	}
	var jsonStr = []byte(`{
			` + passwordString + `
			"label":"` + label + `"		
		}`)

	req, err := http.NewRequest("POST", c.HostURL+"/v1/key/attributes", bytes.NewBuffer(jsonStr))
	var key helpers.KeyAttributes
	if err != nil {
		return key, err
	}
	body, errRes, _ := c.doRequest(req)
	if errRes != nil {
		return key, errRes
	}
	var response interface{}
	json.Unmarshal(body, &response)
	data := response.(map[string]interface{})
	jsonData := data["json"].(map[string]interface{})
	key.Algorithm = jsonData["algorithm"].(string)
	key.AlgorithmOid = jsonData["algorithmOid"].(string)
	key.CurveOid = ""
	if fmt.Sprintf("%T", jsonData["curveOid"]) == "string" {
		key.CurveOid = jsonData["curveOid"].(string)
	}
	key.Attributes = map[string]bool{}
	attributes := jsonData["attributes"].(map[string]interface{})
	for k, e := range attributes {
		if fmt.Sprintf("%T", e) == "bool" {
			key.Attributes[k] = e.(bool)
		}
	}
	if fmt.Sprintf("%T", jsonData["keySize"]) == "float64" {
		key.KeySize = jsonData["keySize"].(float64)
	}
	key.Xml = data["xml"].(string)
	key.XmlSignature = data["xmlSignature"].(string)
	key.AttestationKeyName = data["attestationKeyName"].(string)
	key.Label = jsonData["label"].(string)
	policyString, _ := json.Marshal(jsonData["policy"])
	json.Unmarshal(policyString, &key.Policy)
	if fmt.Sprintf("%T", jsonData["publicKey"]) == "string" {
		key.PublicKey = jsonData["publicKey"].(string)
	}
	return key, nil

}

// Function thats sends delete key request to TSB
func (c *TSBClient) RemoveKey(key helpers.KeyEntry) error {
	for _, version := range key.Versions {
		time.Sleep(500)
		req, _ := http.NewRequest("DELETE", c.HostURL+"/v1/key/"+version.KeyLabel, nil)
		c.doRequest(req)
	}

	return nil

}
func (c *TSBClient) RemoveKeyVersion(keys map[string]helpers.KeyVersion, version string) error {
	time.Sleep(500)
	req, _ := http.NewRequest("DELETE", c.HostURL+"/v1/key/"+keys[version].KeyLabel, nil)
	c.doRequest(req)

	return nil

}

// Function thats sends delete request to TSB
func (c *TSBClient) RemoveRequest(id string) error {
	req, err := http.NewRequest("DELETE", c.HostURL+"/v1/request/"+id, nil)
	if err != nil {
		return err
	}
	_, errReq, code := c.doRequest(req)
	if code == 404 || code == 500 {
		return nil
	}
	if errReq != nil {
		return errReq
	}
	return nil

}

// Function thats sends update key password request to TSB
func (c *TSBClient) UpdateKeyPassword(label string, password string, newPassword string) (string, error) {
	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	charsNewPasswordJson, _ := json.Marshal(helpers.StringToCharArray(newPassword))
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"password": ` + string(charsPasswordJson) + `,`

	}
	newPasswordString := ""
	if len(charsNewPasswordJson) > 2 {
		newPasswordString = `"newPassword": ` + string(charsNewPasswordJson) + `,`

	}
	var jsonStr = []byte(`{
			` + passwordString + newPasswordString + `
			"label": "` + label + `"
		}`)

	req, err := http.NewRequest("POST", c.HostURL+"/v1/key/changePassword", bytes.NewBuffer(jsonStr))
	if err != nil {
		return "", err
	}
	_, errRes, _ := c.doRequest(req)
	if errRes != nil {
		return "", errRes
	}
	return label, nil

}

// Function thats sends create key request to TSB
func (c *TSBClient) CreateOrUpdateKey(label string, password string, attributes map[string]bool, keytype string, keySize float64, policy *helpers.Policy, curveOid string, modify bool) (string, error) {

	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	policyJson, _ := json.Marshal(&policy)
	policyString := string(`,"policy":` + string(policyJson))
	if attributes["extractable"] {
		policyString = string(`,"policy":null`)
	}
	var keySizeAttr string
	if keySize == 0 {
		keySizeAttr = ""
	} else {
		keySizeAttr = `"keySize": ` + fmt.Sprintf("%g", keySize) + `,`
	}
	var curveOidString string
	if curveOid == "" {
		curveOidString = ""
	} else {
		curveOidString = `"curveOid": "` + curveOid + `",`
	}
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"password": ` + string(charsPasswordJson) + `,`

	}
	var jsonStr = []byte(`{
	"label": "` + label + `",
    "algorithm": "` + keytype + `",	
    ` + passwordString + `
	` + keySizeAttr + `
	` + curveOidString + `
	"attributes": ` + helpers.PrepareAttributes(attributes) + policyString + `}`)

	req, err := http.NewRequest("POST", c.HostURL+"/v1/key", bytes.NewBuffer(jsonStr))
	if err != nil {
		return "", err
	}
	body, err, _ := c.doRequest(req)
	if err != nil {
		var result map[string]interface{}
		errJSON := json.Unmarshal(body, &result)
		if errJSON != nil {
			return "", errJSON
		}
		return "", err
	}
	return label, nil
}
func (c *TSBClient) CheckConnection() (string, error) {
	req, err := http.NewRequest("GET", c.HostURL+"/v1/keystore/statistics", nil)
	if err != nil {
		return "", err
	}
	body, errReq, _ := c.doRequest(req)
	if errReq != nil {
		return string(body[:]), errReq
	}
	return string(body[:]), nil

}

// Function thats sends asynchronous unwrap request to TSB
func (c *TSBClient) AsyncUnWrap(wrappedKey string, label string, attributes map[string]bool, unwrapKeyName string, unwrapKeyPassword string, wrapMethod string, policy *helpers.Policy, customMetaData map[string]string) (string, error) {
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
	metaDataB64, metaDataSignature, err := helpers.PrepareMetaData("UnWrap", additionalMetaDataInfo, customMetaData)
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
		"attributes": ` + helpers.PrepareAttributes(attributes) + `,
		"metaData": "` + metaDataB64 + `",
		"metaDataSignature": "` + metaDataSignature + `"` + policyString + `
		}}`)
	req, err := http.NewRequest("POST", c.HostURL+"/v1/unwrap", bytes.NewBuffer(jsonStr))
	if err != nil {
		return "", err
	}
	body, errRes, _ := c.doRequest(req)
	if errRes != nil {
		return "", errRes
	}
	var result map[string]interface{}
	errJSON := json.Unmarshal(body, &result)
	if errJSON != nil {
		return "", errJSON
	}
	return result["unwrapRequestId"].(string), nil
}

// Function thats sends unwrap request to TSB
func (c *TSBClient) UnWrap(wrappedKey string, label string, attributes map[string]bool, unwrapKeyName string, unwrapKeyPassword string, wrapMethod string, policy *helpers.Policy) (string, error) {
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
		return "", err
	}
	body, err, _ := c.doRequest(req)
	if err != nil {
		var result map[string]interface{}
		errJSON := json.Unmarshal(body, &result)
		if errJSON != nil {
			return "", errJSON
		}
		return "", err
	}
	return label, nil
}

// Function that making all requests. Using config for Authorization to TSB
func (c *TSBClient) doRequest(req *http.Request) ([]byte, error, int) {
	// req.Header.Set("Authorization", c.Token)
	if c.Auth.AuthType == "TOKEN" {
		req.Header.Set("Authorization", "Bearer "+c.Auth.BearerToken)
	}
	if c.Auth.AuthType == "BASIC" {
		if c.Auth.BasicToken == "" {
			req.SetBasicAuth(c.Auth.Username, c.Auth.Password)
		} else {
			req.Header.Set("Authorization", "Basic "+(c.Auth.BasicToken))
		}
	}
	if c.Auth.AuthType == "CERT" {

		caCert, _ := ioutil.ReadFile(c.Auth.CertPath)

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		clientTLSCert, err := tls.LoadX509KeyPair(c.Auth.CertPath, c.Auth.KeyPath)
		if err != nil {
			log.Fatalf("Error loading certificate and key file: %v", err)
			return nil, err, 0
		}

		c.HTTPClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            caCertPool,
				InsecureSkipVerify: true,
				Certificates:       []tls.Certificate{clientTLSCert},
			},
		}
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err, res.StatusCode
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err, res.StatusCode
	}
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		return body, fmt.Errorf("status: %d, body: %s", res.StatusCode, body), res.StatusCode
	}

	return body, err, res.StatusCode
}
