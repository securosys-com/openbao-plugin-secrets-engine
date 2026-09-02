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
	"encoding/json"
	"errors"

	helpers "securosys.ch/helpers"
)

// securosysClient creates an object storing
// the client.
type SecurosysClient struct {
	*TSBClient
}

// newClient creates a new client to access HashiCups
func NewClient(config *helpers.SecurosysConfig) (*SecurosysClient, error) {
	if config == nil {
		return nil, errors.New("client configuration was nil")
	}
	bytes, _ := json.Marshal(config)
	var mappedConfig map[string]string
	json.Unmarshal(bytes, &mappedConfig)
	var keyPair KeyPair
	json.Unmarshal([]byte(mappedConfig["applicationKeyPair"]), &keyPair)

	var apiKeys ApiKeyTypes
	json.Unmarshal([]byte(mappedConfig["apiKeys"]), &apiKeys)
	c, err := NewTSBClient(mappedConfig["restapi"], AuthStruct{
		AuthType:           mappedConfig["auth"],
		CertPath:           mappedConfig["certpath"],
		KeyPath:            mappedConfig["keypath"],
		BearerToken:        mappedConfig["bearertoken"],
		BasicToken:         mappedConfig["basictoken"],
		Username:           mappedConfig["username"],
		Password:           mappedConfig["password"],
		ApplicationKeyPair: keyPair,
		ApiKeys:            apiKeys,
		AppName:            "HCVault Plugin Secrets Engine",
	})
	if err != nil {
		return nil, err
	}
	return &SecurosysClient{c}, nil
}
