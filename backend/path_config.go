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

package backend

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	helpers "securosys.ch/helpers"
)

// pathConfig extends the Vault API with a `/config`
// endpoint for the backend. You can choose whether
// or not certain attributes should be displayed,
// required, and named. For example, password
// is marked as sensitive and will not be output
// when you read the configuration.
func pathConfig(b *SecurosysBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"auth": {
				Type:        framework.TypeString,
				Description: "Authorization Type for Securosys HSM. It can be NONE,TOKEN,CERT",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Auth",
					Sensitive: false,
				},
			},
			"bearertoken": {
				Type:        framework.TypeString,
				Description: "This parameter is needed if we set Auth='TOKEN'. It must contain valid Bearer Token",
				Required:    false,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "BearerToken",
					Sensitive: true,
				},
			},
			"certpath": {
				Type:        framework.TypeString,
				Description: "This parameter is needed if we set Auth='CERT'. It must contain valid local path to certificate",
				Required:    false,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "CertPath",
					Sensitive: false,
				},
			},
			"keypath": {
				Type:        framework.TypeString,
				Description: "This parameter is needed if we set Auth='CERT'. It must contain valid local path to key",
				Required:    false,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "KeyPath",
					Sensitive: false,
				},
			},
			"restapi": {
				Type:        framework.TypeString,
				Description: "This parameter must contain url address to TSB",
				Required:    false,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "RestApi",
					Sensitive: false,
				},
			},
			"applicationKeyPair": {
				Type:        framework.TypeString,
				Description: "This parameter must contain ApplicationKeyPair (RSA) to sign async requests",
				Required:    false,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "ApplicationKeyPair",
					Sensitive: false,
				},
			},
			"apiKeys": {
				Type:        framework.TypeString,
				Description: "This parameter must contain ApiKeys",
				Required:    false,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "ApiKeys",
					Sensitive: false,
				},
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigDelete,
			},
		},
		ExistenceCheck:  b.pathConfigExistenceCheck,
		HelpSynopsis:    pathConfigHelpSynopsis,
		HelpDescription: pathConfigHelpDescription,
	}
}

// pathConfigExistenceCheck verifies if the configuration exists.
func (b *SecurosysBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}

	return out != nil, nil
}

// pathConfigRead reads the configuration and outputs non-sensitive information.
func (b *SecurosysBackend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"username": config.Username,
			"restapi":  config.RestApi,
			"auth":     config.Auth,
			"certpath": config.CertPath,
		},
	}, nil
}

// pathConfigWrite updates the configuration for the backend
func (b *SecurosysBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	createOperation := (req.Operation == logical.CreateOperation)

	if config == nil {
		if !createOperation {
			return nil, errors.New("config not found during update operation")
		}
		config = new(helpers.SecurosysConfig)
	}
	if auth, ok := data.GetOk("auth"); ok {
		config.Auth = auth.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing auth in configuration")
	}
	// if config.Auth != "TOKEN" && config.Auth != "BASIC" && config.Auth != "CERT" && config.Auth != "NONE" {
	// 	return nil, fmt.Errorf("auth must have one of following values (NONE,TOKEN,BASIC,CERT)")
	// }
	if config.Auth != "TOKEN" && config.Auth != "CERT" && config.Auth != "NONE" {
		return nil, fmt.Errorf("auth must have one of following values (NONE,TOKEN,CERT)")
	}

	if bearertoken, ok := data.GetOk("bearertoken"); ok {
		config.BearerToken = bearertoken.(string)
	} else if !ok && createOperation && config.Auth == "TOKEN" {
		return nil, fmt.Errorf("missing bearertoken in configuration. It's required when You choose Auth='TOKEN'")
	}
	// if basictoken, ok := data.GetOk("basictoken"); ok {
	// 	config.BearerToken = basictoken.(string)
	// } else if !ok && createOperation && config.Auth == "BASIC" {
	// 	if username, ok := data.GetOk("username"); ok {
	// 		config.Username = username.(string)
	// 	}
	// 	if !ok && createOperation {
	// 		return nil, fmt.Errorf("missing basictoken or username and password in configuration. It's required when You choose Auth='BASIC'. You can use only BasicToken, then combination of Username and Password will be ignored")
	// 	}
	// 	if password, ok := data.GetOk("password"); ok {
	// 		config.Password = password.(string)
	// 	}
	// 	if !ok && createOperation {
	// 		return nil, fmt.Errorf("missing basictoken or username and password in configuration. It's required when You choose Auth='BASIC'. You can use only BasicToken, then combination of Username and Password will be ignored")
	// 	}
	// }

	if certpath, ok := data.GetOk("certpath"); ok {
		config.CertPath = certpath.(string)
	} else if !ok && createOperation && config.Auth == "CERT" {
		return nil, fmt.Errorf("missing certpath in configuration. It's required when You choose Auth='CERT'")
	}
	if config.Auth == "CERT" {
		_, err := os.ReadFile(config.CertPath)

		if err != nil {
			return nil, fmt.Errorf("Certpath in configuration is not valid. Error: %s", err.Error())
		}
	}
	if keypath, ok := data.GetOk("keypath"); ok {
		config.KeyPath = keypath.(string)
	} else if !ok && createOperation && config.Auth == "CERT" {
		return nil, fmt.Errorf("missing keypath in configuration. It's required when You choose Auth='CERT'")
	}
	if config.Auth == "CERT" {
		_, err := os.ReadFile(config.KeyPath)

		if err != nil {
			return nil, fmt.Errorf("Keypath in configuration is not valid. Error: %s", err.Error())
		}
	}
	if restapi, ok := data.GetOk("restapi"); ok {
		config.RestApi = restapi.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing restapi in configuration")
	}
	if applicationKeyPair, ok := data.GetOk("applicationKeyPair"); ok {
		config.ApplicationKeyPair = applicationKeyPair.(string)
	}
	if apiKeys, ok := data.GetOk("apiKeys"); ok {
		config.ApiKeys = apiKeys.(string)
	}

	entry, err := logical.StorageEntryJSON("config", config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	// reset the client so the next invocation will pick up the new configuration
	b.Reset()
	client, err := b.GetClient(ctx, req.Storage)
	body, _, err := client.CheckConnection()
	if err != nil {
		return nil, fmt.Errorf("Cannot make a connection. %s", err.Error())
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"result": "Connection successful: " + body,
		},
	}, nil

}

// pathConfigDelete removes the configuration for the backend
func (b *SecurosysBackend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "config")

	if err == nil {
		b.Reset()
	}

	return nil, err
}

func getConfig(ctx context.Context, s logical.Storage) (*helpers.SecurosysConfig, error) {
	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	config := new(helpers.SecurosysConfig)
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, fmt.Errorf("error reading root configuration: %w", err)
	}

	// return the config, we are done
	return config, nil
}
