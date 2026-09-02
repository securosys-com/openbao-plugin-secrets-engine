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
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	helpers "securosys.ch/helpers"
)

// This function provides path for update-password, modify, unblock, block etc. for a key
func pathHSMKeys(b *SecurosysBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "keys/" + framework.GenericNameRegex("name") + "/update-password",
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the key on Vault",
					Required:    true,
				},
				"password": {
					Type:        framework.TypeString,
					Description: "Key current password",
					Required:    true,
				},
				"newPassword": {
					Type:        framework.TypeString,
					Description: "Key new password",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathKeysUpdatePasswordWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathKeysUpdatePasswordWrite,
				},
			},
			HelpSynopsis:    pathKeyUpdatePasswordHelpSynopsis,
			HelpDescription: pathKeyUpdatePasswordHelpDescription,
		},
		{
			Pattern: "keys/" + framework.GenericNameRegex("name") + "/register",
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the key on Vault",
					Required:    true,
				},
				"keyLabel": {
					Type:        framework.TypeString,
					Description: "Key label from Securosys HSM (needed for register key in the Secrets Engine)",
					Required:    true,
				},
				"password": {
					Type:        framework.TypeString,
					Description: "Password of the HSM key, if the key is password protected.",
					Required:    false,
				},
				"keyTypeName": {
					Type:        framework.TypeLowerCaseString,
					Description: "Optional Vault key type name, used for keys registered from keys/type paths.",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathKeysRegisterWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathKeysRegisterWrite,
				},
			},
			HelpSynopsis:    pathKeyRegisterHelpSynopsis,
			HelpDescription: pathKeyRegisterHelpDescription,
		},
		{
			Pattern: "keys/" + framework.GenericNameRegex("name") + "/rotate",
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the key on Vault",
					Required:    true,
				},
				"password": {
					Type:        framework.TypeString,
					Description: "Key current password",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathKeysRotateWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathKeysRotateWrite,
				},
			},
			HelpSynopsis:    pathKeyRotateHelpSynopsis,
			HelpDescription: pathKeyRotateHelpDescription,
		},
		{
			Pattern: "keys/" + framework.GenericNameRegex("name") + "/block",
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the key on Vault",
					Required:    true,
				},
				"password": {
					Type:        framework.TypeString,
					Description: "Password of the block key.",
					Required:    false,
				},
				"additionalMetaData": {
					Type:        framework.TypeString,
					Description: "Additional metaData values added to request. This needs to be object json in string",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathKeysBlockWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathKeysBlockWrite,
				},
			},
			HelpSynopsis:    pathKeyBlockHelpSynopsis,
			HelpDescription: pathKeyBlockHelpDescription,
		},
		{
			Pattern: "keys/" + framework.GenericNameRegex("name") + "/unblock",
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the key on Vault",
					Required:    true,
				},
				"password": {
					Type:        framework.TypeString,
					Description: "Password of the unblock key.",
					Required:    false,
				},
				"additionalMetaData": {
					Type:        framework.TypeString,
					Description: "Additional metaData values added to request. This needs to be object json in string",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathKeysUnBlockWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathKeysUnBlockWrite,
				},
			},
			HelpSynopsis:    pathKeyUnBlockHelpSynopsis,
			HelpDescription: pathKeyUnBlockHelpDescription,
		},
		{
			Pattern: "keys/" + framework.GenericNameRegex("name") + "/export",
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the key on Vault",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathKeysExportWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathKeysExportWrite,
				},
			},
			HelpSynopsis:    pathKeyExportHelpSynopsis,
			HelpDescription: pathKeyExportHelpDescription,
		},
		{
			Pattern: "keys/" + framework.GenericNameRegex("name") + "/modify",
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the key on Vault",
					Required:    true,
				},
				"policy": {
					Type:        framework.TypeString,
					Description: "Key label for Securosys HSM",
					Required:    false,
				},
				"simplePolicy": {
					Type:        framework.TypeString,
					Description: "Key policy for Securosys HSM. JSON object format. Example {'name':'public_key', 'name2':'public_key2'}",
					Required:    false,
				},
				"additionalMetaData": {
					Type:        framework.TypeString,
					Description: "Additional metaData values added to request. This needs to be object json in string",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathKeysModifyWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathKeysModifyWrite,
				},
			},
			HelpSynopsis:    pathKeyModifyHelpSynopsis,
			HelpDescription: pathKeyModifyHelpDescription,
		},
		{
			Pattern: "keys/" + framework.GenericNameRegex("name") + "/xml",
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the key on Vault",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathKeysReadXML,
				},
			},
			HelpSynopsis:    pathKeyReadXMLHelpSynopsis,
			HelpDescription: pathKeyReadXMLHelpDescription,
		},
		{
			Pattern: "keys/" + framework.GenericNameRegex("name") + "/" + framework.GenericNameRegex("version"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the key on Vault",
					Required:    true,
				},
				"version": {
					Type:        framework.TypeLowerCaseString,
					Description: "Version of the key on Vault",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathKeyVersionRead,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathKeyVersionDelete,
				},
			},
			HelpSynopsis:    pathKeyReadDeleteVersionHelpSynopsis,
			HelpDescription: pathKeyReadDeleteVersionHelpDescription,
		},
		{
			Pattern: "keys/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the key on Vault",
					Required:    true,
				},
				"keyLabel": {
					Type:        framework.TypeString,
					Description: "Key label for Securosys HSM",
					Required:    true,
				},
				"removeFromHSM": {
					Type:        framework.TypeBool,
					Description: "Change to true if You want to remove Key from HSM",
					Default:     false,
					Required:    false,
				},
				"policy": {
					Type:        framework.TypeString,
					Description: "Key label for Securosys HSM",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathKeysRead,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathKeysDelete,
				},
			},
			HelpSynopsis:    pathKeyReadDeleteHelpSynopsis,
			HelpDescription: pathKeyReadDeleteHelpDescription,
		},
		{
			Pattern: "keys_hsm/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathKeysHSMList,
				},
			},
			HelpSynopsis:    pathKeyHSMListHelpSynopsis,
			HelpDescription: pathKeyHSMListHelpDescription,
		},
		{
			Pattern: "keys/" + framework.GenericNameRegex("name") + "/?$",
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the key on Vault",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathKeyVersionsList,
				},
			},
			HelpSynopsis:    pathKeyVersionsListHelpSynopsis,
			HelpDescription: pathKeyVersionsListHelpDescription,
		},
		{
			Pattern: "keys/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathKeysList,
				},
			},
			HelpSynopsis:    pathKeyListHelpSynopsis,
			HelpDescription: pathKeyListHelpDescription,
		},
	}
}

// This function prints lists of stored keys
func (b *SecurosysBackend) pathKeysList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.CheckKeys(ctx, req.Storage)
	entries, err := req.Storage.List(ctx, "keys/")
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(entries))
	keyInfo := make(map[string]interface{})
	for _, name := range entries {
		keys = append(keys, name)
		key, err := b.GetKey(ctx, req.Storage, name)
		if err == nil {
			configuredPolicy := "no"
			if key.Versions[key.CurrentVersion].Policy.RuleBlock != nil {
				if len(key.Versions[key.CurrentVersion].Policy.RuleBlock.Tokens) > 0 {
					for _, value := range key.Versions[key.CurrentVersion].Policy.RuleBlock.Tokens {
						if len(value.Groups) > 0 {
							configuredPolicy = "yes"
						}
					}
				}
			}
			if key.Versions[key.CurrentVersion].Policy.RuleUnBlock != nil {
				if len(key.Versions[key.CurrentVersion].Policy.RuleUnBlock.Tokens) > 0 {
					for _, value := range key.Versions[key.CurrentVersion].Policy.RuleUnBlock.Tokens {
						if len(value.Groups) > 0 {
							configuredPolicy = "yes"
						}
					}
				}
			}
			if len(key.Versions[key.CurrentVersion].Policy.RuleUse.Tokens) > 0 {
				for _, value := range key.Versions[key.CurrentVersion].Policy.RuleUse.Tokens {
					if len(value.Groups) > 0 {
						configuredPolicy = "yes"
					}
				}
			}
			if key.Versions[key.CurrentVersion].Policy.RuleModify != nil {
				if len(key.Versions[key.CurrentVersion].Policy.RuleModify.Tokens) > 0 {
					for _, value := range key.Versions[key.CurrentVersion].Policy.RuleModify.Tokens {
						if len(value.Groups) > 0 {
							configuredPolicy = "yes"
						}
					}
				}
			}
			blocked := "no"
			if key.Versions[key.CurrentVersion].Policy.KeyStatus != nil {
				if key.Versions[key.CurrentVersion].Policy.KeyStatus.Blocked == true {
					blocked = "yes"
				}
			}
			size := fmt.Sprintf("%d", int(key.KeySize))
			if size == "0" {
				size = key.CurveOid
			}
			keyInfo[name] = map[string]interface{}{
				"Algorithm":        key.Algorithm,
				"KeySize/CurveOid": size,
				"KeyLabel":         key.GetActiveVersion().KeyLabel,
				"WithPolicy":       configuredPolicy,
				"Blocked":          blocked,
				"Version":          key.CurrentVersion,
				"Created":          key.Created.Name,
				"Updated":          key.Updated.Name,
			}
		}
	}
	return logical.ListResponseWithInfo(keys, keyInfo), nil
}

// This function prints lists of stored keys
func (b *SecurosysBackend) pathKeysHSMList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	client, err := b.GetClient(ctx, req.Storage)

	if err != nil {
		return nil, err
	}
	keys, err := client.GetKeys()
	if err != nil {
		return nil, err
	}
	return logical.ListResponseWithInfo(keys, nil), nil
}

// This function prints lists of stored keys
func (b *SecurosysBackend) pathKeyVersionsList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	entry, err := b.GetKey(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, fmt.Errorf("Key with name %s not exists", d.Get("name").(string))
	}
	keys := make([]string, 0, len(entry.Versions))
	keyInfo := make(map[string]interface{})
	for key, version := range entry.Versions {
		keys = append(keys, key)
		if err == nil {
			configuredPolicy := "no"
			if version.Policy.RuleBlock != nil {
				if len(version.Policy.RuleBlock.Tokens) > 0 {
					for _, value := range version.Policy.RuleBlock.Tokens {
						if len(value.Groups) > 0 {
							configuredPolicy = "yes"
						}
					}
				}
			}
			if version.Policy.RuleUnBlock != nil {
				if len(version.Policy.RuleUnBlock.Tokens) > 0 {
					for _, value := range version.Policy.RuleUnBlock.Tokens {
						if len(value.Groups) > 0 {
							configuredPolicy = "yes"
						}
					}
				}
			}
			if len(version.Policy.RuleUse.Tokens) > 0 {
				for _, value := range version.Policy.RuleUse.Tokens {
					if len(value.Groups) > 0 {
						configuredPolicy = "yes"
					}
				}
			}
			if version.Policy.RuleModify != nil {
				if len(version.Policy.RuleModify.Tokens) > 0 {
					for _, value := range version.Policy.RuleModify.Tokens {
						if len(value.Groups) > 0 {
							configuredPolicy = "yes"
						}
					}
				}
			}
			blocked := "no"
			if version.Policy.KeyStatus != nil {
				if version.Policy.KeyStatus.Blocked == true {
					blocked = "yes"
				}
			}
			isCurrentVersion := "no"
			if entry.CurrentVersion == key {
				isCurrentVersion = "yes"
			}
			keyInfo[key] = map[string]interface{}{
				"WithPolicy": configuredPolicy,
				"Blocked":    blocked,
				"Active":     isCurrentVersion,
				"Version":    key,
				"Created":    version.Created.Name,
				"Updated":    version.Updated.Name,
			}
		}
	}
	return logical.ListResponseWithInfo(keys, keyInfo), nil
}

// This function prints lists of stored keys
func (b *SecurosysBackend) pathKeyVersionRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	entry, err := b.GetKey(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, fmt.Errorf("Key with name %s not exists", d.Get("name").(string))
	}
	version, ok := d.GetOk("version")
	if !ok {
		return logical.ErrorResponse("missing version of key"), nil
	}

	if helpers.ContainsKey(entry.Versions, version) == false {

		return logical.ErrorResponse("Version %s not exists for a key %s", version.(string), d.Get("name").(string)), nil
	}
	keyVersion := entry.Versions[version.(string)]
	return &logical.Response{
		Data: keyVersion.ToResponseData(*entry),
	}, nil
}

// This function prints single key
func (b *SecurosysBackend) pathKeysRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	entry, err := b.GetKey(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, fmt.Errorf("Key with name %s not exists", d.Get("name").(string))
	}

	return &logical.Response{
		Data: entry.ToResponseData(),
	}, nil
}

// This function prints single key XML and Signature
func (b *SecurosysBackend) pathKeysReadXML(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	entry, err := b.GetKey(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: entry.ToResponseDataXML(),
	}, nil
}

// This function exports key secret, public_key, private_key outside HSM
func (b *SecurosysBackend) pathKeysExportWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	name, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("missing key name"), nil
	}

	keyEntry, err := b.GetKey(ctx, req.Storage, name.(string))
	if err != nil {
		return nil, err
	}
	if keyEntry == nil {
		return logical.ErrorResponse("key with the name %s not exists", name.(string)), nil
	}
	client, err := b.GetClient(ctx, req.Storage)
	password, ok := d.GetOk("password")
	passwordString := ""
	if ok {
		passwordString = password.(string)
	}
	result, errPost := client.ExportKey(keyEntry.GetActiveVersion().KeyLabel, passwordString)
	if errPost != nil {
		errKeyNotExists := b.CheckIfKeyExists(ctx, req.Storage, name.(string), errPost)
		if errKeyNotExists == nil {
			return nil, errPost
		} else {
			return nil, errKeyNotExists
		}
	}

	return &logical.Response{
		Data: result,
	}, nil

}

// This function register existing key in HSM into Secrets Engine
func (b *SecurosysBackend) pathKeysRegisterWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	name, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("missing key name"), nil
	}

	keyEntry, err := b.GetKey(ctx, req.Storage, name.(string))
	if err != nil {
		return nil, err
	}
	if keyEntry != nil {
		return logical.ErrorResponse("Key with name %s already exists.", name.(string)), nil

	}

	sysView := b.System()
	keyVersion := &helpers.KeyVersion{}
	if keyEntry == nil {
		keyEntry = &helpers.KeyEntry{}
		if req.EntityID != "" {
			entity, _ := sysView.EntityInfo(req.EntityID)
			keyEntry.Created.Aliases = entity.Aliases
			keyEntry.Created.Id = entity.ID
			keyEntry.Created.Name = entity.Name
			keyVersion.Created.Aliases = entity.Aliases
			keyVersion.Created.Id = entity.ID
			keyVersion.Created.Name = entity.Name
		} else {
			keyEntry.Created.Id = "root"
			keyEntry.Created.Name = "root"
			keyEntry.Created.Aliases = nil
			keyVersion.Created.Id = "root"
			keyVersion.Created.Name = "root"
			keyVersion.Created.Aliases = nil
		}
	}
	if req.EntityID != "" {
		entity, _ := sysView.EntityInfo(req.EntityID)
		keyEntry.Updated.Aliases = entity.Aliases
		keyEntry.Updated.Id = entity.ID
		keyEntry.Updated.Name = entity.Name
		keyVersion.Updated.Aliases = entity.Aliases
		keyVersion.Updated.Id = entity.ID
		keyVersion.Updated.Name = entity.Name
	} else {
		keyEntry.Updated.Id = "root"
		keyEntry.Updated.Name = "root"
		keyEntry.Updated.Aliases = nil
		keyVersion.Updated.Aliases = nil
		keyVersion.Updated.Id = "root"
		keyVersion.Updated.Name = "root"
	}

	client, err := b.GetClient(ctx, req.Storage)
	if keylabel, ok := d.GetOk("keyLabel"); ok {
		keyEntry.BaseLabel = keylabel.(string)
	} else if !ok {
		return nil, fmt.Errorf("missing keyLabel in key")
	}
	password, ok := d.GetOk("password")
	passwordString := ""
	if ok {
		passwordString = password.(string)
	}

	key, errGet := client.GetKey(keyEntry.BaseLabel, passwordString)
	if errGet != nil {
		return nil, errGet
	}
	if !helpers.Contains(helpers.SUPPORTED_KEY_TYPES, key.Algorithm) {
		return nil, fmt.Errorf("%s algorithm is not supported!", key.Algorithm)
	}
	keyEntry.Algorithm = key.Algorithm
	keyEntry.AlgorithmOid = key.AlgorithmOid
	keyEntry.Attributes = key.Attributes
	keyEntry.BaseLabel = key.Label
	keyEntry.CurveOid = key.CurveOid
	keyEntry.KeySize = key.KeySize
	if keyTypeName, ok := d.GetOk("keyTypeName"); ok {
		keyTypeNameString := keyTypeName.(string)
		if !helpers.Contains(helpers.SUPPORTED_KEY_TYPE_NAME, keyTypeNameString) {
			return nil, fmt.Errorf("Key type name %s is not supported. Available key type names %s", keyTypeNameString, helpers.SUPPORTED_KEY_TYPE_NAME)
		}
		keyEntry.KeyTypeName = keyTypeNameString
	}

	keyVersion.Policy = key.Policy
	keyVersion.PublicKey = key.PublicKey
	keyVersion.KeyLabel = key.Label
	keyVersion.Xml = key.Xml
	keyVersion.XmlSignature = key.XmlSignature
	keyVersion.AttestationKeyName = key.AttestationKeyName
	keyVersion.Version = "v1"

	keyEntry.Versions = make(map[string]helpers.KeyVersion)
	keyEntry.CurrentVersion = "v1"
	keyEntry.Versions[keyEntry.CurrentVersion] = *keyVersion

	if err := SetKey(ctx, req.Storage, name.(string), keyEntry); err != nil {
		return nil, err
	}

	return nil, nil
}

// This function register existing key in HSM into Secrets Engine
func (b *SecurosysBackend) pathKeysRotateWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	name, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("missing key name"), nil
	}

	keyEntry, err := b.GetKey(ctx, req.Storage, name.(string))
	if err != nil {
		return nil, err
	}
	if keyEntry == nil {
		return nil, fmt.Errorf("Key with name %s not exists", name.(string))
	}

	sysView := b.System()
	keyVersion := &helpers.KeyVersion{}
	if req.EntityID != "" {
		entity, _ := sysView.EntityInfo(req.EntityID)
		keyEntry.Updated.Aliases = entity.Aliases
		keyEntry.Updated.Id = entity.ID
		keyEntry.Updated.Name = entity.Name
		keyVersion.Updated.Aliases = entity.Aliases
		keyVersion.Updated.Id = entity.ID
		keyVersion.Updated.Name = entity.Name
	} else {
		keyEntry.Updated.Id = "root"
		keyEntry.Updated.Name = "root"
		keyEntry.Updated.Aliases = nil
		keyVersion.Updated.Aliases = nil
		keyVersion.Updated.Id = "root"
		keyVersion.Updated.Name = "root"
	}

	client, err := b.GetClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	password, ok := d.GetOk("password")
	passwordString := ""
	if ok {
		passwordString = password.(string)
	}
	currentVersion := keyEntry.CurrentVersion
	currentKeyVersion := keyEntry.Versions[currentVersion]
	newVersion := helpers.GetNewVersion(currentVersion)
	baseLabel := baseHSMKeyLabel(keyEntry.BaseLabel)
	rotatedKeyLabel := baseLabel + "_" + newVersion

	switch keyEntry.Algorithm {
	case "BLS":
		keyEntry.KeySize = 0
	case "TDEA":
		keyEntry.KeySize = 0
	case "ED":
		keyEntry.CurveOid = keyEntry.AlgorithmOid
	}
	var key string
	if helpers.Contains(helpers.ASYMMETRIC_KEY_TYPES, keyEntry.Algorithm) {
		key, err = client.CreateOrUpdateKey(rotatedKeyLabel, passwordString, keyEntry.Attributes, keyEntry.Algorithm, keyEntry.KeySize, &currentKeyVersion.Policy, keyEntry.CurveOid, false)
	} else {
		key, err = client.CreateOrUpdateKey(rotatedKeyLabel, passwordString, keyEntry.Attributes, keyEntry.Algorithm, keyEntry.KeySize, nil, keyEntry.CurveOid, false)
	}
	if err != nil {
		_ = client.RemoveKey(rotatedKeyLabel)
		return nil, fmt.Errorf("error rotating key %s with HSM label %s: %w", name.(string), rotatedKeyLabel, err)
	}
	keyInfo, errGet := client.GetKey(key, passwordString)
	if errGet != nil {
		if removeErr := client.RemoveKey(rotatedKeyLabel); removeErr != nil {
			return nil, fmt.Errorf("error reading rotated key %s: %w; failed to remove rotate key %s: %v", key, errGet, rotatedKeyLabel, removeErr)
		}
		return nil, fmt.Errorf("error reading rotated key %s: %w; removed rotate key %s", key, errGet, rotatedKeyLabel)
	}

	keyEntry.CurrentVersion = newVersion
	keyEntry.BaseLabel = baseLabel
	keyVersion.Version = newVersion
	keyVersion.PublicKey = keyInfo.PublicKey
	keyVersion.Policy = keyInfo.Policy
	keyVersion.Xml = keyInfo.Xml
	keyVersion.XmlSignature = keyInfo.XmlSignature
	keyVersion.AttestationKeyName = keyInfo.AttestationKeyName
	keyVersion.KeyLabel = keyInfo.Label
	keyEntry.Versions[keyEntry.CurrentVersion] = *keyVersion

	if err := SetKey(ctx, req.Storage, name.(string), keyEntry); err != nil {
		if removeErr := client.RemoveKey(rotatedKeyLabel); removeErr != nil {
			return nil, fmt.Errorf("error saving rotated key %s: %w; failed to remove rotate key %s: %v", name.(string), err, rotatedKeyLabel, removeErr)
		}
		return nil, fmt.Errorf("error saving rotated key %s: %w; removed rotate key %s", name.(string), err, rotatedKeyLabel)
	}

	return nil, nil
}

func baseHSMKeyLabel(label string) string {
	index := strings.LastIndex(label, "_v")
	if index == -1 {
		return label
	}
	version := label[index+2:]
	if version == "" {
		return label
	}
	for _, r := range version {
		if r < '0' || r > '9' {
			return label
		}
	}
	return label[:index]
}

// This function send command to block key on HSM
func (b *SecurosysBackend) pathKeysBlockWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	name, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("missing key name"), nil
	}

	keyEntry, err := b.GetKey(ctx, req.Storage, name.(string))
	if err != nil {
		return nil, err
	}

	if keyEntry == nil {
		return logical.ErrorResponse("Key with name %s not exists", name), nil
	}

	if len(keyEntry.GetActiveVersion().Policy.RuleBlock.Tokens) > 0 {
		for _, token := range keyEntry.GetActiveVersion().Policy.RuleBlock.Tokens {
			if len(token.Groups) > 0 {
				return b.pathKeysAsyncBlockWrite(ctx, req, d)
			}
		}
	}

	client, err := b.GetClient(ctx, req.Storage)
	password, ok := d.GetOk("password")
	passwordString := ""
	if ok {
		passwordString = password.(string)
	}
	_, errGet := client.Block(keyEntry.GetActiveVersion().KeyLabel, passwordString)
	if errGet != nil {
		errKeyNotExists := b.CheckIfKeyExists(ctx, req.Storage, name.(string), errGet)
		if errKeyNotExists == nil {
			return nil, errGet
		} else {
			return nil, errKeyNotExists
		}
	}
	keyEntry.GetActiveVersion().Policy.KeyStatus.Blocked = true
	sysView := b.System()
	if req.EntityID != "" {
		entity, _ := sysView.EntityInfo(req.EntityID)
		keyEntry.Updated.Aliases = entity.Aliases
		keyEntry.Updated.Id = entity.ID
		keyEntry.Updated.Name = entity.Name
		keyEntry.Updated.Date = time.Now()
		if entry, ok := keyEntry.Versions[keyEntry.CurrentVersion]; ok {
			entry.Updated = keyEntry.Updated
			keyEntry.Versions[keyEntry.CurrentVersion] = entry

		}
	} else {
		keyEntry.Updated.Id = "root"
		keyEntry.Updated.Name = "root"
		keyEntry.Updated.Aliases = nil
		keyEntry.Updated.Date = time.Now()
		if entry, ok := keyEntry.Versions[keyEntry.CurrentVersion]; ok {
			entry.Updated = keyEntry.Updated
			keyEntry.Versions[keyEntry.CurrentVersion] = entry

		}
	}
	if err := SetKey(ctx, req.Storage, name.(string), keyEntry); err != nil {
		return nil, err
	}
	return nil, nil
}

// This function send command to block key on HSM. This command is only use, when key have a policy with Block Rule
func (b *SecurosysBackend) pathKeysAsyncBlockWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	name, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("missing key name"), nil
	}

	keyEntry, err := b.GetKey(ctx, req.Storage, name.(string))
	if err != nil {
		return nil, err
	}

	if keyEntry == nil {
		return logical.ErrorResponse("Key with name %s not exists", name), nil
	}
	client, err := b.GetClient(ctx, req.Storage)
	password, ok := d.GetOk("password")
	passwordString := ""
	if ok {
		passwordString = password.(string)
	}
	additionalMetaData, ok := d.GetOk("additionalMetaData")
	additionalMetaDataObj := map[string]string{}
	if ok {
		additionalMetaDataString := additionalMetaData.(string)
		err := json.Unmarshal([]byte(additionalMetaDataString), &additionalMetaDataObj)
		if err != nil {
			return nil, fmt.Errorf("Provided additionalMetaData is not in correct format: Json object {'key':'value'}. Error: %s", err.Error())
		}
	}
	requestId, _, errEnc := client.AsyncBlock(keyEntry.GetActiveVersion().KeyLabel, passwordString, additionalMetaDataObj)
	if errEnc != nil {
		errKeyNotExists := b.CheckIfKeyExists(ctx, req.Storage, name.(string), errEnc)
		if errKeyNotExists == nil {
			return nil, errEnc
		} else {
			return nil, errKeyNotExists
		}
	}
	if errEnc != nil {
		return nil, errEnc
	}
	var requestEntry helpers.RequestEntry
	requestResponse, _, errReq := client.GetRequest(requestId)

	if errReq != nil {

		return nil, errReq
	}
	requestEntry.Id = requestResponse.Id
	requestEntry.Type = "Block"
	requestEntry.Key = *keyEntry
	requestEntry.KeyVersion = keyEntry.CurrentVersion
	requestEntry.KeyPassword = passwordString
	requestEntry.UpdateStatus(*requestResponse)
	requestEntry.Request = make(map[string]string)
	requestEntry.Request["key"] = name.(string)
	requestEntry.Request["keyLabel"] = keyEntry.GetActiveVersion().KeyLabel
	sysView := b.System()

	if req.EntityID != "" {
		entity, _ := sysView.EntityInfo(req.EntityID)
		requestEntry.Updated.Aliases = entity.Aliases
		requestEntry.Updated.Id = entity.ID
		requestEntry.Updated.Name = entity.Name
		requestEntry.Created.Aliases = entity.Aliases
		requestEntry.Created.Id = entity.ID
		requestEntry.Created.Name = entity.Name
	} else {
		requestEntry.Updated.Id = "root"
		requestEntry.Updated.Name = "root"
		requestEntry.Updated.Aliases = nil
		requestEntry.Created.Id = "root"
		requestEntry.Created.Name = "root"
		requestEntry.Created.Aliases = nil
	}
	if entry, ok := requestEntry.Key.Versions[requestEntry.KeyVersion]; ok {
		entry.Password = passwordString
	}

	if err := setRequest(ctx, req.Storage, requestResponse.Id, &requestEntry); err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: requestEntry.ToResponseData(),
	}, nil
}

// This function send command to unblock key on HSM
func (b *SecurosysBackend) pathKeysUnBlockWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	name, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("missing key name"), nil
	}

	keyEntry, err := b.GetKey(ctx, req.Storage, name.(string))
	if err != nil {
		return nil, err
	}

	if keyEntry == nil {
		return logical.ErrorResponse("Key with name %s not exists", name), nil
	}
	if len(keyEntry.GetActiveVersion().Policy.RuleUnBlock.Tokens) > 0 {
		for _, token := range keyEntry.GetActiveVersion().Policy.RuleUnBlock.Tokens {
			if len(token.Groups) > 0 {
				return b.pathKeysAsyncUnBlockWrite(ctx, req, d)
			}
		}
	}

	client, err := b.GetClient(ctx, req.Storage)
	password, ok := d.GetOk("password")
	passwordString := ""
	if ok {
		passwordString = password.(string)
	}
	_, errGet := client.UnBlock(keyEntry.GetActiveVersion().KeyLabel, passwordString)
	if errGet != nil {
		errKeyNotExists := b.CheckIfKeyExists(ctx, req.Storage, name.(string), errGet)
		if errKeyNotExists == nil {
			return nil, errGet
		} else {
			return nil, errKeyNotExists
		}
	}
	keyEntry.GetActiveVersion().Policy.KeyStatus.Blocked = false
	sysView := b.System()
	if req.EntityID != "" {
		entity, _ := sysView.EntityInfo(req.EntityID)
		keyEntry.Updated.Aliases = entity.Aliases
		keyEntry.Updated.Id = entity.ID
		keyEntry.Updated.Name = entity.Name
		keyEntry.Updated.Date = time.Now()
		if entry, ok := keyEntry.Versions[keyEntry.CurrentVersion]; ok {
			entry.Updated = keyEntry.Updated
			keyEntry.Versions[keyEntry.CurrentVersion] = entry

		}

	} else {
		keyEntry.Updated.Id = "root"
		keyEntry.Updated.Name = "root"
		keyEntry.Updated.Aliases = nil
		keyEntry.Updated.Date = time.Now()
		if entry, ok := keyEntry.Versions[keyEntry.CurrentVersion]; ok {
			entry.Updated = keyEntry.Updated
			keyEntry.Versions[keyEntry.CurrentVersion] = entry

		}

	}
	if err := SetKey(ctx, req.Storage, name.(string), keyEntry); err != nil {
		return nil, err
	}
	return nil, nil
}

// This function send command to unblock key on HSM. This command is only use, when key have a policy with UnBlock rule
func (b *SecurosysBackend) pathKeysAsyncUnBlockWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	name, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("missing key name"), nil
	}

	keyEntry, err := b.GetKey(ctx, req.Storage, name.(string))
	if err != nil {
		return nil, err
	}

	if keyEntry == nil {
		keyEntry = &helpers.KeyEntry{}
	}

	client, err := b.GetClient(ctx, req.Storage)
	password, ok := d.GetOk("password")
	passwordString := ""
	if ok {
		passwordString = password.(string)
	}
	additionalMetaData, ok := d.GetOk("additionalMetaData")
	additionalMetaDataObj := map[string]string{}
	if ok {
		additionalMetaDataString := additionalMetaData.(string)
		err := json.Unmarshal([]byte(additionalMetaDataString), &additionalMetaDataObj)
		if err != nil {
			return nil, fmt.Errorf("Provided additionalMetaData is not in correct format: Json object {'key':'value'}. Error: %s", err.Error())
		}
	}
	requestId, _, errEnc := client.AsyncUnBlock(keyEntry.GetActiveVersion().KeyLabel, passwordString, additionalMetaDataObj)
	if errEnc != nil {
		errKeyNotExists := b.CheckIfKeyExists(ctx, req.Storage, name.(string), errEnc)
		if errKeyNotExists == nil {
			return nil, errEnc
		} else {
			return nil, errKeyNotExists
		}
	}
	var requestEntry helpers.RequestEntry
	requestResponse, _, errReq := client.GetRequest(requestId)
	if errReq != nil {
		return nil, errReq
	}
	requestEntry.Id = requestResponse.Id
	requestEntry.Type = "UnBlock"
	requestEntry.Key = *keyEntry
	requestEntry.KeyVersion = keyEntry.CurrentVersion
	requestEntry.KeyPassword = passwordString
	requestEntry.UpdateStatus(*requestResponse)
	requestEntry.Request = make(map[string]string)
	requestEntry.Request["key"] = name.(string)
	requestEntry.Request["keyLabel"] = keyEntry.GetActiveVersion().KeyLabel
	sysView := b.System()

	if req.EntityID != "" {
		entity, _ := sysView.EntityInfo(req.EntityID)
		requestEntry.Updated.Aliases = entity.Aliases
		requestEntry.Updated.Id = entity.ID
		requestEntry.Updated.Name = entity.Name
		requestEntry.Created.Aliases = entity.Aliases
		requestEntry.Created.Id = entity.ID
		requestEntry.Created.Name = entity.Name
	} else {
		requestEntry.Updated.Id = "root"
		requestEntry.Updated.Name = "root"
		requestEntry.Updated.Aliases = nil
		requestEntry.Created.Id = "root"
		requestEntry.Created.Name = "root"
		requestEntry.Created.Aliases = nil
	}
	if entry, ok := requestEntry.Key.Versions[requestEntry.KeyVersion]; ok {
		entry.Password = passwordString
	}

	if err := setRequest(ctx, req.Storage, requestResponse.Id, &requestEntry); err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: requestEntry.ToResponseData(),
	}, nil
}

// This function send command to modify key policy on HSM.
func (b *SecurosysBackend) pathKeysModifyWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	name, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("missing key name"), nil
	}

	keyEntry, err := b.GetKey(ctx, req.Storage, name.(string))
	if err != nil {
		return nil, err
	}

	if keyEntry == nil {
		return logical.ErrorResponse("Key with name %s not exists", name), nil
	}
	if len(keyEntry.GetActiveVersion().Policy.RuleModify.Tokens) > 0 {
		for _, token := range keyEntry.GetActiveVersion().Policy.RuleModify.Tokens {
			if len(token.Groups) > 0 {
				return b.pathKeysAsyncModifyWrite(ctx, req, d)
			}
		}
	}

	password, ok := d.GetOk("password")
	passwordString := ""
	if ok {
		passwordString = password.(string)
	}

	var hasPolicy bool = false
	var policy helpers.Policy
	if simplePolicy, ok := d.GetOk("simplePolicy"); ok {
		policyObj, err := helpers.PrepareFullPolicy(simplePolicy.(string), true, false)
		if err != nil {
			return nil, fmt.Errorf("Error on generating key policy from '%s' attribute: %s", "simplePolicy", err.Error())
		}
		policy = *policyObj
		hasPolicy = true
	}
	if policy, ok := d.GetOk("policy"); ok {
		policyObj, err := helpers.PrepareFullPolicy(policy.(string), false, false)
		if err != nil {
			return nil, fmt.Errorf("Error on generating key policy from '%s' attribute: %s", "simplePolicy", err.Error())
		}
		policy = *policyObj
		hasPolicy = true
	}
	if hasPolicy == false {
		policyObj, _ := helpers.PrepareFullPolicy("{}", true, false)
		policy = *policyObj
	}

	client, err := b.GetClient(ctx, req.Storage)
	_, errModify := client.Modify(keyEntry.GetActiveVersion().KeyLabel, passwordString, policy)
	if errModify != nil {
		errKeyNotExists := b.CheckIfKeyExists(ctx, req.Storage, name.(string), errModify)
		if errKeyNotExists == nil {
			return nil, errModify
		} else {
			return nil, errKeyNotExists
		}
	}
	key, errGet := client.GetKey(keyEntry.GetActiveVersion().KeyLabel, passwordString)
	if errGet != nil {
		return nil, errGet
	}
	keyEntry.Algorithm = key.Algorithm
	keyEntry.AlgorithmOid = key.AlgorithmOid
	keyEntry.CurveOid = key.CurveOid
	keyEntry.Attributes = key.Attributes
	keyEntry.BaseLabel = key.Label
	keyEntry.KeySize = key.KeySize
	if entry, ok := keyEntry.Versions[keyEntry.CurrentVersion]; ok {
		entry.PublicKey = key.PublicKey
		entry.Policy = key.Policy
		entry.Xml = key.Xml
		entry.XmlSignature = key.XmlSignature
		entry.AttestationKeyName = key.AttestationKeyName
		entry.KeyLabel = key.Label
		keyEntry.Versions[keyEntry.CurrentVersion] = entry
	}

	sysView := b.System()
	if req.EntityID != "" {
		entity, _ := sysView.EntityInfo(req.EntityID)
		keyEntry.Updated.Aliases = entity.Aliases
		keyEntry.Updated.Id = entity.ID
		keyEntry.Updated.Name = entity.Name
		if entry, ok := keyEntry.Versions[keyEntry.CurrentVersion]; ok {
			entry.Updated = keyEntry.Updated
			keyEntry.Versions[keyEntry.CurrentVersion] = entry

		}
	} else {
		keyEntry.Updated.Id = "root"
		keyEntry.Updated.Name = "root"
		keyEntry.Updated.Aliases = nil
		if entry, ok := keyEntry.Versions[keyEntry.CurrentVersion]; ok {
			entry.Updated = keyEntry.Updated
			keyEntry.Versions[keyEntry.CurrentVersion] = entry

		}
	}

	if err := SetKey(ctx, req.Storage, name.(string), keyEntry); err != nil {
		return nil, err
	}

	return nil, nil
}

// This function send command to modify key policy on HSM. This command is only use, when key have a policy with modifyRule
func (b *SecurosysBackend) pathKeysAsyncModifyWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	name, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("missing key name"), nil
	}

	keyEntry, err := b.GetKey(ctx, req.Storage, name.(string))
	if err != nil {
		return nil, err
	}

	if keyEntry == nil {
		return logical.ErrorResponse("Key with name %s not exists", name), nil
	}

	password, ok := d.GetOk("password")
	passwordString := ""
	if ok {
		passwordString = password.(string)
	}

	var hasPolicy bool = false
	var policy helpers.Policy
	if simplePolicy, ok := d.GetOk("simplePolicy"); ok {
		policyObj, err := helpers.PrepareFullPolicy(simplePolicy.(string), true, false)
		if err != nil {
			return nil, fmt.Errorf("Error on generating key policy from '%s' attribute: %s", "simplePolicy", err.Error())
		}
		policy = *policyObj
		hasPolicy = true
	}
	if policy, ok := d.GetOk("policy"); ok {
		policyObj, err := helpers.PrepareFullPolicy(policy.(string), false, false)
		if err != nil {
			return nil, fmt.Errorf("Error on generating key policy from '%s' attribute: %s", "simplePolicy", err.Error())
		}
		policy = *policyObj
		hasPolicy = true
	}
	if hasPolicy == false {
		policyObj, _ := helpers.PrepareFullPolicy("{}", true, false)
		policy = *policyObj
	}
	additionalMetaData, ok := d.GetOk("additionalMetaData")
	additionalMetaDataObj := map[string]string{}
	if ok {
		additionalMetaDataString := additionalMetaData.(string)
		err := json.Unmarshal([]byte(additionalMetaDataString), &additionalMetaDataObj)
		if err != nil {
			return nil, fmt.Errorf("Provided additionalMetaData is not in correct format: Json object {'key':'value'}. Error: %s", err.Error())
		}
	}
	client, err := b.GetClient(ctx, req.Storage)
	requestId, _, errEnc := client.AsyncModify(keyEntry.GetActiveVersion().KeyLabel, passwordString, policy, additionalMetaDataObj)
	if errEnc != nil {
		errKeyNotExists := b.CheckIfKeyExists(ctx, req.Storage, name.(string), errEnc)
		if errKeyNotExists == nil {
			return nil, errEnc
		} else {
			return nil, errKeyNotExists
		}
	}
	var requestEntry helpers.RequestEntry
	requestResponse, _, errReq := client.GetRequest(requestId)
	if errReq != nil {
		return nil, errReq
	}
	requestEntry.Id = requestResponse.Id
	requestEntry.Type = "Modify"
	requestEntry.Key = *keyEntry
	requestEntry.KeyVersion = keyEntry.CurrentVersion
	requestEntry.KeyPassword = passwordString
	requestEntry.UpdateStatus(*requestResponse)
	requestEntry.Request = make(map[string]string)
	requestEntry.Request["key"] = name.(string)
	requestEntry.Request["keyLabel"] = keyEntry.GetActiveVersion().KeyLabel
	sysView := b.System()

	if req.EntityID != "" {
		entity, _ := sysView.EntityInfo(req.EntityID)
		requestEntry.Updated.Aliases = entity.Aliases
		requestEntry.Updated.Id = entity.ID
		requestEntry.Updated.Name = entity.Name
		requestEntry.Created.Aliases = entity.Aliases
		requestEntry.Created.Id = entity.ID
		requestEntry.Created.Name = entity.Name
	} else {
		requestEntry.Updated.Id = "root"
		requestEntry.Updated.Name = "root"
		requestEntry.Updated.Aliases = nil
		requestEntry.Created.Id = "root"
		requestEntry.Created.Name = "root"
		requestEntry.Created.Aliases = nil
	}
	if entry, ok := requestEntry.Key.Versions[requestEntry.KeyVersion]; ok {
		entry.Password = passwordString
	}

	if err := setRequest(ctx, req.Storage, requestResponse.Id, &requestEntry); err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: requestEntry.ToResponseData(),
	}, nil
}

// This function send command to change/update password for key on HSM.
func (b *SecurosysBackend) pathKeysUpdatePasswordWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	name, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("missing key name"), nil
	}

	keyEntry, err := b.GetKey(ctx, req.Storage, name.(string))
	if err != nil {
		return nil, err
	}
	if keyEntry == nil {
		return logical.ErrorResponse("Key with name %s not exists", name), nil
	}
	if helpers.Contains(helpers.SYMMETRIC_KEY_TYPES, keyEntry.Algorithm) {
		return logical.ErrorResponse("Operation for %s rejected. Cannot setup password on symetric keys", name), nil
	}

	password, ok := d.GetOk("password")
	passwordString := ""
	if ok {
		passwordString = password.(string)
	} else {
		return logical.ErrorResponse("missing key password"), nil
	}
	newPassword, ok := d.GetOk("newPassword")
	newPasswordString := ""
	if ok {
		newPasswordString = newPassword.(string)
	} else {
		return logical.ErrorResponse("missing key newPassword"), nil
	}

	client, err := b.GetClient(ctx, req.Storage)
	_, errModify := client.UpdateKeyPassword(keyEntry.GetActiveVersion().KeyLabel, passwordString, newPasswordString)
	if errModify != nil {
		errKeyNotExists := b.CheckIfKeyExists(ctx, req.Storage, name.(string), errModify)
		if errKeyNotExists == nil {
			return nil, errModify
		} else {
			return nil, errKeyNotExists
		}
	}

	sysView := b.System()
	if req.EntityID != "" {
		entity, _ := sysView.EntityInfo(req.EntityID)
		keyEntry.Updated.Aliases = entity.Aliases
		keyEntry.Updated.Id = entity.ID
		keyEntry.Updated.Name = entity.Name
		if entry, ok := keyEntry.Versions[keyEntry.CurrentVersion]; ok {
			entry.Updated = keyEntry.Updated
			keyEntry.Versions[keyEntry.CurrentVersion] = entry

		}
	} else {
		keyEntry.Updated.Id = "root"
		keyEntry.Updated.Name = "root"
		keyEntry.Updated.Aliases = nil
		if entry, ok := keyEntry.Versions[keyEntry.CurrentVersion]; ok {
			entry.Updated = keyEntry.Updated
			keyEntry.Versions[keyEntry.CurrentVersion] = entry

		}
	}
	if err := SetKey(ctx, req.Storage, name.(string), keyEntry); err != nil {
		return nil, err
	}

	return nil, nil
}

// This function send command to delete key in Secrets Engine. Additionaly We can delete key on HSM as well with additional parameter
func (b *SecurosysBackend) pathKeyVersionDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	entry, errGet := b.GetKey(ctx, req.Storage, d.Get("name").(string))
	if errGet != nil {
		return nil, fmt.Errorf("error deleting securosys key: %w", errGet)
	}
	if entry == nil {
		return nil, fmt.Errorf("error deleting securosys key: key with name %s not exists", d.Get("name").(string))

	}
	if !helpers.ContainsKey(entry.Versions, d.Get("version").(string)) {
		return nil, fmt.Errorf("error deleting securosys key: key version %s not exists", d.Get("version").(string))
	}
	if entry.CurrentVersion == d.Get("version").(string) {
		return nil, fmt.Errorf("error deleting securosys key: cannot remove current active key")
	}
	client, errClient := b.GetClient(ctx, req.Storage)
	if errClient != nil {
		return nil, fmt.Errorf("error deleting securosys key: %w", errClient)

	}
	client.RemoveKeyVersion(entry.Versions, d.Get("version").(string))
	delete(entry.Versions, d.Get("version").(string))

	if err := SetKey(ctx, req.Storage, d.Get("name").(string), entry); err != nil {
		return nil, err
	}

	return nil, nil
}
func (b *SecurosysBackend) pathKeysDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	entry, errGet := b.GetKey(ctx, req.Storage, d.Get("name").(string))
	if errGet != nil {
		return nil, fmt.Errorf("error deleting securosys key: %w", errGet)
	}
	if entry == nil {
		return nil, fmt.Errorf("error deleting securosys key: key with name %s not exists", d.Get("name").(string))

	}
	removeFromHSM := d.Get("removeFromHSM")

	client, errClient := b.GetClient(ctx, req.Storage)
	if errClient != nil {
		return nil, fmt.Errorf("error deleting securosys key: %w", errClient)

	}
	if removeFromHSM.(bool) {
		client.RemoveKeyAllVersions(*entry)
	}

	err := req.Storage.Delete(ctx, "keys/"+d.Get("name").(string))
	if err != nil {
		return nil, fmt.Errorf("error deleting securosys key: %w", err)
	}

	return nil, nil
}

// This function helps with saving key in Secrets Engine
func SetKey(ctx context.Context, s logical.Storage, name string, keyEntry *helpers.KeyEntry) error {
	entry, err := logical.StorageEntryJSON("keys/"+name, keyEntry)
	if err != nil {
		return err
	}

	if entry == nil {
		return fmt.Errorf("failed to create storage entry for key")
	}

	if err := s.Put(ctx, entry); err != nil {
		return err
	}

	return nil
}

// This function helps with getting key from Secrets Engine
func (b *SecurosysBackend) GetKey(ctx context.Context, s logical.Storage, name string) (*helpers.KeyEntry, error) {
	if name == "" {
		return nil, fmt.Errorf("missing key name")
	}

	entry, err := s.Get(ctx, "keys/"+name)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	var key helpers.KeyEntry

	if err := entry.DecodeJSON(&key); err != nil {
		return nil, err
	}
	return &key, nil
}

// This function helps with saving key in Secrets Engine
func (b *SecurosysBackend) CheckKeys(ctx context.Context, s logical.Storage) {
	if s == nil {
		return
	}
	// time.Sleep(2 * time.Second)
	entries, _ := s.List(ctx, "keys/")
	client, err := b.GetClient(ctx, s)
	hsmKeys, _ := client.GetKeys()
	if err != nil {
		return
	}
	for _, name := range entries {
		key, _ := b.GetKey(ctx, s, name)
		for _, version := range key.Versions {
			exists := helpers.Contains(hsmKeys, version.KeyLabel)
			if !exists {
				delete(key.Versions, version.Version)
			}
		}
		if len(key.Versions) == 0 {
			s.Delete(ctx, "keys/"+name)
		} else {
			key.ModifyCurrentVersion()
			SetKey(ctx, s, name, key)
		}
	}
}
func (b *SecurosysBackend) CheckIfKeyExists(ctx context.Context, s logical.Storage, keyName string, tsbError error) error {
	if tsbError == nil {
		return nil
	}
	if s == nil {
		return nil
	}
	if !strings.Contains(tsbError.Error(), "res.error.key.not.existent") {
		return nil
	}
	key, _ := b.GetKey(ctx, s, keyName)
	versionRemoved := ""
	versionHSMName := ""
	for _, version := range key.Versions {
		if keyName == version.KeyLabel {
			versionRemoved = version.Version
			versionHSMName = version.KeyLabel
			delete(key.Versions, version.Version)
		}
	}
	if len(key.Versions) == 0 {
		s.Delete(ctx, "keys/"+keyName)
		return fmt.Errorf("HSM Key %s is not exists. \nSecrets engine will remove the key %s, because no version exists", versionHSMName, keyName)
	} else {
		key.ModifyCurrentVersion()
		SetKey(ctx, s, keyName, key)
		return fmt.Errorf("HSM Key %s is not exists. \nSecrets engine will remove version %s of %s. \nCurrent KeyVersion is reverted to: %s", versionHSMName, versionRemoved, keyName, key.CurrentVersion)
	}
}
