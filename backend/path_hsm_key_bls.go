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
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	helpers "securosys.ch/helpers"
)

// Paths for create BLS Keys
func pathHSM_BLSKeys(b *SecurosysBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "keys/bls/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the key on Vault",
					Required:    true,
				},
				"keyLabel": {
					Type:        framework.TypeString,
					Description: "Key label from Securosys HSM (needed for import key)",
					Required:    true,
				},
				"password": {
					Type:        framework.TypeString,
					Description: "Password of the wrap key.",
					Required:    false,
				},
				"policy": {
					Type:        framework.TypeString,
					Description: "Key policy for Securosys HSM. For this attribute You have to provide full JSON policy",
					Required:    false,
				},

				"simplePolicy": {
					Type:        framework.TypeString,
					Description: "Key policy for Securosys HSM. JSON object format. Example {'name':'public_key', 'name2':'public_key2'}",
					Required:    false,
				},
				"attributes": {
					Type:        framework.TypeString,
					Description: "The attributes of the key that should be created. At least one operation (decrypt, sign, unwrap) must be allowed (true). JSON object format. Example {'attribute1':false, 'attribute2':true}. You can setup encrypt, decrypt, verify, sign, wrap, unwrap, derive, bip32, extractable, modifiable, destroyable, sensitive and copyable",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathKeysBLSWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathKeysBLSWrite,
				},
			},
			HelpSynopsis:    pathKeyBLSHelpSynopsis,
			HelpDescription: pathKeyBLSHelpDescription,
		},
	}
}

func (b *SecurosysBackend) pathKeysBLSWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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
	if keyEntry == nil {
		keyEntry = &helpers.KeyEntry{}
		if req.EntityID != "" {
			entity, _ := sysView.EntityInfo(req.EntityID)
			keyEntry.Created.Aliases = entity.Aliases
			keyEntry.Created.Id = entity.ID
			keyEntry.Created.Name = entity.Name
		} else {
			keyEntry.Created.Id = "root"
			keyEntry.Created.Name = "root"
			keyEntry.Created.Aliases = nil
		}
	}
	keyEntry.Created.Date = time.Now()
	keyEntry.Updated.Date = keyEntry.Created.Date

	if req.EntityID != "" {
		entity, _ := sysView.EntityInfo(req.EntityID)
		keyEntry.Updated.Aliases = entity.Aliases
		keyEntry.Updated.Id = entity.ID
		keyEntry.Updated.Name = entity.Name
	} else {
		keyEntry.Updated.Id = "root"
		keyEntry.Updated.Name = "root"
		keyEntry.Updated.Aliases = nil
	}

	createOperation := (req.Operation == logical.CreateOperation)

	if keyLabel, ok := d.GetOk("keyLabel"); ok {
		keyEntry.BaseLabel = keyLabel.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing keyLabel in key")
	}
	password, ok := d.GetOk("password")
	passwordString := ""
	if ok {
		passwordString = password.(string)
	}
	if attributes, ok := d.GetOk("attributes"); ok {
		err := json.Unmarshal([]byte(attributes.(string)), &keyEntry.Attributes)
		if err != nil {
			return nil, fmt.Errorf("%s = error on decoding json: %s", "attributes", err.Error())
		}
		var counter int = 0
		val1, ok1 := keyEntry.Attributes["decrypt"]
		if !ok1 || val1 == false {
			counter = counter + 1
		}
		val2, ok2 := keyEntry.Attributes["sign"]
		if !ok2 || val2 == false {
			counter = counter + 1
		}
		val3, ok3 := keyEntry.Attributes["unwrap"]
		if !ok3 || val3 == false {
			counter = counter + 1
		}
		if counter == 3 {
			return nil, fmt.Errorf("Attributes is not valid. At least one operation (decrypt, sign, unwrap) must be allowed (true). %v", keyEntry.Attributes)
		}
		_, ok4 := keyEntry.Attributes["destroyable"]
		if !ok4 {
			keyEntry.Attributes["destroyable"] = true
		}
		_, ok5 := keyEntry.Attributes["modifiable"]
		if !ok5 {
			keyEntry.Attributes["modifiable"] = true
		}

	} else if !ok {
		return nil, fmt.Errorf("missing attributes in key")
	}
	var hasPolicy bool = false
	var policy helpers.Policy
	if simplePolicy, ok := d.GetOk("simplePolicy"); ok {
		if keyEntry.Attributes["extractable"] {
			return nil, fmt.Errorf("Error on generating key: attribute 'extractable' is set to true. You cannot use policy with this attribute")
		}
		policyObj, err := helpers.PreparePolicy(simplePolicy.(string), true)
		if err != nil {
			return nil, fmt.Errorf("Error on generating key policy from '%s' attribute: %s", "simplePolicy", err.Error())
		}
		policy = *policyObj
		hasPolicy = true
	}
	if policy, ok := d.GetOk("policy"); ok {
		if keyEntry.Attributes["extractable"] {
			return nil, fmt.Errorf("Error on generating key: attribute 'extractable' is set to true. You cannot use policy with this attribute")
		}
		policyObj, err := helpers.PreparePolicy(policy.(string), false)
		if err != nil {
			return nil, fmt.Errorf("Error on generating key policy from '%s' attribute: %s", "simplePolicy", err.Error())
		}
		policy = *policyObj
		hasPolicy = true
	}
	if hasPolicy == false {
		policyObj, _ := helpers.PreparePolicy("{}", true)
		policy = *policyObj
	}
	keyEntry.KeySize = 0
	keyEntry.Algorithm = "BLS"
	client, err := b.GetClient(ctx, req.Storage)
	_, errCrt := client.CreateOrUpdateKey(keyEntry.BaseLabel+"_v1", passwordString, keyEntry.Attributes, keyEntry.Algorithm, keyEntry.KeySize, &policy, "", false)
	if errCrt != nil {
		return nil, errCrt
	}
	key, err := client.GetKey(keyEntry.BaseLabel+"_v1", passwordString)
	if err != nil {
		return nil, err
	}
	keyEntry.Algorithm = key.Algorithm
	keyEntry.AlgorithmOid = key.AlgorithmOid
	keyEntry.Attributes = key.Attributes
	keyEntry.KeySize = key.KeySize
	keyVersion := &helpers.KeyVersion{}
	keyVersion.PublicKey = key.PublicKey
	keyVersion.Policy = key.Policy
	keyVersion.Xml = key.Xml
	keyVersion.XmlSignature = key.XmlSignature
	keyVersion.AttestationKeyName = key.AttestationKeyName
	keyVersion.KeyLabel = key.Label

	keyVersion.Created.Date = keyEntry.Created.Date
	keyVersion.Updated.Date = keyEntry.Created.Date

	if req.EntityID != "" {
		entity, _ := sysView.EntityInfo(req.EntityID)
		keyVersion.Updated.Aliases = entity.Aliases
		keyVersion.Updated.Id = entity.ID
		keyVersion.Updated.Name = entity.Name
		keyVersion.Created.Aliases = entity.Aliases
		keyVersion.Created.Id = entity.ID
		keyVersion.Created.Name = entity.Name

	} else {
		keyVersion.Updated.Id = "root"
		keyVersion.Updated.Name = "root"
		keyVersion.Updated.Aliases = nil
		keyVersion.Created.Aliases = nil
		keyVersion.Created.Id = "root"
		keyVersion.Created.Name = "root"

	}
	keyVersion.Version = "v1"

	keyEntry.Versions = make(map[string]helpers.KeyVersion)
	keyEntry.CurrentVersion = "v1"
	keyEntry.Versions[keyEntry.CurrentVersion] = *keyVersion

	if err := SetKey(ctx, req.Storage, name.(string), keyEntry); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: keyEntry.ToResponseData(),
	}, nil

}
