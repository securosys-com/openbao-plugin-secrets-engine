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
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	helpers "securosys.ch/helpers"
)

// Paths for importing keys
func pathHSM_ImportKeys(b *SecurosysBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "keys/" + framework.GenericNameRegex("name") + "/import",
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
				"privateKey": {
					Type:        framework.TypeString,
					Description: "The private key to be imported. The key must be encoded in the DER format including information like the algorithm or the curve OID. Only available with asymmetric key. It has to be base64 encoded",
					Required:    false,
				},
				"publicKey": {
					Type:        framework.TypeString,
					Description: "The public key to be imported. The key must be encoded in the DER format including information like the algorithm or the curve OID. Only available with asymmetric key. It has to be base64 encoded",
					Required:    false,
				},
				"secretKey": {
					Type:        framework.TypeString,
					Description: "The secret key to be imported. Only available with symmetric key. It has to be base64 encoded",
					Required:    false,
				},
				"certificate": {
					Type:        framework.TypeString,
					Description: "Certificate that should be set to the imported key. It has to be base64 encoded",
					Required:    false,
				},
				"algorithm": {
					Type:        framework.TypeString,
					Description: "The key algorithm. It has to be [EC,ED,RSA,DSA,BLS,AES,ChaCha20,Camellia,TDEA]",
					Required:    true,
				},
				"attributes": {
					Type:        framework.TypeString,
					Description: "The attributes of the key that should be created. At least one operation (decrypt, sign, unwrap) must be allowed (true). JSON object format. Example {'attribute1':false, 'attribute2':true}. You can setup encrypt, decrypt, verify, sign, wrap, unwrap, derive, bip32, extractable, modifiable, destroyable, sensitive and copyable",
					Required:    true,
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
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathKeysImportWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathKeysImportWrite,
				},
			},
			HelpSynopsis:    pathKeyImportHelpSynopsis,
			HelpDescription: pathKeyImportHelpDescription,
		},
	}
}

func (b *SecurosysBackend) pathKeysImportWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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
			keyVersion.Created.Aliases = nil
			keyVersion.Created.Id = "root"
			keyVersion.Created.Name = "root"
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
	keyEntry.Created.Date = time.Now()
	keyEntry.Updated.Date = keyEntry.Created.Date

	createOperation := (req.Operation == logical.CreateOperation)

	if keyLabel, ok := d.GetOk("keyLabel"); ok {
		keyEntry.BaseLabel = keyLabel.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing keyLabel in key")
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
	if algorithm, ok := d.GetOk("algorithm"); ok {
		if !helpers.Contains(helpers.SUPPORTED_KEY_TYPES, algorithm.(string)) {
			return nil, fmt.Errorf("Not supported %s key algorithm. Available key algorithms %s", algorithm, helpers.SUPPORTED_KEY_TYPES)
		} else {
			keyEntry.Algorithm = algorithm.(string)
		}
	} else if !ok {
		return nil, fmt.Errorf("missing algorithm in key")
	}
	if helpers.Contains(helpers.SYMMETRIC_KEY_TYPES, keyEntry.Algorithm) {
		secretKey, ok := d.GetOk("secretKey")
		if !ok {
			return nil, fmt.Errorf("error: missing secretKey")
		}
		_, errB64 := b64.StdEncoding.DecodeString(secretKey.(string))
		if errB64 != nil {
			return nil, fmt.Errorf("error: secretKey is not valid base64 string")
		}
		keyVersion.SecretKey = secretKey.(string)
	}
	if helpers.Contains(helpers.ASYMMETRIC_KEY_TYPES, keyEntry.Algorithm) {
		privateKey, ok := d.GetOk("privateKey")
		if !ok {
			return nil, fmt.Errorf("error: missing privateKey")
		}
		_, errB64 := b64.StdEncoding.DecodeString(privateKey.(string))
		if errB64 != nil {
			return nil, fmt.Errorf("error: privateKey is not valid base64 string")
		}
		keyVersion.PrivateKey = privateKey.(string)
		publicKey, ok := d.GetOk("publicKey")
		if !ok {
			return nil, fmt.Errorf("error: missing publicKey")
		}
		_, err2B64 := b64.StdEncoding.DecodeString(publicKey.(string))
		if err2B64 != nil {
			return nil, fmt.Errorf("error: publicKey is not valid base64 string")
		}
		keyVersion.PublicKey = publicKey.(string)

	}
	var hasPolicy bool = false
	if simplePolicy, ok := d.GetOk("simplePolicy"); ok {
		if keyEntry.Attributes["extractable"] {
			return nil, fmt.Errorf("Error on generating key: attribute 'extractable' is set to true. You cannot use policy with this attribute")
		}
		policyObj, err := helpers.PreparePolicy(simplePolicy.(string), true)
		if err != nil {
			return nil, fmt.Errorf("Error on generating key policy from '%s' attribute: %s", "simplePolicy", err.Error())
		}
		keyVersion.Policy = *policyObj
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
		keyVersion.Policy = *policyObj
		hasPolicy = true
	}
	if hasPolicy == false {
		policyObj, _ := helpers.PreparePolicy("{}", true)
		keyVersion.Policy = *policyObj
	}

	client, err := b.GetClient(ctx, req.Storage)
	_, errCrt := client.ImportKey(keyEntry.BaseLabel+"_v1", keyVersion.PrivateKey, keyVersion.PublicKey, keyVersion.SecretKey, keyVersion.Certificate, keyEntry.Attributes, keyEntry.Algorithm, keyVersion.Policy)
	if errCrt != nil {
		return nil, errCrt
	}
	key, err := client.GetKey(keyEntry.BaseLabel+"_v1", "")
	if err != nil {
		return nil, err
	}
	keyEntry.Algorithm = key.Algorithm
	keyEntry.AlgorithmOid = key.AlgorithmOid
	keyEntry.Attributes = key.Attributes
	keyEntry.KeySize = key.KeySize

	keyVersion.Xml = key.Xml
	keyVersion.XmlSignature = key.XmlSignature
	keyVersion.AttestationKeyName = key.AttestationKeyName
	keyVersion.PublicKey = key.PublicKey
	keyVersion.Policy = key.Policy
	keyVersion.KeyLabel = key.Label
	keyVersion.Created.Date = keyEntry.Created.Date
	keyVersion.Updated.Date = keyEntry.Created.Date
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
