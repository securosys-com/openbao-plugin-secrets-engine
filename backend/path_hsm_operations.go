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
	"encoding/base64"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/andreburgaud/crypt2go/padding"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	helpers "securosys.ch/helpers"
)

// Paths for making operation using key like: encrypt, decrypt, sign, verify etc.
func pathOperations(b *SecurosysBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "operation/wrap/" + framework.GenericNameRegex("keyToBeWrapped") + "/" + framework.GenericNameRegex("wrappedKeyName"),
			Fields: map[string]*framework.FieldSchema{
				"keyToBeWrapped": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the key that shall be wrapped",
					Required:    true,
				},
				"wrappedKeyName": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the key with which the key shall be wrapped.",
					Required:    true,
				},
				"keyToBeWrappedPassword": {
					Type:        framework.TypeString,
					Description: "Password of the key that shall be wrapped.",
					Required:    false,
				},
				"wrapKeyPassword": {
					Type:        framework.TypeString,
					Description: "Password of the wrap key.",
					Required:    false,
				},
				"wrapMethod": {
					Type:        framework.TypeString,
					Description: "The wrap method to be used. The chosen method has to be compatible with the types of the referenced keys",
					Required:    true,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathOperationWrap,
				logical.CreateOperation: b.pathOperationWrap,
			},
			HelpSynopsis:    pathOperationsWrapHelpSyn,
			HelpDescription: pathOperationsWrapHelpDesc,
		},
		{
			Pattern: "operation/unwrap/" + framework.GenericNameRegex("unwrappedKeyName") + "/" + framework.GenericNameRegex("name") + "/" + framework.GenericNameRegex("keyVersion"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the key that used to wrap",
					Required:    true,
				},
				"keyVersion": {
					Type:        framework.TypeLowerCaseString,
					Description: "Key Version that returned in wrap request",
					Required:    true,
				},
				"unwrappedKeyName": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the key that Wee want to store",
					Required:    true,
				},
				"keyLabel": {
					Type:        framework.TypeString,
					Description: "Label for a new unwrapped key on HSM",
					Required:    true,
				},

				"wrappedKey": {
					Type:        framework.TypeString,
					Description: "The key (base64 encoded) that shall be unwrapped",
					Required:    false,
				},
				"password": {
					Type:        framework.TypeString,
					Description: "Password of the wrap key.",
					Required:    false,
				},
				"wrapMethod": {
					Type:        framework.TypeString,
					Description: "The wrap method to be used. The chosen method has to be compatible with the types of the referenced keys",
					Required:    true,
				},
				"policy": {
					Type:        framework.TypeString,
					Description: "Key policy for Securosys HSM. For this attribute You have to provide full JSON policy. Only for synchronous unwrap!",
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
				"additionalMetaData": {
					Type:        framework.TypeString,
					Description: "Additional metaData values added to request. This needs to be object json in string",
					Required:    false,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathOperationUnWrap,
				logical.CreateOperation: b.pathOperationUnWrap,
			},
			HelpSynopsis:    pathOperationsUnWrapHelpSyn,
			HelpDescription: pathOperationsUnWrapHelpDesc,
		},
		{
			Pattern: "operation/unwrap/" + framework.GenericNameRegex("unwrappedKeyName") + "/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the key that used to wrap",
					Required:    true,
				},
				"keyVersion": {
					Type:        framework.TypeString,
					Description: "Key Version that returned in wrap request",
					Required:    true,
				},
				"unwrappedKeyName": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the key that Wee want to store",
					Required:    true,
				},
				"keyLabel": {
					Type:        framework.TypeString,
					Description: "Label for a new unwrapped key on HSM",
					Required:    true,
				},

				"wrappedKey": {
					Type:        framework.TypeString,
					Description: "The key (base64 encoded) that shall be unwrapped",
					Required:    false,
				},
				"password": {
					Type:        framework.TypeString,
					Description: "Password of the wrap key.",
					Required:    false,
				},
				"wrapMethod": {
					Type:        framework.TypeString,
					Description: "The wrap method to be used. The chosen method has to be compatible with the types of the referenced keys",
					Required:    true,
				},
				"policy": {
					Type:        framework.TypeString,
					Description: "Key policy for Securosys HSM. For this attribute You have to provide full JSON policy. Only for synchronous unwrap!",
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
				"additionalMetaData": {
					Type:        framework.TypeString,
					Description: "Additional metaData values added to request. This needs to be object json in string",
					Required:    false,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathOperationUnWrap,
				logical.CreateOperation: b.pathOperationUnWrap,
			},
			HelpSynopsis:    pathOperationsUnWrapHelpSyn,
			HelpDescription: pathOperationsUnWrapHelpDesc,
		},
		{
			Pattern: "operation/sign/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the key",
					Required:    true,
				},
				"password": {
					Type:        framework.TypeString,
					Description: "Password of the sign key. If a derived key should be used for signing the key password of the master key must be specified.",
					Required:    false,
				},
				"signatureAlgorithm": {
					Type:        framework.TypeString,
					Description: "The signature algorithm to be used. The chosen algorithm has to be compatible with the type of the key referenced by the signKeyName param.",
					Required:    true,
				},
				"payload": {
					Type:        framework.TypeString,
					Description: "Payload that shall be signed. It has to be base64 encoded",
					Required:    true,
				},
				"payloadType": {
					Type:        framework.TypeString,
					Description: "The type of the payload.",
					Required:    false,
					Default:     "UNSPECIFIED",
				},
				"additionalMetaData": {
					Type:        framework.TypeString,
					Description: "Additional metaData values added to request. This needs to be object json in string",
					Required:    false,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathOperationSign,
				logical.CreateOperation: b.pathOperationSign,
			},
			HelpSynopsis:    pathOperationsSignHelpSyn,
			HelpDescription: pathOperationsSignHelpDesc,
		},
		{
			Pattern: "operation/certificate/sign/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the key",
					Required:    true,
				},
				"password": {
					Type:        framework.TypeString,
					Description: "Password of the sign key. If a derived key should be used for signing the key password of the master key must be specified.",
					Required:    false,
				},
				"signatureAlgorithm": {
					Type:        framework.TypeString,
					Description: "The signature algorithm to be used. Possible options: SHA224_WITH_RSA, SHA256_WITH_RSA, SHA384_WITH_RSA or SHA512_WITH_RSA",
					Required:    true,
				},
				"commonName": {
					Type:        framework.TypeString,
					Description: "Common Name (Subject CN) on the certificate (e.g. server FQDN or YOUR name)",
					Required:    true,
				},
				"csr": {
					Type:        framework.TypeString,
					Description: "The certificate signing request (csr).",
					Required:    true,
				},
				"certificateAuthority": {
					Type:        framework.TypeBool,
					Description: "The certificate authority: true or false",
					Required:    false,
				},
				"keyUsage": {
					Type:        framework.TypeString,
					Description: "The key usage extension defines the purpose (for example, encipherment, signature, or certificate signing) of the key contained in the certificate. If the public key is used for entity authentication, then the certificate extension should have the key usage Digital signature. This has to be array of [] enums. Possible enums: DIGITAL_SIGNATURE, CONTENT_COMMITMENT, KEY_ENCIPHERMENT, DATA_ENCIPHERMENT, KEY_AGREEMENT, KEY_CERT_SIGN, CRL_SIGN, ENCIPHER_ONLY or DECIPHER_ONLY",
					Required:    false,
					Default:     "[]",
				},
				"extendedKeyUsage": {
					Type:        framework.TypeString,
					Description: "This extension indicates one or more purposes for which the certified public key may be used, in addition to or in place of the basic purposes indicated in the key usage extension. In general, this extension will appear only in end entity certificates. This has to be array of [] enums. Possible enums: ANY_EXTENDED_KEY_USAGE, SERVER_AUTH, CLIENT_AUTH, CODE_SIGNING, EMAIL_PROTECTION, TIME_STAMPING, CRL_SIGN, OCSP_SIGNING",
					Required:    false,
					Default:     "[]",
				},
				"additionalMetaData": {
					Type:        framework.TypeString,
					Description: "Additional metaData values added to request. This needs to be object json in string",
					Required:    false,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathOperationCertificateSign,
				logical.CreateOperation: b.pathOperationCertificateSign,
			},
			HelpSynopsis:    pathOperationsCertificateSignHelpSyn,
			HelpDescription: pathOperationsCertificateSignHelpDesc,
		},
		{
			Pattern: "operation/certificate/selfsign/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the key",
					Required:    true,
				},
				"password": {
					Type:        framework.TypeString,
					Description: "Password of the sign key. If a derived key should be used for signing the key password of the master key must be specified.",
					Required:    false,
				},
				"signatureAlgorithm": {
					Type:        framework.TypeString,
					Description: "The signature algorithm to be used. Possible options: SHA224_WITH_RSA, SHA256_WITH_RSA, SHA384_WITH_RSA or SHA512_WITH_RSA",
					Required:    true,
				},
				"commonName": {
					Type:        framework.TypeString,
					Description: "Common Name (Subject CN) on the certificate (e.g. server FQDN or YOUR name)",
					Required:    true,
				},
				"validity": {
					Type:        framework.TypeInt,
					Description: "The days from today after which the certificate is not valid. e.g. 365 //valid for 1 year. Default: 365",
					Required:    true,
				},
				"certificateAuthority": {
					Type:        framework.TypeBool,
					Description: "The certificate authority: true or false",
					Required:    false,
				},
				"keyUsage": {
					Type:        framework.TypeString,
					Description: "The key usage extension defines the purpose (for example, encipherment, signature, or certificate signing) of the key contained in the certificate. If the public key is used for entity authentication, then the certificate extension should have the key usage Digital signature. This has to be array of [] enums. Possible enums: DIGITAL_SIGNATURE, CONTENT_COMMITMENT, KEY_ENCIPHERMENT, DATA_ENCIPHERMENT, KEY_AGREEMENT, KEY_CERT_SIGN, CRL_SIGN, ENCIPHER_ONLY or DECIPHER_ONLY",
					Required:    true,
					Default:     "[]",
				},
				"extendedKeyUsage": {
					Type:        framework.TypeString,
					Description: "This extension indicates one or more purposes for which the certified public key may be used, in addition to or in place of the basic purposes indicated in the key usage extension. In general, this extension will appear only in end entity certificates. This has to be array of [] enums. Possible enums: ANY_EXTENDED_KEY_USAGE, SERVER_AUTH, CLIENT_AUTH, CODE_SIGNING, EMAIL_PROTECTION, TIME_STAMPING, CRL_SIGN, OCSP_SIGNING",
					Required:    true,
					Default:     "[]",
				},
				"additionalMetaData": {
					Type:        framework.TypeString,
					Description: "Additional metaData values added to request. This needs to be object json in string",
					Required:    false,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathOperationCertificateSelfSign,
				logical.CreateOperation: b.pathOperationCertificateSelfSign,
			},
			HelpSynopsis:    pathOperationsCertificateSelfSignHelpSyn,
			HelpDescription: pathOperationsCertificateSelfSignHelpDesc,
		},
		{
			Pattern: "operation/certificate/request/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the key",
					Required:    true,
				},
				"password": {
					Type:        framework.TypeString,
					Description: "Password of the sign key. If a derived key should be used for signing the key password of the master key must be specified.",
					Required:    false,
				},
				"signatureAlgorithm": {
					Type:        framework.TypeString,
					Description: "The signature algorithm to be used. Possible options: SHA224_WITH_RSA, SHA256_WITH_RSA, SHA384_WITH_RSA or SHA512_WITH_RSA",
					Required:    true,
				},
				"certificateAttributes": {
					Type:        framework.TypeString,
					Description: "The standard attributes of X.500 series the key that should be created. At least one operation (decrypt, sign, unwrap) must be allowed (true). It has to be json object. Possible attributes: commonName, country, stateOrProvinceName, locality, organizationName, organizationUnitName, email, title, surname, givenName, initials, pseudonym, generationQualifier",
					Required:    true,
				},
				"validity": {
					Type:        framework.TypeInt,
					Description: "The days from today after which the certificate is not valid. e.g. 365 //valid for 1 year. Default: 365",
					Required:    true,
				},
				"keyUsage": {
					Type:        framework.TypeString,
					Description: "The key usage extension defines the purpose (for example, encipherment, signature, or certificate signing) of the key contained in the certificate. If the public key is used for entity authentication, then the certificate extension should have the key usage Digital signature. This has to be array of [] enums. Possible enums: DIGITAL_SIGNATURE, CONTENT_COMMITMENT, KEY_ENCIPHERMENT, DATA_ENCIPHERMENT, KEY_AGREEMENT, KEY_CERT_SIGN, CRL_SIGN, ENCIPHER_ONLY or DECIPHER_ONLY",
					Required:    false,
					Default:     "[]",
				},
				"extendedKeyUsage": {
					Type:        framework.TypeString,
					Description: "This extension indicates one or more purposes for which the certified public key may be used, in addition to or in place of the basic purposes indicated in the key usage extension. In general, this extension will appear only in end entity certificates. This has to be array of [] enums. Possible enums: ANY_EXTENDED_KEY_USAGE, SERVER_AUTH, CLIENT_AUTH, CODE_SIGNING, EMAIL_PROTECTION, TIME_STAMPING, CRL_SIGN, OCSP_SIGNING",
					Required:    false,
					Default:     "[]",
				},
				"additionalMetaData": {
					Type:        framework.TypeString,
					Description: "Additional metaData values added to request. This needs to be object json in string",
					Required:    false,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathOperationCertificateRequest,
				logical.CreateOperation: b.pathOperationCertificateRequest,
			},
			HelpSynopsis:    pathOperationsCertificateRequestHelpSyn,
			HelpDescription: pathOperationsCertificateRequestHelpDesc,
		},
		{
			Pattern: "operation/verify/" + framework.GenericNameRegex("name") + "/" + framework.GenericNameRegex("keyVersion"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the key",
					Required:    true,
				},
				"password": {
					Type:        framework.TypeString,
					Description: "The password of the master key, if the master key has a password set.",
					Required:    false,
				},
				"keyVersion": {
					Type:        framework.TypeLowerCaseString,
					Description: "Key Version that returned in sign request",
					Required:    true,
				},
				"signatureAlgorithm": {
					Type:        framework.TypeString,
					Description: "The signature algorithm that was used to sign the payload.",
					Required:    true,
				},
				"payload": {
					Type:        framework.TypeString,
					Description: "Payload for which the signature was created. It has to be base64 encoded",
					Required:    true,
				},
				"signature": {
					Type:        framework.TypeString,
					Description: "The signature to be verified.",
					Required:    false,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathOperationVerify,
				logical.CreateOperation: b.pathOperationVerify,
			},
			HelpSynopsis:    pathOperationsVerifyHelpSyn,
			HelpDescription: pathOperationsVerifyHelpDesc,
		},
		{
			Pattern: "operation/verify/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the key",
					Required:    true,
				},
				"password": {
					Type:        framework.TypeString,
					Description: "The password of the master key, if the master key has a password set.",
					Required:    false,
				},
				"keyVersion": {
					Type:        framework.TypeString,
					Description: "Key Version that returned in sign request",
					Required:    true,
				},
				"signatureAlgorithm": {
					Type:        framework.TypeString,
					Description: "The signature algorithm that was used to sign the payload.",
					Required:    true,
				},
				"payload": {
					Type:        framework.TypeString,
					Description: "Payload for which the signature was created. It has to be base64 encoded",
					Required:    true,
				},
				"signature": {
					Type:        framework.TypeString,
					Description: "The signature to be verified.",
					Required:    false,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathOperationVerify,
				logical.CreateOperation: b.pathOperationVerify,
			},
			HelpSynopsis:    pathOperationsVerifyHelpSyn,
			HelpDescription: pathOperationsVerifyHelpDesc,
		},
		{
			Pattern: "operation/encrypt/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the key",
					Required:    true,
				},
				"password": {
					Type:        framework.TypeString,
					Description: "Password of the encrypt key. This is only necessary if the key algorithm is symmetric.",
					Required:    false,
				},
				"cipherAlgorithm": {
					Type:        framework.TypeString,
					Description: "The cipher algorithm to be used.",
					Required:    true,
				},
				"tagLength": {
					Type:        framework.TypeInt,
					Description: "The MAC (Message Authentication Tag) is a fixed-length value as part of the AES-GCM encryption process, that is INCLUDED in the encryptedPayload and used to authenticatethe integrity of the data and the authenticity of the sender. Supported tag_length: 0, 64, 96, 104, 112, 120, 128",
					Required:    false,
				},
				"additionalAuthenticationData": {
					Type:        framework.TypeString,
					Description: "Additional authentication data (aad) used when decrypting payload. Can be empty if none were used when encrypting the payload",
					Required:    false,
				},
				"payload": {
					Type:        framework.TypeString,
					Description: "Payload to encrypt. It has to be base64 encoded",
					Required:    true,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathOperationEncrypt,
				logical.CreateOperation: b.pathOperationEncrypt,
			},
			HelpSynopsis:    pathOperationsEncryptHelpSyn,
			HelpDescription: pathOperationsEncryptHelpDesc,
		},
		{
			Pattern: "operation/decrypt/" + framework.GenericNameRegex("name") + "/" + framework.GenericNameRegex("keyVersion"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the key",
					Required:    true,
				},
				"password": {
					Type:        framework.TypeString,
					Description: "Password of the decrypt key. This is only necessary if the key algorithm is symmetric.",
					Required:    false,
				},
				"keyVersion": {
					Type:        framework.TypeLowerCaseString,
					Description: "Key Version that returned in encrypt request",
					Required:    true,
				},
				"cipherAlgorithm": {
					Type:        framework.TypeString,
					Description: "Cipher Algorithm",
					Required:    true,
				},
				"encryptedPayload": {
					Type:        framework.TypeString,
					Description: "Encrypted data to decrypt. It has to be base64 encoded",
					Required:    true,
				},
				"initializationVector": {
					Type:        framework.TypeString,
					Description: "The initialization vector (base64 encoded) used to encrypt the payload. Can be empty if the cipher algorithm used does not require an initialization vector.",
					Required:    false,
				},
				"additionalAuthenticationData": {
					Type:        framework.TypeString,
					Description: "Additional authentication data (aad) used when decrypting payload. Can be empty if none were used when encrypting the payload",
					Required:    false,
				},
				"tagLength": {
					Type:        framework.TypeInt,
					Description: "The MAC (Message Authentication Tag) is a fixed-length value as part of the AES-GCM encryption process, that is INCLUDED in the encryptedPayload and used to authenticatethe integrity of the data and the authenticity of the sender. Supported tag_length: 0, 64, 96, 104, 112, 120, 128",
					Required:    false,
				},
				"additionalMetaData": {
					Type:        framework.TypeString,
					Description: "Additional metaData values added to request. This needs to be object json in string",
					Required:    false,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathOperationDecrypt,
				logical.CreateOperation: b.pathOperationDecrypt,
			},
			HelpSynopsis:    pathOperationsDecryptHelpSyn,
			HelpDescription: pathOperationsDecryptHelpDesc,
		},
		{
			Pattern: "operation/decrypt/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the key",
					Required:    true,
				},
				"password": {
					Type:        framework.TypeString,
					Description: "Password of the decrypt key. This is only necessary if the key algorithm is symmetric.",
					Required:    false,
				},
				"keyVersion": {
					Type:        framework.TypeString,
					Description: "Key Version that returned in encrypt request",
					Required:    true,
				},
				"cipherAlgorithm": {
					Type:        framework.TypeString,
					Description: "Cipher Algorithm",
					Required:    true,
				},
				"encryptedPayload": {
					Type:        framework.TypeString,
					Description: "Encrypted data to decrypt. It has to be base64 encoded",
					Required:    true,
				},
				"initializationVector": {
					Type:        framework.TypeString,
					Description: "The initialization vector (base64 encoded) used to encrypt the payload. Can be empty if the cipher algorithm used does not require an initialization vector.",
					Required:    false,
				},
				"additionalAuthenticationData": {
					Type:        framework.TypeString,
					Description: "Additional authentication data (aad) used when decrypting payload. Can be empty if none were used when encrypting the payload",
					Required:    false,
				},
				"tagLength": {
					Type:        framework.TypeInt,
					Description: "The MAC (Message Authentication Tag) is a fixed-length value as part of the AES-GCM encryption process, that is INCLUDED in the encryptedPayload and used to authenticatethe integrity of the data and the authenticity of the sender. Supported tag_length: 0, 64, 96, 104, 112, 120, 128",
					Required:    false,
				},
				"additionalMetaData": {
					Type:        framework.TypeString,
					Description: "Additional metaData values added to request. This needs to be object json in string",
					Required:    false,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathOperationDecrypt,
				logical.CreateOperation: b.pathOperationDecrypt,
			},
			HelpSynopsis:    pathOperationsDecryptHelpSyn,
			HelpDescription: pathOperationsDecryptHelpDesc,
		},
	}
}

// This function sends command to HSM to unwrap key
func (b *SecurosysBackend) pathOperationUnWrap(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	keyName := d.Get("name").(string)
	keyEntry, err := b.GetKey(ctx, req.Storage, keyName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving key: %w", err)
	}
	if keyEntry == nil {
		return nil, errors.New("error retrieving key: key is nil")
	}
	keyVersion, ok := d.GetOk("keyVersion")
	if !ok {
		return nil, fmt.Errorf("error: missing keyVersion")
	}
	if !helpers.ContainsKey(keyEntry.Versions, keyVersion) {
		return nil, fmt.Errorf("Key version %s is not exists.", keyVersion)

	}
	client, err := b.GetClient(ctx, req.Storage)
	password, ok := d.GetOk("password")
	passwordString := ""
	if ok {
		passwordString = password.(string)
	}
	//checking for updates policy on hsm
	keyAttribute, err := client.GetKey(keyEntry.GetActiveVersionKeyLabel(), passwordString)
	if err != nil {
		errKeyNotExists := b.CheckIfKeyExists(ctx, req.Storage, keyName, err)
		if errKeyNotExists == nil {
			return nil, err
		} else {
			return nil, errKeyNotExists
		}
	}

	keyEntry.UpdateKeyFromHSM(keyAttribute)
	if err := SetKey(ctx, req.Storage, keyName, keyEntry); err != nil {
		return nil, err
	}

	if len(keyEntry.GetActiveVersion().Policy.RuleUse.Tokens) > 0 {
		for _, token := range keyEntry.GetActiveVersion().Policy.RuleUse.Tokens {
			if len(token.Groups) > 0 {
				return b.pathAsyncOperationUnWrap(ctx, req, d)
			}
		}
	}
	newKeyName := d.Get("unwrappedKeyName").(string)
	unwrappedKeyEntry, err := b.GetKey(ctx, req.Storage, newKeyName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving key: %w", err)
	}
	if unwrappedKeyEntry == nil {
		unwrappedKeyEntry = &helpers.KeyEntry{}
	}

	if !helpers.Contains(helpers.SUPPORTED_WRAP_KEYS, keyEntry.Algorithm) {
		return nil, fmt.Errorf("Key type %s is not supported. Available key types %s", keyEntry.Algorithm, helpers.SUPPORTED_WRAP_KEYS)
	}
	if !keyEntry.Attributes["unwrap"] {
		return nil, fmt.Errorf("Cannot use key %s with HSM label %s. Attribute unwrap is false", keyName, keyEntry.GetActiveVersion().KeyLabel)

	}
	if attributes, ok := d.GetOk("attributes"); ok {
		err := json.Unmarshal([]byte(attributes.(string)), &unwrappedKeyEntry.Attributes)
		if err != nil {
			return nil, fmt.Errorf("%s = error on decoding json: %s", "attributes", err.Error())
		}
		var counter int = 0
		val1, ok1 := unwrappedKeyEntry.Attributes["decrypt"]
		if !ok1 || val1 == false {
			counter = counter + 1
		}
		val2, ok2 := unwrappedKeyEntry.Attributes["sign"]
		if !ok2 || val2 == false {
			counter = counter + 1
		}
		val3, ok3 := unwrappedKeyEntry.Attributes["unwrap"]
		if !ok3 || val3 == false {
			counter = counter + 1
		}
		if counter == 3 {
			return nil, fmt.Errorf("Attributes is not valid. At least one operation (decrypt, sign, unwrap) must be allowed (true). %v", unwrappedKeyEntry.Attributes)
		}
		_, ok4 := unwrappedKeyEntry.Attributes["destroyable"]
		if !ok4 {
			unwrappedKeyEntry.Attributes["destroyable"] = true
		}
		_, ok5 := unwrappedKeyEntry.Attributes["modifiable"]
		if !ok5 {
			unwrappedKeyEntry.Attributes["modifiable"] = true
		}
	} else if !ok {
		return nil, fmt.Errorf("missing attributes in key")
	}
	keyLabel, ok := d.GetOk("keyLabel")
	if !ok {
		return nil, fmt.Errorf("error: missing keyLabel")
	} else {
		unwrappedKeyEntry.BaseLabel = keyLabel.(string)
	}
	wrappedKey, ok := d.GetOk("wrappedKey")
	if !ok {
		return nil, fmt.Errorf("error: missing wrappedKey")
	}
	wrapMethod, ok := d.GetOk("wrapMethod")
	if !ok {
		return nil, fmt.Errorf("error: missing wrapMethod")
	}
	if keyEntry.Algorithm == "AES" {
		if !helpers.Contains(helpers.AES_WRAP_METHODS_LIST, wrapMethod.(string)) {
			return nil, fmt.Errorf("Not supported wrap method %s for %s key type. Available wrap methods %s", wrapMethod, keyEntry.Algorithm, helpers.AES_WRAP_METHODS_LIST)
		}
	}
	if keyEntry.Algorithm == "RSA" {
		if !helpers.Contains(helpers.RSA_WRAP_METHODS_LIST, wrapMethod.(string)) {
			return nil, fmt.Errorf("Not supported wrap method %s for %s key type. Available wrap methods %s", wrapMethod, keyEntry.Algorithm, helpers.RSA_WRAP_METHODS_LIST)
		}
	}
	var hasPolicy bool = false
	var unwrappedKeyVersion helpers.KeyVersion
	if simplePolicy, ok := d.GetOk("simplePolicy"); ok {
		if unwrappedKeyEntry.Attributes["extractable"] {
			return nil, fmt.Errorf("Error on generating key: attribute 'extractable' is set to true. You cannot use policy with this attribute")
		}
		policyObj, err := helpers.PreparePolicy(simplePolicy.(string), true)
		if err != nil {
			return nil, fmt.Errorf("Error on generating key policy from '%s' attribute: %s", "simplePolicy", err.Error())
		}
		unwrappedKeyVersion.Policy = *policyObj
		hasPolicy = true
	}
	if policy, ok := d.GetOk("policy"); ok {
		if unwrappedKeyEntry.Attributes["extractable"] {
			return nil, fmt.Errorf("Error on generating key: attribute 'extractable' is set to true. You cannot use policy with this attribute")
		}
		policyObj, err := helpers.PreparePolicy(policy.(string), false)
		if err != nil {
			return nil, fmt.Errorf("Error on generating key policy from '%s' attribute: %s", "simplePolicy", err.Error())
		}
		unwrappedKeyVersion.Policy = *policyObj
		hasPolicy = true
	}
	if hasPolicy == false {
		policyObj, _ := helpers.PreparePolicy("{}", true)
		unwrappedKeyVersion.Policy = *policyObj
	}
	var errEnc error
	if hasPolicy == true {
		_, errEnc = client.UnWrap(wrappedKey.(string), unwrappedKeyEntry.BaseLabel+"_v1", unwrappedKeyEntry.Attributes, keyEntry.GetVersion(keyVersion.(string)).KeyLabel, passwordString, wrapMethod.(string), &unwrappedKeyVersion.Policy)
	} else {
		_, errEnc = client.UnWrap(wrappedKey.(string), unwrappedKeyEntry.BaseLabel+"_v1", unwrappedKeyEntry.Attributes, keyEntry.GetVersion(keyVersion.(string)).KeyLabel, passwordString, wrapMethod.(string), nil)
	}
	if errEnc != nil {
		return nil, errEnc
	}
	key, err := client.GetKey(unwrappedKeyEntry.BaseLabel+"_v1", "")
	if err != nil {
		return nil, err
	}
	unwrappedKeyVersion.Policy = key.Policy
	unwrappedKeyVersion.PublicKey = key.PublicKey
	unwrappedKeyEntry.Algorithm = key.Algorithm
	unwrappedKeyEntry.Attributes = key.Attributes
	unwrappedKeyEntry.KeySize = key.KeySize
	unwrappedKeyVersion.Xml = key.Xml
	unwrappedKeyVersion.XmlSignature = key.XmlSignature
	unwrappedKeyVersion.AttestationKeyName = key.AttestationKeyName
	unwrappedKeyVersion.KeyLabel = key.Label
	unwrappedKeyEntry.CurrentVersion = "v1"
	unwrappedKeyVersion.Version = "v1"

	sysView := b.System()
	if req.EntityID != "" {
		entity, _ := sysView.EntityInfo(req.EntityID)
		unwrappedKeyEntry.Updated.Aliases = entity.Aliases
		unwrappedKeyEntry.Updated.Id = entity.ID
		unwrappedKeyEntry.Updated.Name = entity.Name
		unwrappedKeyEntry.Created.Aliases = entity.Aliases
		unwrappedKeyEntry.Created.Id = entity.ID
		unwrappedKeyEntry.Created.Name = entity.Name
	} else {
		unwrappedKeyEntry.Updated.Id = "root"
		unwrappedKeyEntry.Updated.Name = "root"
		unwrappedKeyEntry.Updated.Aliases = nil
		unwrappedKeyEntry.Created.Aliases = nil
		unwrappedKeyEntry.Created.Id = "root"
		unwrappedKeyEntry.Created.Name = "root"
	}
	unwrappedKeyVersion.Updated = unwrappedKeyEntry.Updated
	unwrappedKeyVersion.Created = unwrappedKeyEntry.Created
	unwrappedKeyEntry.Versions = make(map[string]helpers.KeyVersion)
	unwrappedKeyEntry.Versions[unwrappedKeyEntry.CurrentVersion] = unwrappedKeyVersion

	if err := SetKey(ctx, req.Storage, newKeyName, unwrappedKeyEntry); err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: unwrappedKeyEntry.ToResponseData(),
	}, nil
}

// This function sends command to HSM to wrap key
func (b *SecurosysBackend) pathOperationWrap(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	keyToBeWrappedName := d.Get("keyToBeWrapped").(string)
	keyToBeWrappedEntry, err := b.GetKey(ctx, req.Storage, keyToBeWrappedName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving key: %w", err)
	}
	if keyToBeWrappedEntry == nil {
		return nil, errors.New("error retrieving key: key is nil")
	}
	wrapKeyName := d.Get("wrappedKeyName").(string)
	keywrapEntry, err := b.GetKey(ctx, req.Storage, wrapKeyName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving key: %w", err)
	}
	if keywrapEntry == nil {
		return nil, errors.New("error retrieving key: key is nil")
	}
	if !helpers.Contains(helpers.SUPPORTED_WRAP_KEYS, keywrapEntry.Algorithm) {
		return nil, fmt.Errorf("Key type %s is not supported. Available key types %s", keywrapEntry.Algorithm, helpers.SUPPORTED_WRAP_KEYS)
	}
	if !keywrapEntry.Attributes["unwrap"] {
		return nil, fmt.Errorf("Cannot use key %s with HSM label %s. Attribute unwrap is false", wrapKeyName, keywrapEntry.GetActiveVersion().KeyLabel)

	}
	wrapMethod, ok := d.GetOk("wrapMethod")
	if !ok {
		return nil, fmt.Errorf("error: missing wrapMethod")
	}
	if keywrapEntry.Algorithm == "AES" {
		if !helpers.Contains(helpers.AES_WRAP_METHODS_LIST, wrapMethod.(string)) {
			return nil, fmt.Errorf("Not supported wrap method %s for %s key type. Available wrap methods %s", wrapMethod, keywrapEntry.Algorithm, helpers.AES_WRAP_METHODS_LIST)
		}
		if wrapMethod.(string) == "AES_WRAP" || wrapMethod.(string) == "AES_WRAP_PAD" {
			if keyToBeWrappedEntry.Algorithm != "AES" {
				return nil, fmt.Errorf("You cannot use wrap method %s for wrapping key %s. Key to be wrapped is %s", wrapMethod.(string), keyToBeWrappedName, keyToBeWrappedEntry.Algorithm)
			}
		}
		if wrapMethod.(string) == "AES_WRAP_DSA" || wrapMethod.(string) == "AES_WRAP_PAD_DSA" {
			if keyToBeWrappedEntry.Algorithm != "DSA" {
				return nil, fmt.Errorf("You cannot use wrap method %s for wrapping key %s. Key to be wrapped is %s", wrapMethod.(string), keyToBeWrappedName, keyToBeWrappedEntry.Algorithm)
			}

		}
		if wrapMethod.(string) == "AES_WRAP_EC" || wrapMethod.(string) == "AES_WRAP_PAD_EC" {
			if keyToBeWrappedEntry.Algorithm != "EC" {
				return nil, fmt.Errorf("You cannot use wrap method %s for wrapping key %s. Key to be wrapped is %s", wrapMethod.(string), keyToBeWrappedName, keyToBeWrappedEntry.Algorithm)
			}

		}
		if wrapMethod.(string) == "AES_WRAP_ED" || wrapMethod.(string) == "AES_WRAP_PAD_ED" {

			if keyToBeWrappedEntry.Algorithm != "ED" {
				return nil, fmt.Errorf("You cannot use wrap method %s for wrapping key %s. Key to be wrapped is %s", wrapMethod.(string), keyToBeWrappedName, keyToBeWrappedEntry.Algorithm)
			}
		}
		if wrapMethod.(string) == "AES_WRAP_RSA" || wrapMethod.(string) == "AES_WRAP_PAD_RSA" {
			if keyToBeWrappedEntry.Algorithm != "RSA" {
				return nil, fmt.Errorf("You cannot use wrap method %s for wrapping key %s. Key to be wrapped is %s", wrapMethod.(string), keyToBeWrappedName, keyToBeWrappedEntry.Algorithm)
			}

		}
		if wrapMethod.(string) == "AES_WRAP_BLS" || wrapMethod.(string) == "AES_WRAP_PAD_BLS" {
			if keyToBeWrappedEntry.Algorithm != "BLS" {
				return nil, fmt.Errorf("You cannot use wrap method %s for wrapping key %s. Key to be wrapped is %s", wrapMethod.(string), keyToBeWrappedName, keyToBeWrappedEntry.Algorithm)
			}

		}
	}
	if keywrapEntry.Algorithm == "RSA" {
		if !helpers.Contains(helpers.RSA_WRAP_METHODS_LIST, wrapMethod.(string)) {
			return nil, fmt.Errorf("Not supported wrap method %s for %s key type. Available wrap methods %s", wrapMethod, keywrapEntry.Algorithm, helpers.RSA_WRAP_METHODS_LIST)
		}
		if !helpers.Contains(helpers.SYMMETRIC_KEY_TYPES, keyToBeWrappedEntry.Algorithm) {
			return nil, fmt.Errorf("You cannot use assymetric keys for %s wrap method. Your key type %s, available:%s", wrapMethod, keyToBeWrappedEntry.Algorithm, helpers.SYMMETRIC_KEY_TYPES)

		}
	}
	keyToBeWrappedPassword, ok := d.GetOk("keyToBeWrappedPassword")
	keyToBeWrappedPasswordString := ""
	if ok {
		keyToBeWrappedPasswordString = keyToBeWrappedPassword.(string)
	}
	wrapKeyPassword, ok := d.GetOk("wrapKeyPassword")
	wrapKeyPasswordString := ""
	if ok {
		wrapKeyPasswordString = wrapKeyPassword.(string)
	}
	client, err := b.GetClient(ctx, req.Storage)
	result, _, errEnc := client.Wrap(keywrapEntry.GetActiveVersion().KeyLabel, wrapKeyPasswordString, keyToBeWrappedEntry.GetActiveVersion().KeyLabel, keyToBeWrappedPasswordString, wrapMethod.(string))
	if errEnc != nil {
		errKeyNotExists := b.CheckIfKeyExists(ctx, req.Storage, wrapKeyName, errEnc)
		if errKeyNotExists == nil {
			return nil, errEnc
		} else {
			return nil, errKeyNotExists
		}
	}

	result.KeyVersion = keywrapEntry.CurrentVersion
	var inInterface map[string]interface{}
	inrec, _ := json.Marshal(result)
	json.Unmarshal(inrec, &inInterface)

	return &logical.Response{
		Data: inInterface,
	}, nil
}

// This function sends command to HSM to encrypt payload using selected key
func (b *SecurosysBackend) pathOperationEncrypt(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	keyName := d.Get("name").(string)
	keyEntry, err := b.GetKey(ctx, req.Storage, keyName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving key: %w", err)
	}
	if keyEntry == nil {
		return nil, errors.New("error retrieving key: key is nil")
	}
	if !helpers.Contains(helpers.SUPPORTED_ENCRYPT_DECRYPT_KEYS, keyEntry.Algorithm) {
		return nil, fmt.Errorf("Key type %s is not supported. Available key types %s", keyEntry.Algorithm, helpers.SUPPORTED_ENCRYPT_DECRYPT_KEYS)
	}
	if !keyEntry.Attributes["decrypt"] {
		return nil, fmt.Errorf("Cannot use key %s with HSM label %s. Attribute decrypt is false", keyName, keyEntry.GetActiveVersion().KeyLabel)

	}
	payload, ok := d.GetOk("payload")
	if !ok {
		return nil, fmt.Errorf("error: missing payload")
	}
	_, errB64 := b64.StdEncoding.DecodeString(payload.(string))
	if errB64 != nil {
		return nil, fmt.Errorf("error: payload is not valid base64 string")
	}

	cipherAlgorithm, ok := d.GetOk("cipherAlgorithm")
	if !ok && (keyEntry.KeyTypeName != "aes256-gcm96" && keyEntry.KeyTypeName != "aes128-gcm96") {
		return nil, fmt.Errorf("error: missing cipherAlgorithm")
	}
	if keyEntry.KeyTypeName == "aes256-gcm96" || keyEntry.KeyTypeName == "aes128-gcm96" {
		cipherAlgorithm = "AES_GCM"
	}
	if keyEntry.Algorithm == "AES" {
		if !helpers.Contains(helpers.AES_CIPHER_LIST, cipherAlgorithm.(string)) {
			return nil, fmt.Errorf("Not supported cipherAlgorithm %s for %s key type. Available cipher algorithms %s", cipherAlgorithm, keyEntry.Algorithm, helpers.AES_CIPHER_LIST)
		}
	}
	if keyEntry.Algorithm == "RSA" {
		if !helpers.Contains(helpers.RSA_CIPHER_LIST, cipherAlgorithm.(string)) {
			return nil, fmt.Errorf("Not supported cipherAlgorithm %s for %s key type. Available cipher algorithms %s", cipherAlgorithm, keyEntry.Algorithm, helpers.RSA_CIPHER_LIST)
		}
	}
	if keyEntry.Algorithm == "CHACHA20" {
		if !helpers.Contains(helpers.CHACHA20_CIPHER_LIST, cipherAlgorithm.(string)) {
			return nil, fmt.Errorf("Not supported cipherAlgorithm %s for %s key type. Available cipher algorithms %s", cipherAlgorithm, keyEntry.Algorithm, helpers.CHACHA20_CIPHER_LIST)
		}
	}
	if keyEntry.Algorithm == "CAMELIA" {
		if !helpers.Contains(helpers.CAMELIA_CIPHER_LIST, cipherAlgorithm.(string)) {
			return nil, fmt.Errorf("Not supported cipherAlgorithm %s for %s key type. Available cipher algorithms %s", cipherAlgorithm, keyEntry.Algorithm, helpers.CAMELIA_CIPHER_LIST)
		}
	}
	if keyEntry.Algorithm == "TDEA" {
		if !helpers.Contains(helpers.TDEA_CIPHER_LIST, cipherAlgorithm.(string)) {
			return nil, fmt.Errorf("Not supported cipherAlgorithm %s for %s key type. Available cipher algorithms %s", cipherAlgorithm, keyEntry.Algorithm, helpers.TDEA_CIPHER_LIST)
		}

	}

	if cipherAlgorithm.(string) == "AES_ECB" ||
		cipherAlgorithm.(string) == "AES_CBC_NO_PADDING" ||
		cipherAlgorithm.(string) == "CAMELLIA_ECB" ||
		cipherAlgorithm.(string) == "CAMELLIA_CBC_NO_PADDING" {
		payloadBytes, _ := base64.StdEncoding.DecodeString(payload.(string))
		padder := padding.NewPkcs7Padding(32)
		payloadBytes, _ = padder.Pad(payloadBytes)
		payload = base64.StdEncoding.EncodeToString(payloadBytes)
	}
	if cipherAlgorithm.(string) == "TDEA_CBC_NO_PADDING" ||
		cipherAlgorithm.(string) == "TDEA_ECB" {
		payloadBytes, _ := base64.StdEncoding.DecodeString(payload.(string))
		padder := padding.NewPkcs7Padding(24)
		payloadBytes, _ = padder.Pad(payloadBytes)
		payload = base64.StdEncoding.EncodeToString(payloadBytes)

	}

	password, ok := d.GetOk("password")
	passwordString := ""
	if ok {
		passwordString = password.(string)
	}
	tagLength, ok := d.GetOk("tagLength")
	tagLengthInt := -1

	if ok && (keyEntry.KeyTypeName != "aes256-gcm96" && keyEntry.KeyTypeName != "aes128-gcm96") {
		tagLengthInt = tagLength.(int)
		if tagLengthInt != -1 && keyEntry.Algorithm == "AES" && cipherAlgorithm == "AES_GCM" {
			if !helpers.Contains(helpers.SUPPORTED_TAG_LENGTH, strconv.Itoa(tagLengthInt)) {
				return nil, fmt.Errorf("Not supported tag length %s. Available tag lengths %s", strconv.Itoa(tagLengthInt), helpers.SUPPORTED_TAG_LENGTH)
			}
		}
	}
	if keyEntry.KeyTypeName == "aes256-gcm96" || keyEntry.KeyTypeName == "aes128-gcm96" {
		tagLengthInt = 96
	}

	additionalAuthenticationData, ok := d.GetOk("additionalAuthenticationData")
	additionalAuthenticationDataString := ""
	if ok {
		_, errB64 := b64.StdEncoding.DecodeString(additionalAuthenticationData.(string))
		if errB64 != nil {
			return nil, fmt.Errorf("error: additionalAuthenticationData is not valid base64 string")
		}
		additionalAuthenticationDataString = additionalAuthenticationData.(string)
	}
	client, err := b.GetClient(ctx, req.Storage)
	result, _, errEnc := client.Encrypt(keyEntry.GetActiveVersion().KeyLabel, passwordString, payload.(string), cipherAlgorithm.(string), tagLengthInt, additionalAuthenticationDataString)
	if errEnc != nil {
		errKeyNotExists := b.CheckIfKeyExists(ctx, req.Storage, keyName, errEnc)
		if errKeyNotExists == nil {
			return nil, errEnc
		} else {
			return nil, errKeyNotExists
		}
	}
	result.KeyVersion = keyEntry.CurrentVersion
	var inInterface map[string]interface{}
	inrec, _ := json.Marshal(result)
	json.Unmarshal(inrec, &inInterface)

	return &logical.Response{
		Data: inInterface,
	}, nil
}

// This function sends command to HSM to sign payload using selected key. This command is only use, when key have a policy with Use Rule
func (b *SecurosysBackend) pathAsyncOperationSign(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	keyName := d.Get("name").(string)
	keyEntry, err := b.GetKey(ctx, req.Storage, keyName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving key: %w", err)
	}
	if keyEntry == nil {
		return nil, errors.New("error retrieving key: key is nil")
	}
	if !helpers.Contains(helpers.SUPPORTED_SIGN_KEYS, keyEntry.Algorithm) {
		return nil, fmt.Errorf("Key type %s is not supported. Available key types %s", keyEntry.Algorithm, helpers.SUPPORTED_SIGN_KEYS)
	}
	if !keyEntry.Attributes["sign"] {
		return nil, fmt.Errorf("Cannot use key %s with HSM label %s. Attribute sign is false", keyName, keyEntry.GetActiveVersion().KeyLabel)

	}
	payload, ok := d.GetOk("payload")
	if !ok {
		return nil, fmt.Errorf("error: missing payload")
	}
	_, errB64 := b64.StdEncoding.DecodeString(payload.(string))
	if errB64 != nil {
		return nil, fmt.Errorf("error: payload is not valid base64 string")
	}
	payloadType, ok := d.GetOk("payloadType")
	if !ok {
		payloadType = "UNSPECIFIED"
	}
	if !helpers.Contains(helpers.SUPPORTED_PAYLOAD_TYPE, payloadType.(string)) {
		return nil, fmt.Errorf("Not supported payload type %s. Available payload types %s", payloadType, helpers.SUPPORTED_PAYLOAD_TYPE)

	}
	signatureAlgorithm, ok := d.GetOk("signatureAlgorithm")
	if !ok {
		return nil, fmt.Errorf("error: missing signatureAlgorithm")
	}
	if err := validateSignatureAlgorithmForKey(keyEntry.Algorithm, signatureAlgorithm.(string)); err != nil {
		return nil, err
	}

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
	client, err := b.GetClient(ctx, req.Storage)
	requestId, _, errEnc := client.AsyncSign(keyEntry.GetActiveVersion().KeyLabel, passwordString, payload.(string), payloadType.(string), signatureAlgorithm.(string), additionalMetaDataObj)
	if errEnc != nil {
		errKeyNotExists := b.CheckIfKeyExists(ctx, req.Storage, keyName, errEnc)
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

	requestEntry.Id = requestResponse.Id
	requestEntry.Type = "Sign"
	requestEntry.Key = *keyEntry
	requestEntry.KeyPassword = passwordString

	requestEntry.KeyVersion = keyEntry.CurrentVersion
	requestEntry.UpdateStatus(*requestResponse)
	requestEntry.Request = make(map[string]string)
	requestEntry.Request["key"] = keyName
	requestEntry.Request["keyLabel"] = keyEntry.GetActiveVersion().KeyLabel
	requestEntry.Request["payload"] = payload.(string)
	requestEntry.Request["payloadType"] = payloadType.(string)
	requestEntry.Request["signatureAlgorithm"] = signatureAlgorithm.(string)

	if err := setRequest(ctx, req.Storage, requestResponse.Id, &requestEntry); err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: requestEntry.ToResponseData(),
	}, nil
}

// This function sends command to HSM to sign payload using selected key.
func (b *SecurosysBackend) pathOperationSign(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	keyName := d.Get("name").(string)
	keyEntry, err := b.GetKey(ctx, req.Storage, keyName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving key: %w", err)
	}
	if keyEntry == nil {
		return nil, errors.New("error retrieving key: key is nil")
	}
	client, err := b.GetClient(ctx, req.Storage)
	password, ok := d.GetOk("password")
	passwordString := ""
	if ok {
		passwordString = password.(string)
	}
	//checking for updates policy on hsm
	keyAttribute, err := client.GetKey(keyEntry.GetActiveVersionKeyLabel(), passwordString)
	if err != nil {
		errKeyNotExists := b.CheckIfKeyExists(ctx, req.Storage, keyName, err)
		if errKeyNotExists == nil {
			return nil, err
		} else {
			return nil, errKeyNotExists
		}
	}

	keyEntry.UpdateKeyFromHSM(keyAttribute)
	if err := SetKey(ctx, req.Storage, keyName, keyEntry); err != nil {
		return nil, err
	}

	if len(keyEntry.GetActiveVersion().Policy.RuleUse.Tokens) > 0 {
		for _, token := range keyEntry.GetActiveVersion().Policy.RuleUse.Tokens {
			if len(token.Groups) > 0 {
				return b.pathAsyncOperationSign(ctx, req, d)
			}
		}
	}

	if !helpers.Contains(helpers.SUPPORTED_SIGN_KEYS, keyEntry.Algorithm) {
		return nil, fmt.Errorf("Key type %s is not supported. Available key types %s", keyEntry.Algorithm, helpers.SUPPORTED_SIGN_KEYS)
	}
	if !keyEntry.Attributes["sign"] {
		return nil, fmt.Errorf("Cannot use key %s with HSM label %s. Attribute sign is false", keyName, keyEntry.GetActiveVersion().KeyLabel)

	}
	payload, ok := d.GetOk("payload")
	if !ok {
		return nil, fmt.Errorf("error: missing payload")
	}
	_, errB64 := b64.StdEncoding.DecodeString(payload.(string))
	if errB64 != nil {
		return nil, fmt.Errorf("error: payload is not valid base64 string")
	}
	payloadType, ok := d.GetOk("payloadType")
	if !ok {
		payloadType = "UNSPECIFIED"
	}
	if !helpers.Contains(helpers.SUPPORTED_PAYLOAD_TYPE, payloadType.(string)) {
		return nil, fmt.Errorf("Not supported payload type %s. Available payload types %s", payloadType, helpers.SUPPORTED_PAYLOAD_TYPE)

	}
	signatureAlgorithm, ok := d.GetOk("signatureAlgorithm")
	if !ok {
		return nil, fmt.Errorf("error: missing signatureAlgorithm")
	}
	if err := validateSignatureAlgorithmForKey(keyEntry.Algorithm, signatureAlgorithm.(string)); err != nil {
		return nil, err
	}

	result, _, errEnc := client.Sign(keyEntry.GetActiveVersion().KeyLabel, passwordString, payload.(string), payloadType.(string), signatureAlgorithm.(string))
	if errEnc != nil {
		return nil, errEnc
	}
	result.KeyVersion = keyEntry.CurrentVersion
	var inInterface map[string]interface{}
	inrec, _ := json.Marshal(result)
	json.Unmarshal(inrec, &inInterface)

	return &logical.Response{
		Data: inInterface,
	}, nil
}

// This function sends command to HSM to sign certificate using selected key.
func (b *SecurosysBackend) pathOperationCertificateSign(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	keyName := d.Get("name").(string)
	keyEntry, err := b.GetKey(ctx, req.Storage, keyName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving key: %w", err)
	}
	if keyEntry == nil {
		return nil, errors.New("error retrieving key: key is nil")
	}
	client, err := b.GetClient(ctx, req.Storage)
	password, ok := d.GetOk("password")
	passwordString := ""
	if ok {
		passwordString = password.(string)
	}
	//checking for updates policy on hsm
	keyAttribute, err := client.GetKey(keyEntry.GetActiveVersionKeyLabel(), passwordString)
	if err != nil {
		errKeyNotExists := b.CheckIfKeyExists(ctx, req.Storage, keyName, err)
		if errKeyNotExists == nil {
			return nil, err
		} else {
			return nil, errKeyNotExists
		}
	}

	keyEntry.UpdateKeyFromHSM(keyAttribute)
	if err := SetKey(ctx, req.Storage, keyName, keyEntry); err != nil {
		return nil, err
	}

	if len(keyEntry.GetActiveVersion().Policy.RuleUse.Tokens) > 0 {
		for _, token := range keyEntry.GetActiveVersion().Policy.RuleUse.Tokens {
			if len(token.Groups) > 0 {
				return b.pathAsyncOperationCertificateSign(ctx, req, d)
			}
		}
	}

	if !helpers.Contains(helpers.SUPPORTED_CERTIFICATE_SIGN_KEYS, keyEntry.Algorithm) {
		return nil, fmt.Errorf("Key type %s is not supported. Available key types %s", keyEntry.Algorithm, helpers.SUPPORTED_CERTIFICATE_SIGN_KEYS)
	}
	if !keyEntry.Attributes["sign"] {
		return nil, fmt.Errorf("Cannot use key %s with HSM label %s. Attribute sign is false", keyName, keyEntry.GetActiveVersion().KeyLabel)

	}
	certificateSigningRequest, ok := d.GetOk("csr")
	if !ok {
		return nil, fmt.Errorf("error: missing csr")
	}
	commonName, ok := d.GetOk("commonName")
	if !ok {
		return nil, fmt.Errorf("error: missing commonName")
	}
	signatureAlgorithm, ok := d.GetOk("signatureAlgorithm")
	if !ok {
		return nil, fmt.Errorf("error: missing signatureAlgorithm")
	}
	if !helpers.Contains(helpers.CERTIFICATE_RSA_SIGNATURE_LIST, signatureAlgorithm.(string)) {
		return nil, fmt.Errorf("Not supported signatureAlgorithm %s for %s key type. Available certificate signature algorithms %s", signatureAlgorithm, keyEntry.Algorithm, helpers.CERTIFICATE_RSA_SIGNATURE_LIST)
	}
	certificateAuthority, ok := d.GetOk("certificateAuthority")
	certificateAuthorityBool := true
	if ok {
		certificateAuthorityBool = certificateAuthority.(bool)
	}
	keyUsage, ok := d.GetOk("keyUsage")
	keyUsageArray := []string{}
	if ok {
		json.Unmarshal([]byte(keyUsage.(string)), &keyUsageArray)
		for _, enum := range keyUsageArray {
			if !helpers.Contains(helpers.SUPPORTED_KEY_USAGE, enum) {
				return nil, fmt.Errorf("Not supported keyUsage %s. Available certificate key usage %s", enum, helpers.SUPPORTED_KEY_USAGE)
			}
		}
	}
	extendedKeyUsage, ok := d.GetOk("extendedKeyUsage")
	extendedKeyUsageArray := []string{}
	if ok {
		json.Unmarshal([]byte(extendedKeyUsage.(string)), &extendedKeyUsageArray)
		for _, enum := range extendedKeyUsageArray {
			if !helpers.Contains(helpers.SUPPORTED_EXTENDED_KEY_USAGE, enum) {
				return nil, fmt.Errorf("Not supported keyUsage %s. Available certificate key usage %s", enum, helpers.SUPPORTED_EXTENDED_KEY_USAGE)
			}
		}
	}
	result, _, errEnc := client.SignCertificate(keyEntry.GetActiveVersion().KeyLabel, passwordString, signatureAlgorithm.(string), certificateSigningRequest.(string), commonName.(string), keyUsageArray, extendedKeyUsageArray, certificateAuthorityBool)
	if errEnc != nil {
		return nil, errEnc
	}
	result.KeyVersion = keyEntry.CurrentVersion
	var inInterface map[string]interface{}
	inrec, _ := json.Marshal(result)
	json.Unmarshal(inrec, &inInterface)

	return &logical.Response{
		Data: inInterface,
	}, nil
}

// This function sends command to HSM to sign certificate using selected key. This command is only use, when key have a policy with Use Rule
func (b *SecurosysBackend) pathAsyncOperationCertificateSign(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	keyName := d.Get("name").(string)
	keyEntry, err := b.GetKey(ctx, req.Storage, keyName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving key: %w", err)
	}
	if keyEntry == nil {
		return nil, errors.New("error retrieving key: key is nil")
	}
	if !helpers.Contains(helpers.SUPPORTED_CERTIFICATE_SIGN_KEYS, keyEntry.Algorithm) {
		return nil, fmt.Errorf("Key type %s is not supported. Available key types %s", keyEntry.Algorithm, helpers.SUPPORTED_CERTIFICATE_SIGN_KEYS)
	}
	if !keyEntry.Attributes["sign"] {
		return nil, fmt.Errorf("Cannot use key %s with HSM label %s. Attribute sign is false", keyName, keyEntry.GetActiveVersion().KeyLabel)

	}
	certificateSigningRequest, ok := d.GetOk("csr")
	if !ok {
		return nil, fmt.Errorf("error: missing csr")
	}
	commonName, ok := d.GetOk("commonName")
	if !ok {
		return nil, fmt.Errorf("error: missing commonName")
	}
	signatureAlgorithm, ok := d.GetOk("signatureAlgorithm")
	if !ok {
		return nil, fmt.Errorf("error: missing signatureAlgorithm")
	}
	if !helpers.Contains(helpers.CERTIFICATE_RSA_SIGNATURE_LIST, signatureAlgorithm.(string)) {
		return nil, fmt.Errorf("Not supported signatureAlgorithm %s for %s key type. Available certificate signature algorithms %s", signatureAlgorithm, keyEntry.Algorithm, helpers.CERTIFICATE_RSA_SIGNATURE_LIST)
	}
	password, ok := d.GetOk("password")
	passwordString := ""
	if ok {
		passwordString = password.(string)
	}
	certificateAuthority, ok := d.GetOk("certificateAuthority")
	certificateAuthorityBool := true
	if ok {
		certificateAuthorityBool = certificateAuthority.(bool)
	}
	keyUsage, ok := d.GetOk("keyUsage")
	keyUsageArray := []string{}
	if ok {
		json.Unmarshal([]byte(keyUsage.(string)), &keyUsageArray)
		for _, enum := range keyUsageArray {
			if !helpers.Contains(helpers.SUPPORTED_KEY_USAGE, enum) {
				return nil, fmt.Errorf("Not supported keyUsage %s. Available certificate key usage %s", enum, helpers.SUPPORTED_KEY_USAGE)
			}
		}
	}
	extendedKeyUsage, ok := d.GetOk("extendedKeyUsage")
	extendedKeyUsageArray := []string{}
	if ok {
		json.Unmarshal([]byte(extendedKeyUsage.(string)), &extendedKeyUsageArray)
		for _, enum := range extendedKeyUsageArray {
			if !helpers.Contains(helpers.SUPPORTED_EXTENDED_KEY_USAGE, enum) {
				return nil, fmt.Errorf("Not supported keyUsage %s. Available certificate key usage %s", enum, helpers.SUPPORTED_EXTENDED_KEY_USAGE)
			}
		}
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
	requestId, _, errEnc := client.AsyncSignCertificate(keyEntry.GetActiveVersion().KeyLabel, passwordString, signatureAlgorithm.(string), certificateSigningRequest.(string), commonName.(string), keyUsageArray, extendedKeyUsageArray, certificateAuthorityBool, additionalMetaDataObj)
	if errEnc != nil {
		errKeyNotExists := b.CheckIfKeyExists(ctx, req.Storage, keyName, errEnc)
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

	requestEntry.Id = requestResponse.Id
	requestEntry.Type = "CertificateSign"
	requestEntry.Key = *keyEntry
	requestEntry.KeyPassword = passwordString

	requestEntry.KeyVersion = keyEntry.CurrentVersion
	requestEntry.UpdateStatus(*requestResponse)
	requestEntry.Request = make(map[string]string)
	requestEntry.Request["key"] = keyName
	requestEntry.Request["keyLabel"] = keyEntry.GetActiveVersion().KeyLabel
	requestEntry.Request["commonName"] = commonName.(string)
	requestEntry.Request["csr"] = certificateAuthority.(string)
	requestEntry.Request["signatureAlgorithm"] = signatureAlgorithm.(string)
	requestEntry.Request["certificateAuthorityBool"] = strconv.FormatBool(certificateAuthorityBool)
	requestEntry.Request["keyUsage"] = strings.Join(keyUsageArray[:], ", ")
	requestEntry.Request["extendedKeyUsage"] = strings.Join(extendedKeyUsageArray[:], ", ")

	if err := setRequest(ctx, req.Storage, requestResponse.Id, &requestEntry); err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: requestEntry.ToResponseData(),
	}, nil
}

// This function sends command to HSM to self sign certificate using selected key.
func (b *SecurosysBackend) pathOperationCertificateSelfSign(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	keyName := d.Get("name").(string)
	keyEntry, err := b.GetKey(ctx, req.Storage, keyName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving key: %w", err)
	}
	if keyEntry == nil {
		return nil, errors.New("error retrieving key: key is nil")
	}
	client, err := b.GetClient(ctx, req.Storage)
	password, ok := d.GetOk("password")
	passwordString := ""
	if ok {
		passwordString = password.(string)
	}
	//checking for updates policy on hsm
	keyAttribute, err := client.GetKey(keyEntry.GetActiveVersionKeyLabel(), passwordString)
	if err != nil {
		errKeyNotExists := b.CheckIfKeyExists(ctx, req.Storage, keyName, err)
		if errKeyNotExists == nil {
			return nil, err
		} else {
			return nil, errKeyNotExists
		}
	}

	keyEntry.UpdateKeyFromHSM(keyAttribute)
	if err := SetKey(ctx, req.Storage, keyName, keyEntry); err != nil {
		return nil, err
	}

	if len(keyEntry.GetActiveVersion().Policy.RuleUse.Tokens) > 0 {
		for _, token := range keyEntry.GetActiveVersion().Policy.RuleUse.Tokens {
			if len(token.Groups) > 0 {
				return b.pathAsyncOperationCertificateSelfSign(ctx, req, d)
			}
		}
	}

	if !helpers.Contains(helpers.SUPPORTED_CERTIFICATE_SIGN_KEYS, keyEntry.Algorithm) {
		return nil, fmt.Errorf("Key type %s is not supported. Available key types %s", keyEntry.Algorithm, helpers.SUPPORTED_CERTIFICATE_SIGN_KEYS)
	}
	if !keyEntry.Attributes["sign"] {
		return nil, fmt.Errorf("Cannot use key %s with HSM label %s. Attribute sign is false", keyName, keyEntry.GetActiveVersion().KeyLabel)

	}
	validity, ok := d.GetOk("validity")
	validityInt := 365
	if ok {
		validityInt = validity.(int)
	}
	commonName, ok := d.GetOk("commonName")
	if !ok {
		return nil, fmt.Errorf("error: missing commonName")
	}
	signatureAlgorithm, ok := d.GetOk("signatureAlgorithm")
	if !ok {
		return nil, fmt.Errorf("error: missing signatureAlgorithm")
	}
	if !helpers.Contains(helpers.CERTIFICATE_RSA_SIGNATURE_LIST, signatureAlgorithm.(string)) {
		return nil, fmt.Errorf("Not supported signatureAlgorithm %s for %s key type. Available certificate signature algorithms %s", signatureAlgorithm, keyEntry.Algorithm, helpers.CERTIFICATE_RSA_SIGNATURE_LIST)
	}
	certificateAuthority, ok := d.GetOk("certificateAuthority")
	certificateAuthorityBool := true
	if ok {
		certificateAuthorityBool = certificateAuthority.(bool)
	}
	keyUsage, ok := d.GetOk("keyUsage")
	keyUsageArray := []string{}
	if ok {
		json.Unmarshal([]byte(keyUsage.(string)), &keyUsageArray)
		if len(keyUsageArray) == 0 {
			return nil, fmt.Errorf("Not provided any of keyUsage attribute. Supported attributes: %s", helpers.SUPPORTED_KEY_USAGE)
		}
		for _, enum := range keyUsageArray {
			if !helpers.Contains(helpers.SUPPORTED_KEY_USAGE, enum) {
				return nil, fmt.Errorf("Not supported keyUsage %s. Available certificate key usage %s", enum, helpers.SUPPORTED_KEY_USAGE)
			}
		}
	}
	extendedKeyUsage, ok := d.GetOk("extendedKeyUsage")
	extendedKeyUsageArray := []string{}
	if ok {
		json.Unmarshal([]byte(extendedKeyUsage.(string)), &extendedKeyUsageArray)
		if len(extendedKeyUsageArray) == 0 {
			return nil, fmt.Errorf("Not provided any of extendedKeyUsage attribute. Supported attributes: %s", helpers.SUPPORTED_EXTENDED_KEY_USAGE)
		}
		for _, enum := range extendedKeyUsageArray {
			if !helpers.Contains(helpers.SUPPORTED_EXTENDED_KEY_USAGE, enum) {
				return nil, fmt.Errorf("Not supported extendedKeyUsage %s. Available certificate key usage %s", enum, helpers.SUPPORTED_EXTENDED_KEY_USAGE)
			}
		}
	}
	result, _, errEnc := client.CreateSelfSignedCertificate(keyEntry.GetActiveVersion().KeyLabel, passwordString, signatureAlgorithm.(string), validityInt, commonName.(string), keyUsageArray, extendedKeyUsageArray, certificateAuthorityBool)
	if errEnc != nil {
		return nil, errEnc
	}
	result.KeyVersion = keyEntry.CurrentVersion
	var inInterface map[string]interface{}
	inrec, _ := json.Marshal(result)
	json.Unmarshal(inrec, &inInterface)

	return &logical.Response{
		Data: inInterface,
	}, nil
}

// This function sends command to HSM to self sign certificate using selected key. This command is only use, when key have a policy with Use Rule
func (b *SecurosysBackend) pathAsyncOperationCertificateSelfSign(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	keyName := d.Get("name").(string)
	keyEntry, err := b.GetKey(ctx, req.Storage, keyName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving key: %w", err)
	}
	if keyEntry == nil {
		return nil, errors.New("error retrieving key: key is nil")
	}
	if !helpers.Contains(helpers.SUPPORTED_CERTIFICATE_SIGN_KEYS, keyEntry.Algorithm) {
		return nil, fmt.Errorf("Key type %s is not supported. Available key types %s", keyEntry.Algorithm, helpers.SUPPORTED_CERTIFICATE_SIGN_KEYS)
	}
	if !keyEntry.Attributes["sign"] {
		return nil, fmt.Errorf("Cannot use key %s with HSM label %s. Attribute sign is false", keyName, keyEntry.GetActiveVersion().KeyLabel)

	}
	validity, ok := d.GetOk("validity")
	validityInt := 365
	if !ok {
		validityInt = validity.(int)
	}
	commonName, ok := d.GetOk("commonName")
	if !ok {
		return nil, fmt.Errorf("error: missing commonName")
	}
	signatureAlgorithm, ok := d.GetOk("signatureAlgorithm")
	if !ok {
		return nil, fmt.Errorf("error: missing signatureAlgorithm")
	}
	if !helpers.Contains(helpers.CERTIFICATE_RSA_SIGNATURE_LIST, signatureAlgorithm.(string)) {
		return nil, fmt.Errorf("Not supported signatureAlgorithm %s for %s key type. Available certificate signature algorithms %s", signatureAlgorithm, keyEntry.Algorithm, helpers.CERTIFICATE_RSA_SIGNATURE_LIST)
	}
	password, ok := d.GetOk("password")
	passwordString := ""
	if ok {
		passwordString = password.(string)
	}
	certificateAuthority, ok := d.GetOk("certificateAuthority")
	certificateAuthorityBool := true
	if ok {
		certificateAuthorityBool = certificateAuthority.(bool)
	}
	keyUsage, ok := d.GetOk("keyUsage")
	keyUsageArray := []string{}
	if ok {
		json.Unmarshal([]byte(keyUsage.(string)), &keyUsageArray)
		if len(keyUsageArray) == 0 {
			return nil, fmt.Errorf("Not provided any of keyUsage attribute. Supported attributes: %s", helpers.SUPPORTED_KEY_USAGE)
		}
		for _, enum := range keyUsageArray {
			if !helpers.Contains(helpers.SUPPORTED_KEY_USAGE, enum) {
				return nil, fmt.Errorf("Not supported keyUsage %s. Available certificate key usage %s", enum, helpers.SUPPORTED_KEY_USAGE)
			}
		}
	}
	extendedKeyUsage, ok := d.GetOk("extendedKeyUsage")
	extendedKeyUsageArray := []string{}
	if ok {
		json.Unmarshal([]byte(extendedKeyUsage.(string)), &extendedKeyUsageArray)
		if len(extendedKeyUsageArray) == 0 {
			return nil, fmt.Errorf("Not provided any of extendedKeyUsage attribute. Supported attributes: %s", helpers.SUPPORTED_EXTENDED_KEY_USAGE)
		}
		for _, enum := range extendedKeyUsageArray {
			if !helpers.Contains(helpers.SUPPORTED_EXTENDED_KEY_USAGE, enum) {
				return nil, fmt.Errorf("Not supported extendedKeyUsage %s. Available certificate key usage %s", enum, helpers.SUPPORTED_EXTENDED_KEY_USAGE)
			}
		}
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
	requestId, _, errEnc := client.AsyncSelfSignedCertificate(keyEntry.GetActiveVersion().KeyLabel, passwordString, signatureAlgorithm.(string), validityInt, commonName.(string), keyUsageArray, extendedKeyUsageArray, certificateAuthorityBool, additionalMetaDataObj)
	if errEnc != nil {
		errKeyNotExists := b.CheckIfKeyExists(ctx, req.Storage, keyName, errEnc)
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

	requestEntry.Id = requestResponse.Id
	requestEntry.Type = "CertificateSelfSign"
	requestEntry.Key = *keyEntry
	requestEntry.KeyPassword = passwordString

	requestEntry.KeyVersion = keyEntry.CurrentVersion
	requestEntry.UpdateStatus(*requestResponse)
	requestEntry.Request = make(map[string]string)
	requestEntry.Request["key"] = keyName
	requestEntry.Request["keyLabel"] = keyEntry.GetActiveVersion().KeyLabel
	requestEntry.Request["commonName"] = commonName.(string)
	requestEntry.Request["validity"] = fmt.Sprintf("%d", validityInt)
	requestEntry.Request["signatureAlgorithm"] = signatureAlgorithm.(string)
	requestEntry.Request["certificateAuthorityBool"] = strconv.FormatBool(certificateAuthorityBool)
	requestEntry.Request["keyUsage"] = strings.Join(keyUsageArray[:], ", ")
	requestEntry.Request["extendedKeyUsage"] = strings.Join(extendedKeyUsageArray[:], ", ")

	if err := setRequest(ctx, req.Storage, requestResponse.Id, &requestEntry); err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: requestEntry.ToResponseData(),
	}, nil
}

// This function sends command to HSM to creates certificate request using selected key.
func (b *SecurosysBackend) pathOperationCertificateRequest(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	keyName := d.Get("name").(string)
	keyEntry, err := b.GetKey(ctx, req.Storage, keyName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving key: %w", err)
	}
	if keyEntry == nil {
		return nil, errors.New("error retrieving key: key is nil")
	}
	client, err := b.GetClient(ctx, req.Storage)
	password, ok := d.GetOk("password")
	passwordString := ""
	if ok {
		passwordString = password.(string)
	}
	//checking for updates policy on hsm
	keyAttribute, err := client.GetKey(keyEntry.GetActiveVersionKeyLabel(), passwordString)
	if err != nil {
		errKeyNotExists := b.CheckIfKeyExists(ctx, req.Storage, keyName, err)
		if errKeyNotExists == nil {
			return nil, err
		} else {
			return nil, errKeyNotExists
		}
	}

	keyEntry.UpdateKeyFromHSM(keyAttribute)
	if err := SetKey(ctx, req.Storage, keyName, keyEntry); err != nil {
		return nil, err
	}

	if len(keyEntry.GetActiveVersion().Policy.RuleUse.Tokens) > 0 {
		for _, token := range keyEntry.GetActiveVersion().Policy.RuleUse.Tokens {
			if len(token.Groups) > 0 {
				return b.pathAsyncOperationCertificateRequest(ctx, req, d)
			}
		}
	}

	if !helpers.Contains(helpers.SUPPORTED_CERTIFICATE_SIGN_KEYS, keyEntry.Algorithm) {
		return nil, fmt.Errorf("Key type %s is not supported. Available key types %s", keyEntry.Algorithm, helpers.SUPPORTED_CERTIFICATE_SIGN_KEYS)
	}
	if !keyEntry.Attributes["sign"] {
		return nil, fmt.Errorf("Cannot use key %s with HSM label %s. Attribute sign is false", keyName, keyEntry.GetActiveVersion().KeyLabel)

	}
	validity, ok := d.GetOk("validity")
	validityInt := 365
	if !ok {
		validityInt = validity.(int)
	}
	certificateAttributes, ok := d.GetOk("certificateAttributes")
	if !ok {
		return nil, fmt.Errorf("error: missing certificateAttributes")
	}
	certificateAttributesObj := helpers.CertificateAttributes{}
	if ok {
		err := json.Unmarshal([]byte(certificateAttributes.(string)), &certificateAttributesObj)
		if err != nil {
			return nil, fmt.Errorf("Something wrong on mapping JSON to Object. Error: %s", err.Error())
		}
	}

	signatureAlgorithm, ok := d.GetOk("signatureAlgorithm")
	if !ok {
		return nil, fmt.Errorf("error: missing signatureAlgorithm")
	}
	if !helpers.Contains(helpers.CERTIFICATE_RSA_SIGNATURE_LIST, signatureAlgorithm.(string)) {
		return nil, fmt.Errorf("Not supported signatureAlgorithm %s for %s key type. Available certificate signature algorithms %s", signatureAlgorithm, keyEntry.Algorithm, helpers.CERTIFICATE_RSA_SIGNATURE_LIST)
	}
	keyUsage, ok := d.GetOk("keyUsage")
	keyUsageArray := []string{}
	if ok {
		json.Unmarshal([]byte(keyUsage.(string)), &keyUsageArray)
		for _, enum := range keyUsageArray {
			if !helpers.Contains(helpers.SUPPORTED_KEY_USAGE, enum) {
				return nil, fmt.Errorf("Not supported keyUsage %s. Available certificate key usage %s", enum, helpers.SUPPORTED_KEY_USAGE)
			}
		}
	}
	extendedKeyUsage, ok := d.GetOk("extendedKeyUsage")
	extendedKeyUsageArray := []string{}
	if ok {
		json.Unmarshal([]byte(extendedKeyUsage.(string)), &extendedKeyUsageArray)
		for _, enum := range extendedKeyUsageArray {
			if !helpers.Contains(helpers.SUPPORTED_EXTENDED_KEY_USAGE, enum) {
				return nil, fmt.Errorf("Not supported extendedKeyUsage %s. Available certificate key usage %s", enum, helpers.SUPPORTED_EXTENDED_KEY_USAGE)
			}
		}
	}
	result, _, errEnc := client.CreateCertificate(keyEntry.GetActiveVersion().KeyLabel, passwordString, signatureAlgorithm.(string), validityInt, certificateAttributesObj, keyUsageArray, extendedKeyUsageArray)
	if errEnc != nil {
		return nil, errEnc
	}
	result.KeyVersion = keyEntry.CurrentVersion
	var inInterface map[string]interface{}
	inrec, _ := json.Marshal(result)
	json.Unmarshal(inrec, &inInterface)

	return &logical.Response{
		Data: inInterface,
	}, nil
}

// This function sends command to HSM to creates certificate request using selected key. This command is only use, when key have a policy with Use Rule
func (b *SecurosysBackend) pathAsyncOperationCertificateRequest(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	keyName := d.Get("name").(string)
	keyEntry, err := b.GetKey(ctx, req.Storage, keyName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving key: %w", err)
	}
	if keyEntry == nil {
		return nil, errors.New("error retrieving key: key is nil")
	}
	if !helpers.Contains(helpers.SUPPORTED_CERTIFICATE_SIGN_KEYS, keyEntry.Algorithm) {
		return nil, fmt.Errorf("Key type %s is not supported. Available key types %s", keyEntry.Algorithm, helpers.SUPPORTED_CERTIFICATE_SIGN_KEYS)
	}
	if !keyEntry.Attributes["sign"] {
		return nil, fmt.Errorf("Cannot use key %s with HSM label %s. Attribute sign is false", keyName, keyEntry.GetActiveVersion().KeyLabel)

	}
	validity, ok := d.GetOk("validity")
	validityInt := 365
	if !ok {
		validityInt = validity.(int)
	}
	certificateAttributes, ok := d.GetOk("certificateAttributes")
	if !ok {
		return nil, fmt.Errorf("error: missing certificateAttributes")
	}
	certificateAttributesObj := helpers.CertificateAttributes{}
	if ok {
		err := json.Unmarshal([]byte(certificateAttributes.(string)), &certificateAttributesObj)
		if err != nil {
			return nil, fmt.Errorf("Something wrong on mapping JSON to Object. Error: %s", err.Error())
		}
	}

	signatureAlgorithm, ok := d.GetOk("signatureAlgorithm")
	if !ok {
		return nil, fmt.Errorf("error: missing signatureAlgorithm")
	}
	if !helpers.Contains(helpers.CERTIFICATE_RSA_SIGNATURE_LIST, signatureAlgorithm.(string)) {
		return nil, fmt.Errorf("Not supported signatureAlgorithm %s for %s key type. Available certificate signature algorithms %s", signatureAlgorithm, keyEntry.Algorithm, helpers.CERTIFICATE_RSA_SIGNATURE_LIST)
	}
	password, ok := d.GetOk("password")
	passwordString := ""
	if ok {
		passwordString = password.(string)
	}
	keyUsage, ok := d.GetOk("keyUsage")
	keyUsageArray := []string{}
	if ok {
		json.Unmarshal([]byte(keyUsage.(string)), &keyUsageArray)
		for _, enum := range keyUsageArray {
			if !helpers.Contains(helpers.SUPPORTED_KEY_USAGE, enum) {
				return nil, fmt.Errorf("Not supported keyUsage %s. Available certificate key usage %s", enum, helpers.SUPPORTED_KEY_USAGE)
			}
		}
	}
	extendedKeyUsage, ok := d.GetOk("extendedKeyUsage")
	extendedKeyUsageArray := []string{}
	if ok {
		json.Unmarshal([]byte(extendedKeyUsage.(string)), &extendedKeyUsageArray)
		for _, enum := range extendedKeyUsageArray {
			if !helpers.Contains(helpers.SUPPORTED_EXTENDED_KEY_USAGE, enum) {
				return nil, fmt.Errorf("Not supported extendedKeyUsage %s. Available certificate key usage %s", enum, helpers.SUPPORTED_EXTENDED_KEY_USAGE)
			}
		}
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
	requestId, _, errEnc := client.AsyncCreateCertificate(keyEntry.GetActiveVersion().KeyLabel, passwordString, signatureAlgorithm.(string), validityInt, certificateAttributesObj, keyUsageArray, extendedKeyUsageArray, additionalMetaDataObj)
	if errEnc != nil {
		return nil, errEnc
	}
	var requestEntry helpers.RequestEntry
	requestResponse, _, errReq := client.GetRequest(requestId)
	if errReq != nil {
		return nil, errReq
	}
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

	requestEntry.Id = requestResponse.Id
	requestEntry.Type = "CertificateRequest"
	requestEntry.Key = *keyEntry
	requestEntry.KeyPassword = passwordString

	requestEntry.KeyVersion = keyEntry.CurrentVersion
	requestEntry.UpdateStatus(*requestResponse)
	requestEntry.Request = make(map[string]string)
	requestEntry.Request["key"] = keyName
	requestEntry.Request["keyLabel"] = keyEntry.GetActiveVersion().KeyLabel
	requestEntry.Request["certificateAttributes"] = certificateAttributes.(string)
	requestEntry.Request["validity"] = fmt.Sprintf("%d", validityInt)
	requestEntry.Request["signatureAlgorithm"] = signatureAlgorithm.(string)
	requestEntry.Request["keyUsage"] = strings.Join(keyUsageArray[:], ", ")
	requestEntry.Request["extendedKeyUsage"] = strings.Join(extendedKeyUsageArray[:], ", ")

	if err := setRequest(ctx, req.Storage, requestResponse.Id, &requestEntry); err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: requestEntry.ToResponseData(),
	}, nil
}

// This function sends command to HSM to verify payload using signature
func (b *SecurosysBackend) pathOperationVerify(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	keyName := d.Get("name").(string)
	keyEntry, err := b.GetKey(ctx, req.Storage, keyName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving key: %w", err)
	}
	if keyEntry == nil {
		return nil, errors.New("error retrieving key: key is nil")
	}
	keyVersion, ok := d.GetOk("keyVersion")
	if !ok {
		return nil, fmt.Errorf("error: missing keyVersion")
	}
	if !helpers.ContainsKey(keyEntry.Versions, keyVersion) {
		return nil, fmt.Errorf("Key version %s is not exists.", keyVersion)

	}
	if !helpers.Contains(helpers.SUPPORTED_SIGN_KEYS, keyEntry.Algorithm) {
		return nil, fmt.Errorf("Key type %s is not supported. Available key types %s", keyEntry.Algorithm, helpers.SUPPORTED_SIGN_KEYS)
	}
	if !keyEntry.Attributes["sign"] {
		return nil, fmt.Errorf("Cannot use key %s with HSM label %s. Attribute sign is false", keyName, keyEntry.GetActiveVersion().KeyLabel)

	}
	payload, ok := d.GetOk("payload")
	if !ok {
		return nil, fmt.Errorf("error: missing payload")
	}
	_, errB64 := b64.StdEncoding.DecodeString(payload.(string))
	if errB64 != nil {
		return nil, fmt.Errorf("error: payload is not valid base64 string")
	}
	signatureAlgorithm, ok := d.GetOk("signatureAlgorithm")
	if !ok {
		return nil, fmt.Errorf("error: missing signatureAlgorithm")
	}
	if err := validateSignatureAlgorithmForKey(keyEntry.Algorithm, signatureAlgorithm.(string)); err != nil {
		return nil, err
	}
	signature, ok := d.GetOk("signature")
	if !ok {
		return nil, fmt.Errorf("error: missing signature")
	}

	password, ok := d.GetOk("password")
	passwordString := ""
	if ok {
		passwordString = password.(string)
	}
	client, err := b.GetClient(ctx, req.Storage)
	result, _, errEnc := client.Verify(keyEntry.GetVersion(keyVersion.(string)).KeyLabel, passwordString, payload.(string), signatureAlgorithm.(string), signature.(string))
	if errEnc != nil {
		errKeyNotExists := b.CheckIfKeyExists(ctx, req.Storage, keyName, errEnc)
		if errKeyNotExists == nil {
			return nil, errEnc
		} else {
			return nil, errKeyNotExists
		}
	}

	return &logical.Response{
		Data: map[string]interface{}{"signatureValid": result},
	}, nil
}

// This function sends command to HSM to unwrap key. This command is only use, when key have a policy with Use Rule
func (b *SecurosysBackend) pathAsyncOperationUnWrap(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	keyName := d.Get("name").(string)
	keyEntry, err := b.GetKey(ctx, req.Storage, keyName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving key: %w", err)
	}
	if keyEntry == nil {
		return nil, errors.New("error retrieving key: key is nil")
	}
	keyVersion, ok := d.GetOk("keyVersion")
	if !ok {
		return nil, fmt.Errorf("error: missing keyVersion")
	}
	if !helpers.ContainsKey(keyEntry.Versions, keyVersion) {
		return nil, fmt.Errorf("Key version %s is not exists.", keyVersion)

	}

	newKeyName := d.Get("unwrappedKeyName").(string)
	unwrappedKeyEntry, err := b.GetKey(ctx, req.Storage, newKeyName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving key: %w", err)
	}
	if unwrappedKeyEntry == nil {
		unwrappedKeyEntry = &helpers.KeyEntry{}
	}

	if !helpers.Contains(helpers.SUPPORTED_WRAP_KEYS, keyEntry.Algorithm) {
		return nil, fmt.Errorf("Key type %s is not supported. Available key types %s", keyEntry.Algorithm, helpers.SUPPORTED_WRAP_KEYS)
	}
	if !keyEntry.Attributes["unwrap"] {
		return nil, fmt.Errorf("Cannot use key %s with HSM label %s. Attribute unwrap is false", keyName, keyEntry.GetActiveVersion().KeyLabel)

	}
	if attributes, ok := d.GetOk("attributes"); ok {
		err := json.Unmarshal([]byte(attributes.(string)), &unwrappedKeyEntry.Attributes)
		if err != nil {
			return nil, fmt.Errorf("%s = error on decoding json: %s", "attributes", err.Error())
		}
		var counter int = 0
		val1, ok1 := unwrappedKeyEntry.Attributes["decrypt"]
		if !ok1 || val1 == false {
			counter = counter + 1
		}
		val2, ok2 := unwrappedKeyEntry.Attributes["sign"]
		if !ok2 || val2 == false {
			counter = counter + 1
		}
		val3, ok3 := unwrappedKeyEntry.Attributes["unwrap"]
		if !ok3 || val3 == false {
			counter = counter + 1
		}
		if counter == 3 {
			return nil, fmt.Errorf("Attributes is not valid. At least one operation (decrypt, sign, unwrap) must be allowed (true). %v", unwrappedKeyEntry.Attributes)
		}
		_, ok4 := unwrappedKeyEntry.Attributes["destroyable"]
		if !ok4 {
			unwrappedKeyEntry.Attributes["destroyable"] = true
		}
		_, ok5 := unwrappedKeyEntry.Attributes["modifiable"]
		if !ok5 {
			unwrappedKeyEntry.Attributes["modifiable"] = true
		}
	} else if !ok {
		return nil, fmt.Errorf("missing attributes in key")
	}
	keyLabel, ok := d.GetOk("keyLabel")
	if !ok {
		return nil, fmt.Errorf("error: missing keyLabel")
	} else {
		unwrappedKeyEntry.BaseLabel = keyLabel.(string)
	}
	wrappedKey, ok := d.GetOk("wrappedKey")
	if !ok {
		return nil, fmt.Errorf("error: missing wrappedKey")
	}
	wrapMethod, ok := d.GetOk("wrapMethod")
	if !ok {
		return nil, fmt.Errorf("error: missing wrapMethod")
	}
	if keyEntry.Algorithm == "AES" {
		if !helpers.Contains(helpers.AES_WRAP_METHODS_LIST, wrapMethod.(string)) {
			return nil, fmt.Errorf("Not supported wrap method %s for %s key type. Available wrap methods %s", wrapMethod, keyEntry.Algorithm, helpers.AES_WRAP_METHODS_LIST)
		}
	}
	if keyEntry.Algorithm == "RSA" {
		if !helpers.Contains(helpers.RSA_WRAP_METHODS_LIST, wrapMethod.(string)) {
			return nil, fmt.Errorf("Not supported wrap method %s for %s key type. Available wrap methods %s", wrapMethod, keyEntry.Algorithm, helpers.RSA_WRAP_METHODS_LIST)
		}
	}
	password, ok := d.GetOk("password")
	passwordString := ""
	if ok {
		passwordString = password.(string)
	}
	var hasPolicy bool = false
	var unwrappedKeyVersion helpers.KeyVersion

	if simplePolicy, ok := d.GetOk("simplePolicy"); ok {
		if unwrappedKeyEntry.Attributes["extractable"] {
			return nil, fmt.Errorf("Error on generating key: attribute 'extractable' is set to true. You cannot use policy with this attribute")
		}
		policyObj, err := helpers.PreparePolicy(simplePolicy.(string), true)
		if err != nil {
			return nil, fmt.Errorf("Error on generating key policy from '%s' attribute: %s", "simplePolicy", err.Error())
		}
		unwrappedKeyVersion.Policy = *policyObj
		hasPolicy = true
	}
	if policy, ok := d.GetOk("policy"); ok {
		if unwrappedKeyEntry.Attributes["extractable"] {
			return nil, fmt.Errorf("Error on generating key: attribute 'extractable' is set to true. You cannot use policy with this attribute")
		}
		policyObj, err := helpers.PreparePolicy(policy.(string), false)
		if err != nil {
			return nil, fmt.Errorf("Error on generating key policy from '%s' attribute: %s", "simplePolicy", err.Error())
		}
		unwrappedKeyVersion.Policy = *policyObj
		hasPolicy = true
	}
	if hasPolicy == false {
		policyObj, _ := helpers.PreparePolicy("{}", true)
		unwrappedKeyVersion.Policy = *policyObj
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
	var errEnc error
	var requestId string
	if hasPolicy == true {
		requestId, _, errEnc = client.AsyncUnWrap(wrappedKey.(string), unwrappedKeyEntry.BaseLabel+"_v1", unwrappedKeyEntry.Attributes, keyEntry.GetVersion(keyVersion.(string)).KeyLabel, passwordString, wrapMethod.(string), &unwrappedKeyVersion.Policy, additionalMetaDataObj)
	} else {
		requestId, _, errEnc = client.AsyncUnWrap(wrappedKey.(string), unwrappedKeyEntry.BaseLabel+"_v1", unwrappedKeyEntry.Attributes, keyEntry.GetVersion(keyVersion.(string)).KeyLabel, passwordString, wrapMethod.(string), nil, additionalMetaDataObj)
	}
	if errEnc != nil {
		return nil, errEnc
	}
	var requestEntry helpers.RequestEntry
	requestResponse, _, errReq := client.GetRequest(requestId)
	if errReq != nil {
		return nil, errReq
	}
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

	requestEntry.Id = requestResponse.Id
	requestEntry.Type = "UnWrap"
	requestEntry.Key = *keyEntry
	requestEntry.KeyVersion = keyEntry.CurrentVersion
	requestEntry.KeyPassword = passwordString

	requestEntry.UpdateStatus(*requestResponse)
	requestEntry.Request = make(map[string]string)
	requestEntry.Request["key"] = keyName
	requestEntry.Request["unwrapedKey"] = newKeyName
	requestEntry.Request["keyLabel"] = keyEntry.GetVersion(keyVersion.(string)).KeyLabel
	requestEntry.Request["unwrapKeyName"] = unwrappedKeyEntry.BaseLabel + "_v1"
	requestEntry.Request["wrappedKey"] = wrappedKey.(string)
	requestEntry.Request["wrapMethod"] = wrapMethod.(string)
	requestEntry.Request["attributes"] = fmt.Sprintf("%v", unwrappedKeyEntry.Attributes)
	if err := setRequest(ctx, req.Storage, requestResponse.Id, &requestEntry); err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: requestEntry.ToResponseData(),
	}, nil
}

// This function sends command to HSM to decrypt payload. This command is only use, when key have a policy with Use Rule
func (b *SecurosysBackend) pathAsyncOperationDecrypt(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	keyName := d.Get("name").(string)
	keyEntry, err := b.GetKey(ctx, req.Storage, keyName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving key: %w", err)
	}
	if keyEntry == nil {
		return nil, errors.New("error retrieving key: key is nil")
	}
	if !keyEntry.Attributes["decrypt"] {
		return nil, fmt.Errorf("Cannot use key %s with HSM label %s. Attribute decrypt is false", keyName, keyEntry.GetActiveVersion().KeyLabel)

	}
	keyVersion, ok := d.GetOk("keyVersion")
	if !ok {
		return nil, fmt.Errorf("error: missing keyVersion")
	}
	if !helpers.ContainsKey(keyEntry.Versions, keyVersion) {
		return nil, fmt.Errorf("Key version %s is not exists.", keyVersion)

	}
	if !helpers.Contains(helpers.SUPPORTED_ENCRYPT_DECRYPT_KEYS, keyEntry.Algorithm) {
		return nil, fmt.Errorf("Key type %s is not supported. Available key types %s", keyEntry.Algorithm, helpers.SUPPORTED_ENCRYPT_DECRYPT_KEYS)
	}
	encryptedPayload, ok := d.GetOk("encryptedPayload")
	if !ok {
		return nil, fmt.Errorf("error: missing encryptedPayload")
	}
	_, errB64 := b64.StdEncoding.DecodeString(encryptedPayload.(string))
	if errB64 != nil {
		return nil, fmt.Errorf("error: encryptedPayload is not valid base64 string")
	}
	cipherAlgorithm, ok := d.GetOk("cipherAlgorithm")
	if !ok && (keyEntry.KeyTypeName != "aes256-gcm96" && keyEntry.KeyTypeName != "aes128-gcm96") {
		return nil, fmt.Errorf("error: missing cipherAlgorithm")
	}
	if keyEntry.KeyTypeName == "aes256-gcm96" || keyEntry.KeyTypeName == "aes128-gcm96" {
		cipherAlgorithm = "AES_GCM"
	}
	initializationVector, ok := d.GetOk("initializationVector")
	initializationVectorString := ""
	if ok {
		initializationVectorString = initializationVector.(string)
	}

	if keyEntry.Algorithm == "AES" {
		if !helpers.Contains(helpers.AES_CIPHER_LIST, cipherAlgorithm.(string)) {
			return nil, fmt.Errorf("Not supported cipherAlgorithm %s for %s key type. Available cipher algorithms %s", cipherAlgorithm, keyEntry.Algorithm, helpers.AES_CIPHER_LIST)
		}
	}
	if keyEntry.Algorithm == "RSA" {
		if !helpers.Contains(helpers.RSA_CIPHER_LIST, cipherAlgorithm.(string)) {
			return nil, fmt.Errorf("Not supported cipherAlgorithm %s for %s key type. Available cipher algorithms %s", cipherAlgorithm, keyEntry.Algorithm, helpers.RSA_CIPHER_LIST)
		}
	}
	if keyEntry.Algorithm == "CHACHA20" {
		if !helpers.Contains(helpers.CHACHA20_CIPHER_LIST, cipherAlgorithm.(string)) {
			return nil, fmt.Errorf("Not supported cipherAlgorithm %s for %s key type. Available cipher algorithms %s", cipherAlgorithm, keyEntry.Algorithm, helpers.CHACHA20_CIPHER_LIST)
		}

	}
	if keyEntry.Algorithm == "CAMELIA" {
		if !helpers.Contains(helpers.CAMELIA_CIPHER_LIST, cipherAlgorithm.(string)) {
			return nil, fmt.Errorf("Not supported cipherAlgorithm %s for %s key type. Available cipher algorithms %s", cipherAlgorithm, keyEntry.Algorithm, helpers.CAMELIA_CIPHER_LIST)
		}

	}
	if keyEntry.Algorithm == "TDEA" {
		if !helpers.Contains(helpers.TDEA_CIPHER_LIST, cipherAlgorithm.(string)) {
			return nil, fmt.Errorf("Not supported cipherAlgorithm %s for %s key type. Available cipher algorithms %s", cipherAlgorithm, keyEntry.Algorithm, helpers.TDEA_CIPHER_LIST)
		}

	}
	password, ok := d.GetOk("password")
	passwordString := ""
	if ok {
		passwordString = password.(string)
	}
	tagLength, ok := d.GetOk("tagLength")
	tagLengthInt := -1
	if ok && (keyEntry.KeyTypeName != "aes256-gcm96" && keyEntry.KeyTypeName != "aes128-gcm96") {
		tagLengthInt = tagLength.(int)
		if tagLengthInt != -1 && keyEntry.Algorithm == "AES" && cipherAlgorithm == "AES_GCM" {
			if !helpers.Contains(helpers.SUPPORTED_TAG_LENGTH, strconv.Itoa(tagLengthInt)) {
				return nil, fmt.Errorf("Not supported tag length %s. Available tag lengths %s", strconv.Itoa(tagLengthInt), helpers.SUPPORTED_TAG_LENGTH)
			}
		}
	}
	if keyEntry.KeyTypeName == "aes256-gcm96" || keyEntry.KeyTypeName == "aes128-gcm96" {
		tagLengthInt = 96
	}
	additionalAuthenticationData, ok := d.GetOk("additionalAuthenticationData")
	additionalAuthenticationDataString := ""
	if ok {
		_, errB64 := b64.StdEncoding.DecodeString(additionalAuthenticationData.(string))
		if errB64 != nil {
			return nil, fmt.Errorf("error: additionalAuthenticationData is not valid base64 string")
		}
		additionalAuthenticationDataString = additionalAuthenticationData.(string)
	}
	client, err := b.GetClient(ctx, req.Storage)
	requestId, _, errEnc := client.AsyncDecrypt(keyEntry.GetVersion(keyVersion.(string)).KeyLabel, passwordString, encryptedPayload.(string), initializationVectorString, cipherAlgorithm.(string), tagLengthInt, additionalAuthenticationDataString, nil)
	if errEnc != nil {
		return nil, errEnc
	}
	var requestEntry helpers.RequestEntry
	requestResponse, _, errReq := client.GetRequest(requestId)
	if errReq != nil {
		return nil, errReq
	}
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

	requestEntry.Id = requestResponse.Id
	requestEntry.Type = "Decrypt"
	requestEntry.Key = *keyEntry
	requestEntry.KeyVersion = keyEntry.CurrentVersion
	requestEntry.KeyPassword = passwordString

	requestEntry.UpdateStatus(*requestResponse)
	requestEntry.Request = make(map[string]string)
	requestEntry.Request["key"] = keyName
	requestEntry.Request["keyLabel"] = keyEntry.GetVersion(keyVersion.(string)).KeyLabel
	requestEntry.Request["encryptedPayload"] = encryptedPayload.(string)
	requestEntry.Request["initializationVector"] = initializationVectorString
	requestEntry.Request["cipherAlgorithm"] = cipherAlgorithm.(string)
	requestEntry.Request["tagLength"] = strconv.Itoa(tagLengthInt)
	requestEntry.Request["additionalAuthenticationData"] = additionalAuthenticationDataString

	if err := setRequest(ctx, req.Storage, requestResponse.Id, &requestEntry); err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: requestEntry.ToResponseData(),
	}, nil
}

// This function sends command to HSM to decrypt payload.
func (b *SecurosysBackend) pathOperationDecrypt(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	keyName := d.Get("name").(string)
	keyEntry, err := b.GetKey(ctx, req.Storage, keyName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving key: %w", err)
	}
	if keyEntry == nil {
		return nil, errors.New("error retrieving key: key is nil")
	}
	if !keyEntry.Attributes["decrypt"] {
		return nil, fmt.Errorf("Cannot use key %s with HSM label %s. Attribute decrypt is false", keyName, keyEntry.GetActiveVersion().KeyLabel)

	}
	keyVersion, ok := d.GetOk("keyVersion")
	if !ok {
		return nil, fmt.Errorf("error: missing keyVersion")
	}
	if !helpers.ContainsKey(keyEntry.Versions, keyVersion) {
		return nil, fmt.Errorf("Key version %s is not exists.", keyVersion)

	}
	client, err := b.GetClient(ctx, req.Storage)
	password, ok := d.GetOk("password")
	passwordString := ""
	if ok {
		passwordString = password.(string)
	}
	//checking for updates policy on hsm
	keyAttribute, err := client.GetKey(keyEntry.GetActiveVersionKeyLabel(), passwordString)
	if err != nil {
		errKeyNotExists := b.CheckIfKeyExists(ctx, req.Storage, keyName, err)
		if errKeyNotExists == nil {
			return nil, err
		} else {
			return nil, errKeyNotExists
		}
	}

	keyEntry.UpdateKeyFromHSM(keyAttribute)
	if err := SetKey(ctx, req.Storage, keyName, keyEntry); err != nil {
		return nil, err
	}

	if len(keyEntry.GetVersion(keyVersion.(string)).Policy.RuleUse.Tokens) > 0 {
		for _, token := range keyEntry.GetVersion(keyVersion.(string)).Policy.RuleUse.Tokens {
			if len(token.Groups) > 0 {
				return b.pathAsyncOperationDecrypt(ctx, req, d)
			}
		}
	}
	if !helpers.Contains(helpers.SUPPORTED_ENCRYPT_DECRYPT_KEYS, keyEntry.Algorithm) {
		return nil, fmt.Errorf("Key type %s is not supported. Available key types %s", keyEntry.Algorithm, helpers.SUPPORTED_ENCRYPT_DECRYPT_KEYS)
	}
	encryptedPayload, ok := d.GetOk("encryptedPayload")
	if !ok {
		return nil, fmt.Errorf("error: missing encryptedPayload")
	}
	_, errB64 := b64.StdEncoding.DecodeString(encryptedPayload.(string))
	if errB64 != nil {
		return nil, fmt.Errorf("error: encryptedPayload is not valid base64 string")
	}
	cipherAlgorithm, ok := d.GetOk("cipherAlgorithm")
	if !ok && (keyEntry.KeyTypeName != "aes256-gcm96" && keyEntry.KeyTypeName != "aes128-gcm96") {
		return nil, fmt.Errorf("error: missing cipherAlgorithm")
	}
	if keyEntry.KeyTypeName == "aes256-gcm96" || keyEntry.KeyTypeName == "aes128-gcm96" {
		cipherAlgorithm = "AES_GCM"
	}
	initializationVector, ok := d.GetOk("initializationVector")
	initializationVectorString := ""
	if ok {
		initializationVectorString = initializationVector.(string)
	}

	if keyEntry.Algorithm == "AES" {
		if !helpers.Contains(helpers.AES_CIPHER_LIST, cipherAlgorithm.(string)) {
			return nil, fmt.Errorf("Not supported cipherAlgorithm %s for %s key type. Available cipher algorithms %s", cipherAlgorithm, keyEntry.Algorithm, helpers.AES_CIPHER_LIST)
		}
	}
	if keyEntry.Algorithm == "RSA" {
		if !helpers.Contains(helpers.RSA_CIPHER_LIST, cipherAlgorithm.(string)) {
			return nil, fmt.Errorf("Not supported cipherAlgorithm %s for %s key type. Available cipher algorithms %s", cipherAlgorithm, keyEntry.Algorithm, helpers.RSA_CIPHER_LIST)
		}
	}
	if keyEntry.Algorithm == "CHACHA20" {
		if !helpers.Contains(helpers.CHACHA20_CIPHER_LIST, cipherAlgorithm.(string)) {
			return nil, fmt.Errorf("Not supported cipherAlgorithm %s for %s key type. Available cipher algorithms %s", cipherAlgorithm, keyEntry.Algorithm, helpers.CHACHA20_CIPHER_LIST)
		}

	}
	if keyEntry.Algorithm == "CAMELIA" {
		if !helpers.Contains(helpers.CAMELIA_CIPHER_LIST, cipherAlgorithm.(string)) {
			return nil, fmt.Errorf("Not supported cipherAlgorithm %s for %s key type. Available cipher algorithms %s", cipherAlgorithm, keyEntry.Algorithm, helpers.CAMELIA_CIPHER_LIST)
		}

	}
	if keyEntry.Algorithm == "TDEA" {
		if !helpers.Contains(helpers.TDEA_CIPHER_LIST, cipherAlgorithm.(string)) {
			return nil, fmt.Errorf("Not supported cipherAlgorithm %s for %s key type. Available cipher algorithms %s", cipherAlgorithm, keyEntry.Algorithm, helpers.TDEA_CIPHER_LIST)
		}

	}
	tagLength, ok := d.GetOk("tagLength")
	tagLengthInt := -1
	if ok && (keyEntry.KeyTypeName != "aes256-gcm96" && keyEntry.KeyTypeName != "aes128-gcm96") {
		tagLengthInt = tagLength.(int)
		if tagLengthInt != -1 && keyEntry.Algorithm == "AES" && cipherAlgorithm == "AES_GCM" {
			if !helpers.Contains(helpers.SUPPORTED_TAG_LENGTH, strconv.Itoa(tagLengthInt)) {
				return nil, fmt.Errorf("Not supported tag length %s. Available tag lengths %s", strconv.Itoa(tagLengthInt), helpers.SUPPORTED_TAG_LENGTH)
			}
		}
	}
	if keyEntry.KeyTypeName == "aes256-gcm96" || keyEntry.KeyTypeName == "aes128-gcm96" {
		tagLengthInt = 96
	}
	additionalAuthenticationData, ok := d.GetOk("additionalAuthenticationData")
	additionalAuthenticationDataString := ""
	if ok {
		_, errB64 := b64.StdEncoding.DecodeString(additionalAuthenticationData.(string))
		if errB64 != nil {
			return nil, fmt.Errorf("error: additionalAuthenticationData is not valid base64 string")
		}
		additionalAuthenticationDataString = additionalAuthenticationData.(string)
	}
	result, _, errEnc := client.Decrypt(keyEntry.GetVersion(keyVersion.(string)).KeyLabel, passwordString, encryptedPayload.(string), initializationVectorString, cipherAlgorithm.(string), tagLengthInt, additionalAuthenticationDataString)
	if errEnc != nil {
		return nil, errEnc
	}

	if cipherAlgorithm.(string) == "AES_ECB" ||
		cipherAlgorithm.(string) == "AES_CBC_NO_PADDING" ||
		cipherAlgorithm.(string) == "CAMELLIA_ECB" ||
		cipherAlgorithm.(string) == "CAMELLIA_CBC_NO_PADDING" {
		payloadBytes, _ := base64.StdEncoding.DecodeString(result.Payload)
		padder := padding.NewPkcs7Padding(32)
		payloadBytes, _ = padder.Unpad(payloadBytes)
		result.Payload = base64.StdEncoding.EncodeToString(payloadBytes)
	}
	if cipherAlgorithm.(string) == "TDEA_CBC_NO_PADDING" ||
		cipherAlgorithm.(string) == "TDEA_ECB" {
		payloadBytes, _ := base64.StdEncoding.DecodeString(result.Payload)
		padder := padding.NewPkcs7Padding(24)
		payloadBytes, _ = padder.Unpad(payloadBytes)
		result.Payload = base64.StdEncoding.EncodeToString(payloadBytes)

	}
	var inInterface map[string]interface{}
	inrec, _ := json.Marshal(result)
	json.Unmarshal(inrec, &inInterface)

	return &logical.Response{
		Data: inInterface,
	}, nil
}
