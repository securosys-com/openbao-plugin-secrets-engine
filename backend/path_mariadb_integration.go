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
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/andreburgaud/crypt2go/padding"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	helpers "securosys.ch/helpers"
)

// Paths for create Camellia Keys
func pathMariaDBIntegration(b *SecurosysBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "integrations/mariadb/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the secret",
					Required:    true,
				},
				"keyName": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the key on Vault",
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
			},
			Operations: map[logical.Operation]framework.OperationHandler{

				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathIntegrationMariaDBSecretsWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathIntegrationMariaDBSecretsWrite,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathIntegrationMariaDBSecretsDelete,
				},
			},
			HelpSynopsis:    pathIntegrationMariaDBWriteHelpSynopsis,
			HelpDescription: pathIntegrationMariaDBWriteHelpDescription,
		},
		{
			Pattern: "integrations/mariadb/" + framework.GenericNameRegex("name") + "/" + framework.GenericNameRegex("version") + "/?" + framework.MatchAllRegex("query"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the secret",
					Required:    true,
				},
				"query": {
					Type:        framework.TypeString,
					Description: "Additional query params",
					Required:    false,
				},
				"key_name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the key on Vault",
					Required:    true,
					Query:       true,
				},
				"password": {
					Type:        framework.TypeString,
					Description: "Password of the encrypt key. This is only necessary if the key algorithm is symmetric.",
					Required:    false,
					Query:       true,
				},
				"cipher_algorithm": {
					Type:        framework.TypeString,
					Description: "The cipher algorithm to be used.",
					Required:    true,
					Query:       true,
				},
				"tag_length": {
					Type:        framework.TypeInt,
					Description: "The MAC (Message Authentication Tag) is a fixed-length value as part of the AES-GCM encryption process, that is INCLUDED in the encryptedPayload and used to authenticatethe integrity of the data and the authenticity of the sender. Supported tag_length: 0, 64, 96, 104, 112, 120, 128",
					Required:    false,
					Query:       true,
				},
				"aad": {
					Type:        framework.TypeString,
					Description: "Additional authentication data (aad) used when decrypting payload. Can be empty if none were used when encrypting the payload",
					Required:    false,
					Query:       true,
				},
				"version": {
					Type:        framework.TypeString,
					Description: "Additional data from mariadb plugin",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{

				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathIntegrationMariaDBSecretsRead,
				},
			},
			HelpSynopsis:    pathIntegrationMariaDBReadV1HelpSynopsis,
			HelpDescription: pathIntegrationMariaDBReadV1HelpDescription,
		},
		{
			Pattern: "integrations/mariadb/" + framework.GenericNameRegex("name") + "/?" + framework.MatchAllRegex("query"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the secret",
					Required:    true,
				},
				"query": {
					Type:        framework.TypeString,
					Description: "Additional query params",
					Required:    false,
				},
				"key_name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the key on Vault",
					Required:    true,
					Query:       true,
				},
				"password": {
					Type:        framework.TypeString,
					Description: "Password of the encrypt key. This is only necessary if the key algorithm is symmetric.",
					Required:    false,
					Query:       true,
				},
				"cipher_algorithm": {
					Type:        framework.TypeString,
					Description: "The cipher algorithm to be used.",
					Required:    true,
					Query:       true,
				},
				"tag_length": {
					Type:        framework.TypeInt,
					Description: "The MAC (Message Authentication Tag) is a fixed-length value as part of the AES-GCM encryption process, that is INCLUDED in the encryptedPayload and used to authenticatethe integrity of the data and the authenticity of the sender. Supported tag_length: 0, 64, 96, 104, 112, 120, 128",
					Required:    false,
					Query:       true,
				},
				"aad": {
					Type:        framework.TypeString,
					Description: "Additional authentication data (aad) used when decrypting payload. Can be empty if none were used when encrypting the payload",
					Required:    false,
					Query:       true,
				},
				"version": {
					Type:        framework.TypeString,
					Description: "Additional data from mariadb plugin",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{

				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathIntegrationMariaDBSecretsRead,
				},
			},
			HelpSynopsis:    pathIntegrationMariaDBReadV2HelpSynopsis,
			HelpDescription: pathIntegrationMariaDBReadV2HelpDescription,
		},
		{
			Pattern: "integrations/mariadb/?$",
			Fields:  map[string]*framework.FieldSchema{},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathIntegrationMariaDBSecretsList,
				},
			},
			HelpSynopsis:    pathIntegrationMariaDBListHelpSynopsis,
			HelpDescription: pathIntegrationMariaDBListHelpDescription,
		},
	}
}
func (b *SecurosysBackend) pathIntegrationMariaDBSecretsList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "intergration/mariadb/")
	if err != nil {
		return nil, err
	}
	secrets := make([]string, 0, len(entries))
	secretsInfo := make(map[string]interface{})
	for _, name := range entries {
		secrets = append(secrets, name)
		secret, err := b.GetMariaDBSecret(ctx, req.Storage, name)
		if err == nil {
			secretsInfo[name] = map[string]interface{}{
				"KeyName": secret.KeyName,
				"Version": secret.CurrentVersion,
				"Created": secret.Created.Name,
				"Updated": secret.Updated.Name,
			}
		}
	}
	return logical.ListResponseWithInfo(secrets, secretsInfo), nil
}

func (b *SecurosysBackend) pathIntegrationMariaDBSecretsDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	storedSecret, errGet := b.GetMariaDBSecret(ctx, req.Storage, name)
	if errGet != nil {
		return nil, fmt.Errorf("error deleting mariadb secret: %w", errGet)
	}
	if storedSecret == nil {
		return nil, fmt.Errorf("error deleting mariadb secret: secret with name %s not exists", d.Get("name").(string))

	}

	err := req.Storage.Delete(ctx, "intergration/mariadb/"+d.Get("name").(string))
	if err != nil {
		return nil, fmt.Errorf("error deleting securosys key: %w", err)
	}

	return nil, nil
}

func (b *SecurosysBackend) pathIntegrationMariaDBSecretsWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	storedSecret, _ := b.GetMariaDBSecret(ctx, req.Storage, name)
	rotate := false
	if storedSecret != nil {
		rotate = true
		// return nil, fmt.Errorf("error secret with name: %s exists", name)
	} else {
		storedSecret = &helpers.MariaDBSecretEntry{}

	}

	keyName := d.Get("keyName").(string)

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
	payload := b64.StdEncoding.EncodeToString([]byte(helpers.GeneratePassword(32, false, false, false, true)))

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
		payloadBytes, _ := base64.StdEncoding.DecodeString(payload)
		padder := padding.NewPkcs7Padding(32)
		payloadBytes, _ = padder.Pad(payloadBytes)
		payload = base64.StdEncoding.EncodeToString(payloadBytes)
	}
	if cipherAlgorithm.(string) == "TDEA_CBC_NO_PADDING" ||
		cipherAlgorithm.(string) == "TDEA_ECB" {
		payloadBytes, _ := base64.StdEncoding.DecodeString(payload)
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
	result, _, errEnc := client.Encrypt(keyEntry.GetActiveVersion().KeyLabel, passwordString, payload, cipherAlgorithm.(string), tagLengthInt, additionalAuthenticationDataString)
	if errEnc != nil {
		return nil, errEnc
	}
	sysView := b.System()
	creator := helpers.Entity{}
	if req.EntityID != "" {
		entity, _ := sysView.EntityInfo(req.EntityID)
		creator.Aliases = entity.Aliases
		creator.Id = entity.ID
		creator.Name = entity.Name
		creator.Date = time.Now().UTC()

	} else {
		creator.Aliases = nil
		creator.Id = "root"
		creator.Name = "root"
		creator.Date = time.Now().UTC()

	}
	var messageAuthenticationCode *string = nil
	if result.MessageAuthenticationCode != nil {
		temp := *result.MessageAuthenticationCode
		messageAuthenticationCode = &temp
	}
	var initializationVector *string = nil
	if result.InitializationVector != nil {
		temp := *result.InitializationVector
		initializationVector = &temp
	}
	if !rotate {
		storedSecret.InitSecret(keyName, keyEntry.CurrentVersion, messageAuthenticationCode, initializationVector, result.EncryptedPayload, creator)
	} else {
		storedSecret.RotateSecret(keyEntry.CurrentVersion, messageAuthenticationCode, initializationVector, result.EncryptedPayload, creator)

	}
	if err := SetMariaDBSecret(ctx, req.Storage, name, storedSecret); err != nil {
		return nil, err
	}

	response := map[string]interface{}{}
	now := storedSecret.GetActiveVersion().Created.Date
	version := storedSecret.GetActiveVersion().Version
	response["metadata"] = map[string]interface{}{
		"created_time": fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02dZ", now.Year(), int(now.Month()), now.Day(), now.Hour(), now.Minute(), now.Second()),
		"version":      helpers.GetVersionNumber(version)}
	return &logical.Response{
		Warnings: nil,
		Data:     response,
	}, nil
}
func (b *SecurosysBackend) pathIntegrationMariaDBSecretsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	query := d.Get("query").(string)
	if strings.HasPrefix(query, "?") {
		query = query[1:]
	}
	params, err := url.ParseQuery(query)

	if query == "" {
		str := ""
		for key, value := range req.Data {
			str = str + key + "=" + value.(string) + "&"
		}
		str = str[:len(str)-1]
		params, err = url.ParseQuery(str)
	}

	if err != nil {
		return nil, err
	}
	name := d.Get("name").(string)

	storedSecret, _ := b.GetMariaDBSecret(ctx, req.Storage, name)
	if storedSecret == nil {
		return nil, fmt.Errorf("error secret with name: %s not exists", name)
	}

	version := "1"
	if params.Has("version") {
		if !strings.Contains(params.Get("version"), "?version=") {
			version = storedSecret.CurrentVersion
		} else {
			parts := strings.Split(params.Get("version"), "?version=")
			version = "v" + parts[1]
		}
	} else {
		ver, ok := d.GetOk("version")
		if !ok {
			return nil, fmt.Errorf("error: missing version")
		}
		version = ver.(string)
	}

	if !params.Has("key_name") {
		return nil, fmt.Errorf("key_name query param not exists")
	}
	keyEntry, err := b.GetKey(ctx, req.Storage, params.Get("key_name"))
	if err != nil {
		return nil, fmt.Errorf("error retrieving key: %w", err)
	}
	keyName := params.Get("key_name")
	if keyEntry == nil {
		return nil, errors.New("error retrieving key: key is nil")
	}
	if !keyEntry.Attributes["decrypt"] {
		return nil, fmt.Errorf("Cannot use key %s with HSM label %s. Attribute decrypt is false", keyName, keyEntry.GetActiveVersion().KeyLabel)

	}

	if !helpers.ContainsKey(storedSecret.Versions, version) {
		return nil, fmt.Errorf("Secret version %s is not exists.", version)

	}
	if !helpers.Contains(helpers.SUPPORTED_ENCRYPT_DECRYPT_KEYS, keyEntry.Algorithm) {
		return nil, fmt.Errorf("Key type %s is not supported. Available key types %s", keyEntry.Algorithm, helpers.SUPPORTED_ENCRYPT_DECRYPT_KEYS)
	}
	encryptedPayload := storedSecret.GetVersion(version).EncryptedSecret

	if !params.Has("cipher_algorithm") {
		return nil, fmt.Errorf("cipher_algorithm query param not exists")
	}

	cipherAlgorithm := params.Get("cipher_algorithm")
	if (keyEntry.KeyTypeName != "aes256-gcm96" && keyEntry.KeyTypeName != "aes128-gcm96") && cipherAlgorithm == "" {
		return nil, fmt.Errorf("error: missing cipherAlgorithm")
	}
	if keyEntry.KeyTypeName == "aes256-gcm96" || keyEntry.KeyTypeName == "aes128-gcm96" {
		cipherAlgorithm = "AES_GCM"
	}
	initializationVectorString := ""
	if params.Has("initialization_vector") {
		initializationVectorString = params.Get("initialization_vector")
	}

	if keyEntry.Algorithm == "AES" {
		if !helpers.Contains(helpers.AES_CIPHER_LIST, cipherAlgorithm) {
			return nil, fmt.Errorf("Not supported cipherAlgorithm %s for %s key type. Available cipher algorithms %s", cipherAlgorithm, keyEntry.Algorithm, helpers.AES_CIPHER_LIST)
		}
	}
	if keyEntry.Algorithm == "RSA" {
		if !helpers.Contains(helpers.RSA_CIPHER_LIST, cipherAlgorithm) {
			return nil, fmt.Errorf("Not supported cipherAlgorithm %s for %s key type. Available cipher algorithms %s", cipherAlgorithm, keyEntry.Algorithm, helpers.RSA_CIPHER_LIST)
		}
	}
	if keyEntry.Algorithm == "CHACHA20" {
		if !helpers.Contains(helpers.CHACHA20_CIPHER_LIST, cipherAlgorithm) {
			return nil, fmt.Errorf("Not supported cipherAlgorithm %s for %s key type. Available cipher algorithms %s", cipherAlgorithm, keyEntry.Algorithm, helpers.CHACHA20_CIPHER_LIST)
		}

	}
	if keyEntry.Algorithm == "CAMELIA" {
		if !helpers.Contains(helpers.CAMELIA_CIPHER_LIST, cipherAlgorithm) {
			return nil, fmt.Errorf("Not supported cipherAlgorithm %s for %s key type. Available cipher algorithms %s", cipherAlgorithm, keyEntry.Algorithm, helpers.CAMELIA_CIPHER_LIST)
		}

	}
	if keyEntry.Algorithm == "TDEA" {
		if !helpers.Contains(helpers.TDEA_CIPHER_LIST, cipherAlgorithm) {
			return nil, fmt.Errorf("Not supported cipherAlgorithm %s for %s key type. Available cipher algorithms %s", cipherAlgorithm, keyEntry.Algorithm, helpers.TDEA_CIPHER_LIST)
		}

	}
	passwordString := ""
	if params.Has("password") {
		passwordString = params.Get("password")
	}
	tagLengthInt := -1
	if params.Has("tag_length") {
		tagLengthInt, _ = strconv.Atoi(params.Get("tag_length"))
	}
	if keyEntry.KeyTypeName != "aes256-gcm96" && keyEntry.KeyTypeName != "aes128-gcm96" {
		tagLengthInt, _ = strconv.Atoi(params.Get("tag_length"))
		if tagLengthInt != -1 && keyEntry.Algorithm == "AES" && cipherAlgorithm == "AES_GCM" {
			if !helpers.Contains(helpers.SUPPORTED_TAG_LENGTH, strconv.Itoa(tagLengthInt)) {
				return nil, fmt.Errorf("Not supported tag length %s. Available tag lengths %s", strconv.Itoa(tagLengthInt), helpers.SUPPORTED_TAG_LENGTH)
			}
		}
	}
	if keyEntry.KeyTypeName == "aes256-gcm96" || keyEntry.KeyTypeName == "aes128-gcm96" {
		tagLengthInt = 96
	}
	additionalAuthenticationDataString := ""
	if params.Has("aad") {
		additionalAuthenticationDataString = params.Get("aad")
		_, errB64 := b64.StdEncoding.DecodeString(additionalAuthenticationDataString)
		if errB64 != nil {
			return nil, fmt.Errorf("error: additionalAuthenticationData (param aad) is not valid base64 string")
		}
	}
	client, err := b.GetClient(ctx, req.Storage)
	async := false
	decrypted := ""
	if len(keyEntry.GetVersion(storedSecret.GetVersion(version).KeyVersion).Policy.RuleUse.Tokens) > 0 {
		for _, token := range keyEntry.GetVersion(storedSecret.GetVersion(version).KeyVersion).Policy.RuleUse.Tokens {
			if len(token.Groups) > 0 {
				async = true
				requestId, _, errEnc := client.AsyncDecrypt(keyEntry.GetVersion(storedSecret.GetVersion(version).KeyVersion).KeyLabel,
					passwordString, encryptedPayload,
					initializationVectorString,
					cipherAlgorithm,
					tagLengthInt,
					additionalAuthenticationDataString, map[string]string{"integration": "MariaDB Encrypt"})
				if errEnc != nil {
					return nil, errEnc
				}
				var resp *helpers.RequestResponse
				resp, _, _ = client.GetRequest(requestId)
				for resp.Status == "PENDING" {
					time.Sleep(1000)
					resp, _, _ = client.GetRequest(requestId)
				}
				if resp.Status != "EXECUTED" {
					return nil, fmt.Errorf("error on async decrypt. Expected Status '%s' got '%s'", "EXECUTED", resp.Status)
				}
				decrypted = resp.Result

			}
		}
	}
	if !async {
		resultSync, _, errEnc := client.Decrypt(keyEntry.GetVersion(storedSecret.GetVersion(version).KeyVersion).KeyLabel,
			passwordString, encryptedPayload,
			initializationVectorString,
			cipherAlgorithm,
			tagLengthInt,
			additionalAuthenticationDataString)
		if errEnc != nil {
			return nil, errEnc
		}
		decrypted = resultSync.Payload
	}

	if cipherAlgorithm == "AES_ECB" ||
		cipherAlgorithm == "AES_CBC_NO_PADDING" ||
		cipherAlgorithm == "CAMELLIA_ECB" ||
		cipherAlgorithm == "CAMELLIA_CBC_NO_PADDING" {
		payloadBytes, _ := base64.StdEncoding.DecodeString(decrypted)
		padder := padding.NewPkcs7Padding(32)
		payloadBytes, _ = padder.Unpad(payloadBytes)
		decrypted = base64.StdEncoding.EncodeToString(payloadBytes)
	}
	if cipherAlgorithm == "TDEA_CBC_NO_PADDING" ||
		cipherAlgorithm == "TDEA_ECB" {
		payloadBytes, _ := base64.StdEncoding.DecodeString(decrypted)
		padder := padding.NewPkcs7Padding(24)
		payloadBytes, _ = padder.Unpad(payloadBytes)
		decrypted = base64.StdEncoding.EncodeToString(payloadBytes)

	}

	decoded, _ := base64.StdEncoding.DecodeString(decrypted)
	response := map[string]interface{}{}
	response["data"] = map[string]interface{}{"data": string(decoded)}
	now := storedSecret.GetVersion(version).Created.Date

	response["metadata"] = map[string]interface{}{
		"created_time": fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02dZ", now.Year(), int(now.Month()), now.Day(), now.Hour(), now.Minute(), now.Second()),
		"version":      helpers.GetVersionNumber(version)}
	return &logical.Response{
		Warnings: nil,
		Data:     response,
	}, nil
}

// This function helps with saving key in Secrets Engine
func SetMariaDBSecret(ctx context.Context, s logical.Storage, name string, secretEntry *helpers.MariaDBSecretEntry) error {
	entry, err := logical.StorageEntryJSON("intergration/mariadb/"+name, secretEntry)
	if err != nil {
		return err
	}

	if entry == nil {
		return fmt.Errorf("failed to create storage secret")
	}

	if err := s.Put(ctx, entry); err != nil {
		return err
	}

	return nil
}

// This function helps with getting key from Secrets Engine
func (b *SecurosysBackend) GetMariaDBSecret(ctx context.Context, s logical.Storage, name string) (*helpers.MariaDBSecretEntry, error) {
	if name == "" {
		return nil, fmt.Errorf("missing key name")
	}

	entry, err := s.Get(ctx, "intergration/mariadb/"+name)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	var secret helpers.MariaDBSecretEntry

	if err := entry.DecodeJSON(&secret); err != nil {
		return nil, err
	}
	return &secret, nil
}
