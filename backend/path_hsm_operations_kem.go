// SPDX-FileCopyrightText: Copyright 2026 Securosys SA
// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	helpers "securosys.ch/helpers"
)

func pathKEMOperations(b *SecurosysBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "operation/encapsulate/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {Type: framework.TypeLowerCaseString, Required: true, Description: "Name of the ML-KEM key"},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathOperationEncapsulate,
				logical.CreateOperation: b.pathOperationEncapsulate,
			},
			HelpSynopsis:    "Encapsulate a shared secret using an ML-KEM public key",
			HelpDescription: "Returns a shared secret and ciphertext for the active version of an ML-KEM key.",
		},
		{
			Pattern: "operation/decapsulate/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name":       {Type: framework.TypeLowerCaseString, Required: true, Description: "Name of the ML-KEM key"},
				"password":   {Type: framework.TypeString, Required: false, Description: "Password of the ML-KEM key"},
				"ciphertext": {Type: framework.TypeString, Required: true, Description: "Base64-encoded ML-KEM ciphertext"},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathOperationDecapsulate,
				logical.CreateOperation: b.pathOperationDecapsulate,
			},
			HelpSynopsis:    "Decapsulate a shared secret using an ML-KEM private key",
			HelpDescription: "Returns the shared secret recovered with the active version of an ML-KEM key.",
		},
	}
}

func getMLKEMKey(ctx context.Context, b *SecurosysBackend, req *logical.Request, name string) (*helpers.KeyEntry, error) {
	key, err := b.GetKey(ctx, req.Storage, name)
	if err != nil {
		return nil, fmt.Errorf("error retrieving key: %w", err)
	}
	if key == nil {
		return nil, errors.New("error retrieving key: key is nil")
	}
	if !helpers.Contains(helpers.ML_KEM_KEY_TYPES, key.Algorithm) {
		return nil, fmt.Errorf("key type %s is not supported; encapsulation and decapsulation require an ML-KEM key", key.Algorithm)
	}
	return key, nil
}

func (b *SecurosysBackend) pathOperationEncapsulate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	key, err := getMLKEMKey(ctx, b, req, name)
	if err != nil {
		return nil, err
	}
	version := key.GetActiveVersion()
	if version.PublicKey == "" {
		return nil, fmt.Errorf("ML-KEM key %s has no public key", name)
	}

	client, err := b.GetClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	result, _, err := client.Encapsulate(version.PublicKey)
	if err != nil {
		return nil, err
	}
	result.KeyVersion = key.CurrentVersion
	return &logical.Response{Data: map[string]interface{}{
		"sharedSecret": result.SharedSecret,
		"ciphertext":   result.Ciphertext,
		"keyVersion":   result.KeyVersion,
	}}, nil
}

func (b *SecurosysBackend) pathOperationDecapsulate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	key, err := getMLKEMKey(ctx, b, req, name)
	if err != nil {
		return nil, err
	}
	version := key.GetActiveVersion()
	if !key.Attributes["unwrap"] {
		return nil, fmt.Errorf("cannot use key %s with HSM label %s: attribute unwrap is false", name, version.KeyLabel)
	}
	ciphertext, ok := d.GetOk("ciphertext")
	if !ok {
		return nil, errors.New("error: missing ciphertext")
	}
	if _, err := base64.StdEncoding.DecodeString(ciphertext.(string)); err != nil {
		return nil, errors.New("error: ciphertext is not a valid base64 string")
	}
	password := ""
	if value, ok := d.GetOk("password"); ok {
		password = value.(string)
	}

	client, err := b.GetClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	result, _, err := client.Decapsulate(version.KeyLabel, password, ciphertext.(string))
	if err != nil {
		return nil, err
	}
	result.KeyVersion = key.CurrentVersion
	return &logical.Response{Data: map[string]interface{}{
		"sharedSecret": result.SharedSecret,
		"keyVersion":   result.KeyVersion,
	}}, nil
}
