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

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// This function provides path for update-password, modify, unblock, block etc. for a key
func pathHSMHealth(b *SecurosysBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "health",
			Fields:  map[string]*framework.FieldSchema{},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathHealthStatus,
				},
			},
			HelpSynopsis:    pathHealthHelpSynopsis,
			HelpDescription: pathHealthHelpDescription,
		},
	}
}

// This function prints lists of stored keys
func (b *SecurosysBackend) pathHealthStatus(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	client, err := b.GetClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	result, _, errHealth := client.CheckConnection()
	if errHealth != nil {
		return nil, errHealth
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"result": "Connection successful: " + result,
		},
	}, nil

}
