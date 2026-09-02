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
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	helpers "securosys.ch/helpers"
)

// Path for storing requests for async key operation
func pathRequests(b *SecurosysBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "requests/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRequestsList,
				},
			},
			HelpSynopsis:    pathRequestListHelpSynopsis,
			HelpDescription: pathRequestListHelpDescription,
		}, {
			Pattern: "requests/" + framework.GenericNameRegex("id"),
			Fields: map[string]*framework.FieldSchema{
				"id": {
					Type:        framework.TypeLowerCaseString,
					Description: "Request ID",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRequestsRead,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRequestsDelete,
				},
			},
			HelpSynopsis:    pathRequestReadDeleteHelpSynopsis,
			HelpDescription: pathRequestReadDeleteHelpDescription,
		},
	}
}

// Function thats delete request from Secrets Engine and also on HSM
func (b *SecurosysBackend) pathRequestsDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	_, errGet := b.getRequest(ctx, req.Storage, d.Get("id").(string))
	if errGet != nil {
		return nil, fmt.Errorf("error deleting request: %w", errGet)
	}

	client, errClient := b.GetClient(ctx, req.Storage)
	if errClient != nil {
		return nil, fmt.Errorf("error deleting request key: %w", errClient)

	}
	_, errReq := client.RemoveRequest(d.Get("id").(string))
	if errReq != nil {
		return nil, fmt.Errorf("error deleting request key: %w", errReq)

	}

	err := req.Storage.Delete(ctx, "requests/"+d.Get("id").(string))
	if err != nil {
		return nil, fmt.Errorf("error deleting request key: %w", err)
	}

	return nil, nil
}

// This function read stored requests operation from Secrets Engine
func (b *SecurosysBackend) pathRequestsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entry, err := b.getRequest(ctx, req.Storage, d.Get("id").(string))
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}
	if entry.Status == "PENDING" {
		requestResponse, _, err := b.client.GetRequest(entry.Id)
		if err != nil {
			entry.Status = "ERROR"
		} else {
			entry.UpdateStatus(*requestResponse)
		}
		if entry.Status == "EXECUTED" && entry.KeyUpdated == false && !helpers.Contains(helpers.UPDATE_POLICY_ON, entry.Type) {
			entry.KeyUpdated = true
			key, err := b.client.GetKey(entry.Key.Versions[entry.KeyVersion].KeyLabel, entry.Key.Versions[entry.KeyVersion].Password)
			if err != nil {
				return nil, err
			}
			entry.Key.UpdateKeyFromHSMWithRequest(key, *entry)
			if err := SetKey(ctx, req.Storage, entry.Request["key"], &entry.Key); err != nil {
				return nil, err
			}

		}

	}

	return &logical.Response{
		Data: entry.ToResponseData(),
	}, nil
}

// This function read all stored requests operation from Secrets Engine
func (b *SecurosysBackend) pathRequestsList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "requests/")
	if err != nil {
		return nil, err
	}
	requests := make([]string, 0, len(entries))
	requestInfo := make(map[string]interface{})
	for _, name := range entries {
		requests = append(requests, name)
		request, err := b.getRequest(ctx, req.Storage, name)
		if err == nil {
			if request.Status == "PENDING" {
				requestResponse, _, err := b.client.GetRequest(request.Id)
				if err != nil {
					request.Status = "ERROR"
				} else {
					request.UpdateStatus(*requestResponse)
				}
				if request.Status == "EXECUTED" && request.KeyUpdated == false && !helpers.Contains(helpers.UPDATE_POLICY_ON, request.Type) {
					request.KeyUpdated = true
					key, err := b.client.GetKey(request.Key.Versions[request.KeyVersion].KeyLabel, request.Key.Versions[request.KeyVersion].Password)
					if err != nil {
						return nil, err
					}
					request.Key.UpdateKeyFromHSMWithRequest(key, *request)
					if err := SetKey(ctx, req.Storage, request.Request["key"], &request.Key); err != nil {
						return nil, err
					}

				}
				if request.Status == "EXECUTED" && request.KeyUpdated == false && request.Type == "UnWrap" {
					request.KeyUpdated = true
					key, err := b.client.GetKey(request.Request["unwrapKeyName"], "")
					if err != nil {
						return nil, err
					}
					var newKey helpers.KeyEntry
					var newKeyVersion helpers.KeyVersion
					newKey.Algorithm = key.Algorithm
					newKeyVersion.AttestationKeyName = key.AttestationKeyName
					newKey.Attributes = key.Attributes
					newKey.CurveOid = key.CurveOid
					newKey.CurrentVersion = "v1"
					newKey.BaseLabel = strings.Replace(request.Request["unwrapKeyName"], "_v1", "", 1)
					newKeyVersion.KeyLabel = request.Request["unwrapKeyName"]
					newKey.KeySize = key.KeySize
					newKeyVersion.Policy = key.Policy
					newKeyVersion.PublicKey = key.PublicKey
					newKeyVersion.Xml = key.Xml
					newKeyVersion.Version = "v1"
					newKeyVersion.XmlSignature = key.XmlSignature

					created := request.Created
					created.Date = time.Now()
					newKey.Created = created
					newKey.Updated = created
					newKeyVersion.Created = created
					newKeyVersion.Updated = created

					newKey.Versions[newKey.CurrentVersion] = newKeyVersion
					if err := SetKey(ctx, req.Storage, request.Request["unwrapedKey"], &newKey); err != nil {
						return nil, err
					}

				}

			}
			var notYetApprovedByArray []string = make([]string, len(request.NotYetApprovedBy))
			for name, _ := range request.NotYetApprovedBy {
				notYetApprovedByArray = append(notYetApprovedByArray, name)
			}
			requestInfo[name] = map[string]interface{}{
				"ExecutionTime":  request.ExecutionTime,
				"Status":         request.Status,
				"Type":           request.Type,
				"NotYetApproved": notYetApprovedByArray,
				"Created":        request.Created.Name,
				"Updated":        request.Updated.Name,
			}
		}
	}
	return logical.ListResponseWithInfo(requests, requestInfo), nil
}

// This function helps saves requests inside Secrets Engine
func setRequest(ctx context.Context, s logical.Storage, name string, requestEntry *helpers.RequestEntry) error {
	entry, err := logical.StorageEntryJSON("requests/"+name, requestEntry)
	if err != nil {
		return err
	}

	if entry == nil {
		return fmt.Errorf("failed to create storage entry for request")
	}

	if err := s.Put(ctx, entry); err != nil {
		return err
	}

	return nil
}

// This function helps with getting requests from Secrets Engine
func (b *SecurosysBackend) getRequest(ctx context.Context, s logical.Storage, name string) (*helpers.RequestEntry, error) {
	if name == "" {
		return nil, fmt.Errorf("missing request name")
	}

	entry, err := s.Get(ctx, "requests/"+name)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, fmt.Errorf("Request with %s not exists", name)
	}

	var request helpers.RequestEntry

	if err := entry.DecodeJSON(&request); err != nil {
		return nil, err
	}
	if request.Status == "PENDING" && !helpers.Contains(helpers.UPDATE_POLICY_ON, request.Type) {
		requestResponse, _, err := b.client.GetRequest(request.Id)
		if err != nil {
			request.Status = "ERROR"
		} else {
			request.UpdateStatus(*requestResponse)
		}
		setRequest(ctx, s, name, &request)
	}
	if request.Status == "PENDING" && request.Type == "UnWrap" {
		request.KeyUpdated = true
		key, err := b.client.GetKey(request.Request["unwrapKeyName"], "")
		if err != nil {
			return nil, err
		}
		var newKey helpers.KeyEntry
		var newKeyVersion helpers.KeyVersion
		newKey.Algorithm = key.Algorithm
		newKeyVersion.AttestationKeyName = key.AttestationKeyName
		newKey.Attributes = key.Attributes
		newKey.CurveOid = key.CurveOid
		newKey.CurrentVersion = "v1"
		newKey.BaseLabel = strings.Replace(request.Request["unwrapKeyName"], "_v1", "", 1)
		newKeyVersion.KeyLabel = request.Request["unwrapKeyName"]
		newKey.KeySize = key.KeySize
		newKeyVersion.Policy = key.Policy
		newKeyVersion.PublicKey = key.PublicKey
		newKeyVersion.Xml = key.Xml
		newKeyVersion.Version = "v1"
		newKeyVersion.XmlSignature = key.XmlSignature

		created := request.Created
		created.Date = time.Now()
		newKey.Created = created
		newKey.Updated = created
		newKeyVersion.Created = created
		newKeyVersion.Updated = created

		if err := SetKey(ctx, s, request.Request["unwrapedKey"], &newKey); err != nil {
			return nil, err
		}

	}
	return &request, nil
}
