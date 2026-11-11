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

package testHelpers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// HostURL - Default Securosys TSB URL
const HostURL string = ""

// TSBClient struct
type TestTSBClient struct {
	HostURL    string
	HTTPClient *http.Client
}

// Function inicialize new client for accessing TSB
func NewTestTSBClient() (*TestTSBClient, error) {
	hostURL, ok := ConfigParams["restapi"].(string)
	if !ok || hostURL == "" {
		return nil, fmt.Errorf("missing restapi config; set TSB_URL or add it to .env")
	}

	c := TestTSBClient{
		HTTPClient: &http.Client{Timeout: 9999999 * time.Second},
		// Default Hashicups URL
		HostURL: hostURL,
	}

	return &c, nil
}

func HasApproverToken() bool {
	_, err := getApproverToken()
	return err == nil
}

func getApproverToken() (string, error) {
	apiKeysValue, ok := ConfigParams["apiKeys"]
	if !ok || apiKeysValue == nil {
		return "", fmt.Errorf("missing apiKeys config")
	}
	apiKeys, ok := apiKeysValue.(string)
	if !ok || apiKeys == "" {
		return "", fmt.Errorf("missing apiKeys config")
	}

	var apiKeysStruct ApiKeyTypes
	if err := json.Unmarshal([]byte(apiKeys), &apiKeysStruct); err != nil {
		return "", err
	}
	if len(apiKeysStruct.ApproverToken) == 0 || apiKeysStruct.ApproverToken[0] == "" {
		return "", fmt.Errorf("missing ApproverToken in apiKeys config")
	}
	return apiKeysStruct.ApproverToken[0], nil
}

// Function thats send request modify key to TSB

func (c *TestTSBClient) GetApprovalTasks(taskType string) (string, string, error) {
	return c.GetApprovalTask(taskType, "")
}

func (c *TestTSBClient) GetApprovalTask(taskType string, requestID string) (string, string, error) {
	path := ""
	switch taskType {
	case "Block":
		path = "/v1/filteredBlockKeyApprovalTask"
	case "Decrypt":
		path = "/v1/filteredDecryptApprovalTask"
	case "Modify":
		path = "/v1/filteredModifyKeyApprovalTask"
	case "Sign":
		path = "/v1/filteredSignApprovalTask"
	case "UnBlock":
		path = "/v1/filteredUnblockKeyApprovalTask"
	case "UnWrap":
		path = "/v1/filteredUnwrapKeyApprovalTask"
	}
	now := time.Now()

	// Convert the time to UTC
	utc := now.UTC()

	// Format the time using the same layout as JavaScript's toISOString()
	iso8601 := fmt.Sprintf("%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
		utc.Year(), utc.Month(), utc.Day(),
		utc.Hour(), utc.Minute(), utc.Second(), utc.Nanosecond()/1e6)

	var jsonStr = []byte(`{
		"timestamp":"` + iso8601 + `",
		"timestampSignature":"` + Sign([]byte(iso8601)) + `",
		"approverPublicKey":"` + GetPublicKey() + `",
		"detailLevel": "level5",
		"timestampDigestAlgorithm":"SHA-256",
		"paging": {
            "pageNumber": 0,
            "pageSize": 25,
		"sortOrder": "CREATION_DATE_ASC"
	}}`)
	req, err := http.NewRequest("POST", c.HostURL+path, bytes.NewBuffer(jsonStr))
	if err != nil {
		return "", "", err
	}
	body, _, err := c.doRequestApproval(req)
	if err != nil {
		return "", "", err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", "", err
	}
	tasks, ok := result["tasks"].([]interface{})
	if !ok || len(tasks) == 0 {
		return "", "", fmt.Errorf("no approval tasks found for %s", taskType)
	}

	for _, taskValue := range tasks {
		task, ok := taskValue.(map[string]interface{})
		if !ok {
			continue
		}
		id, _ := task["id"].(string)
		approvalToBeSigned, _ := task["approvalToBeSigned"].(string)
		if id == "" || approvalToBeSigned == "" {
			continue
		}
		if requestID == "" || id == requestID {
			return id, approvalToBeSigned, nil
		}
	}

	if requestID != "" {
		return "", "", fmt.Errorf("approval task %s for %s not found", requestID, taskType)
	}
	return "", "", fmt.Errorf("no valid approval tasks found for %s", taskType)
}
func (c *TestTSBClient) MakeApproval(id string, approvalToBeSigned string) (bool, error) {
	// Format the time using the same layout as JavaScript's toISOString()
	data, _ := base64.StdEncoding.DecodeString(approvalToBeSigned)
	var jsonStr = []byte(`{
		"signature":"` + Sign(data) + `",
		"approvalDigestAlgorithm":"SHA-256",
		"approverPublicKey":"` + GetPublicKey() + `",
		"approvalToBeSigned":"` + approvalToBeSigned + `",
		"id":"` + id + `"}`)
	req, err := http.NewRequest("POST", c.HostURL+"/v1/approval", bytes.NewBuffer(jsonStr))
	if err != nil {
		return false, err
	}
	_, code, err := c.doRequestApproval(req)
	if err != nil {
		return false, err
	}
	if code == 200 {
		return true, nil
	} else {
		return false, fmt.Errorf("Wrong result code. Expected 200 got %d", code)
	}
}

// Function that making all requests. Using config for Authorization to TSB

type ApiKeyTypes struct {
	KeyManagementToken         []string `json:"KeyManagementToken,omitempty"`
	KeyOperationToken          []string `json:"KeyOperationToken,omitempty"`
	ApproverToken              []string `json:"ApproverToken,omitempty"`
	ServiceToken               []string `json:"ServiceToken,omitempty"`
	ApproverKeyManagementToken []string `json:"ApproverKeyManagementToken,omitempty"`
}

func (c *TestTSBClient) doRequestApproval(req *http.Request) ([]byte, int, error) {
	// req.Header.Set("Authorization", c.Token)
	approverToken, err := getApproverToken()
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("X-API-KEY", approverToken)
	req.Header.Set("Content-Type", "application/json")

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		if res == nil {
			return nil, 0, err
		}
		return nil, res.StatusCode, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, res.StatusCode, err
	}

	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		return body, res.StatusCode, fmt.Errorf("status: %d, body: %s", res.StatusCode, body)
	}

	return body, res.StatusCode, err
}
