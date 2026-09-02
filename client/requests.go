/*
Copyright (c) 2023 Securosys SA, authors: Tomasz Madej, Mikolaj Szargut

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

package client

import (
	"bytes"
	"encoding/json"
	"net/http"

	helpers "securosys.ch/helpers"
)

// Function thats sends get request to TSB
func (c *TSBClient) GetRequest(id string) (*helpers.RequestResponse, int, error) {
	req, err := http.NewRequest("GET", c.HostURL+"/v1/request/"+id, bytes.NewBuffer(nil))
	if err != nil {
		return nil, 500, err
	}
	body, code, errRes := c.doRequest(req, KeyOperationTokenName)
	if errRes != nil {
		return nil, code, errRes
	}
	var requestResponse helpers.RequestResponse
	errJSON := json.Unmarshal(body, &requestResponse)
	if errJSON != nil {
		return nil, code, errJSON
	}
	return &requestResponse, code, nil
}

// Function thats sends delete request to TSB
func (c *TSBClient) RemoveRequest(id string) (int, error) {
	req, err := http.NewRequest("DELETE", c.HostURL+"/v1/request/"+id, nil)
	if err != nil {
		return 500, err
	}
	_, code, errReq := c.doRequest(req, KeyOperationTokenName)
	if code == 404 || code == 500 {
		return code, nil
	}
	if errReq != nil {
		return code, errReq
	}
	return code, nil

}
