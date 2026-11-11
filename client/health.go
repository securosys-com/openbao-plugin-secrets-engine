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

import "net/http"

func (c *TSBClient) CheckConnection() (string, int, error) {
	req, err := http.NewRequest("GET", c.HostURL+"/v1/keystore/statistics", nil)
	if err != nil {
		return "", 500, err
	}
	body, code, errReq := c.doRequest(req, ServiceTokenName)
	if errReq != nil {
		return string(body[:]), code, errReq
	}
	return string(body[:]), code, nil

}
