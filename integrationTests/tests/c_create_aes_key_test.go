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

package integrationTests

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"testing"

	"github.com/hashicorp/vault-client-go"
	"github.com/stretchr/testify/assert"
	integrationClient "securosys.ch/integration/client"
)

func TestCreateAESKeyPlugin(t *testing.T) {

	t.Run("C.1 Test Create Key AES Key with name integrationTestKeyAES", func(t *testing.T) {
		ctx := context.Background()

		client:=integrationClient.InitVaultClient()
		
		resp,err:=client.Write(ctx,integrationClient.VaultConfig.SecretsEnginePath+"/keys/aes/integration_test_key_aes",map[string]interface{}{
			"keyLabel":"integrationTestKeyAES",
			"keySize":256,
			"attributes": `{
				"decrypt": true,
				"sign": false,
				"unwrap": true,
				"derive": true,
				"sensitive": false,
				"alwaysSensitive": false,
				"extractable": true,
				"neverExtractable": true,
				"modifiable": true,
				"copyable": false,
				"destroyable": true
			}`,
		})		
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp==nil || resp.Data==nil{
			assert.FailNow(t, fmt.Errorf("Expected: Key response got %s","null").Error())
		}
		if(resp.Data["algorithm"].(string)!="AES"){
			assert.FailNow(t, fmt.Errorf("Expected: Key type %s got %s","AES",resp.Data["algorithm"]).Error())
		}
		if(resp.Data["baseLabel"].(string)!="integrationTestKeyAES"){
			assert.FailNow(t, fmt.Errorf("Expected: Key name %s got %s","integrationTestKeyAES",resp.Data["baseLabel"]).Error())
		}
		if(resp.Data["version"].(string)!="v1"){
			assert.FailNow(t, fmt.Errorf("Expected: Key version %s got %s","v1",resp.Data["version"]).Error())
		}
		if(resp.Data["keySize"].(json.Number)!=json.Number("256")){
			assert.FailNow(t, fmt.Errorf("Expected: Key size %s got %s","256",resp.Data["keySize"]).Error())
		}
		if(resp.Data["keyLabel"].(string)!="integrationTestKeyAES_v1"){
			assert.FailNow(t, fmt.Errorf("Expected: Key label %s got %s","integrationTestKeyAES_v1",resp.Data["keyLabel"]).Error())
		}
	})
	t.Run("C.2 Test List Keys", func(t *testing.T) {
		ctx := context.Background()

		client:=integrationClient.InitVaultClient()
		resp,err:=client.List(ctx,integrationClient.VaultConfig.SecretsEnginePath+"/keys/")		
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp==nil || resp.Data==nil{
			assert.FailNow(t, fmt.Errorf("Expected: List of keys got %s","null").Error())
		}
		if(resp.Data["key_info"]==nil){
			assert.FailNow(t, fmt.Errorf("Expected: List of keys got %s","null").Error())

		}
		keyInfo:=resp.Data["key_info"].(map[string]interface{});
		if(keyInfo==nil){
			assert.FailNow(t, fmt.Errorf("Expected: List of keys got %s","null").Error())
		}
		if(keyInfo["integration_test_key_aes"]==nil){
			assert.FailNow(t, fmt.Errorf("Expected: integration_test_key_aes got %s","null").Error())
		}
	})
	t.Run("C.3 Read AES Key with name integrationTestKeyAES", func(t *testing.T) {
		ctx := context.Background()

		client:=integrationClient.InitVaultClient()
		
		resp,err:=client.Read(ctx,integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_aes")		
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp==nil || resp.Data==nil{
			assert.FailNow(t, fmt.Errorf("Expected: Key response got %s","null").Error())
		}
		if(resp.Data["algorithm"].(string)!="AES"){
			assert.FailNow(t, fmt.Errorf("Expected: Key type %s got %s","AES",resp.Data["algorithm"]).Error())
		}
		if(resp.Data["baseLabel"].(string)!="integrationTestKeyAES"){
			assert.FailNow(t, fmt.Errorf("Expected: Key name %s got %s","integrationTestKeyAES",resp.Data["baseLabel"]).Error())
		}
		if(resp.Data["version"].(string)!="v1"){
			assert.FailNow(t, fmt.Errorf("Expected: Key version %s got %s","v1",resp.Data["version"]).Error())
		}
		if(resp.Data["keySize"].(json.Number)!=json.Number("256")){
			assert.FailNow(t, fmt.Errorf("Expected: Key size %s got %s","256",resp.Data["keySize"]).Error())
		}
		if(resp.Data["keyLabel"].(string)!="integrationTestKeyAES_v1"){
			assert.FailNow(t, fmt.Errorf("Expected: Key label %s got %s","integrationTestKeyAES_v1",resp.Data["keyLabel"]).Error())
		}
	})
	t.Run("C.4 Rotate AES Key with name integrationTestKeyAES", func(t *testing.T) {
		ctx := context.Background()

		client:=integrationClient.InitVaultClient()
		
		_,err:=client.Write(ctx,integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_aes/rotate",map[string]interface{}{})		
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		resp,_:=client.Read(ctx,integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_aes")		
		if resp==nil || resp.Data==nil{
			assert.FailNow(t, fmt.Errorf("Expected: Key response got %s","null").Error())
		}
		if(resp.Data["algorithm"].(string)!="AES"){
			assert.FailNow(t, fmt.Errorf("Expected: Key type %s got %s","AES",resp.Data["algorithm"]).Error())
		}
		if(resp.Data["baseLabel"].(string)!="integrationTestKeyAES"){
			assert.FailNow(t, fmt.Errorf("Expected: Key name %s got %s","integrationTestKeyAES",resp.Data["baseLabel"]).Error())
		}
		if(resp.Data["version"].(string)!="v2"){
			assert.FailNow(t, fmt.Errorf("Expected: Key version %s got %s","v2",resp.Data["version"]).Error())
		}
		if(resp.Data["keySize"].(json.Number)!=json.Number("256")){
			assert.FailNow(t, fmt.Errorf("Expected: Key size %s got %s","256",resp.Data["keySize"]).Error())
		}
		if(resp.Data["keyLabel"].(string)!="integrationTestKeyAES_v2"){
			assert.FailNow(t, fmt.Errorf("Expected: Key Label %s got %s","integrationTestKeyAES_v2",resp.Data["keyLabel"]).Error())
		}
	})
	t.Run("C.5 Test List Versions of Key integrationTestKeyAES", func(t *testing.T) {
		ctx := context.Background()

		client:=integrationClient.InitVaultClient()
		resp,err:=client.List(ctx,integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_aes")		
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp==nil || resp.Data==nil{
			assert.FailNow(t, fmt.Errorf("Expected: List of key versions got %s","null").Error())
		}
		if(resp.Data["key_info"]==nil){
			assert.FailNow(t, fmt.Errorf("Expected: List of key versions got %s","null").Error())

		}
		keyInfo:=resp.Data["key_info"].(map[string]interface{});
		if(keyInfo==nil){
			assert.FailNow(t, fmt.Errorf("Expected: List of key versions got %s","null").Error())
		}
		if(keyInfo["v1"]==nil){
			assert.FailNow(t, fmt.Errorf("Expected: v1 got %s","null").Error())
		}
		if(keyInfo["v2"]==nil){
			assert.FailNow(t, fmt.Errorf("Expected: v2 got %s","null").Error())
		}
	})
	t.Run("C.6 Test List Versions of Key integrationTestKeyAES", func(t *testing.T) {
		ctx := context.Background()

		client:=integrationClient.InitVaultClient()
		resp,_:=client.Read(ctx,integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_aes/v2")		
		if resp==nil || resp.Data==nil{
			assert.FailNow(t, fmt.Errorf("Expected: Key response got %s","null").Error())
		}
		if(resp.Data["algorithm"].(string)!="AES"){
			assert.FailNow(t, fmt.Errorf("Expected: Key type %s got %s","AES",resp.Data["algorithm"]).Error())
		}
		if(resp.Data["version"].(string)!="v2"){
			assert.FailNow(t, fmt.Errorf("Expected: Key version %s got %s","v2",resp.Data["version"]).Error())
		}
		if(resp.Data["keySize"].(json.Number)!=json.Number("256")){
			assert.FailNow(t, fmt.Errorf("Expected: Key size %s got %s","256",resp.Data["keySize"]).Error())
		}
		if(resp.Data["keyLabel"].(string)!="integrationTestKeyAES_v2"){
			assert.FailNow(t, fmt.Errorf("Expected: Key Label %s got %s","integrationTestKeyAES_v2",resp.Data["keyLabel"]).Error())
		}
	})	
	t.Run("C.7 Export AES Key with name integrationTestKeyAES", func(t *testing.T) {
		ctx := context.Background()

		client:=integrationClient.InitVaultClient()
		
		resp ,err:=client.Write(ctx,integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_aes/export",map[string]interface{}{})		
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if(resp.Data["secretKey"]==nil){
			assert.FailNow(t, fmt.Errorf("Expected: Key Secret got %s","null").Error())
		}
	})
	t.Run("C.8 Test Remove Key AES Key with name integrationTestKeyAES", func(t *testing.T) {
		ctx := context.Background()

		client:=integrationClient.InitVaultClient()
		_,err:=client.Delete(ctx,integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_aes",vault.WithQueryParameters(url.Values{
			"removeFromHSM": {"true"},
		}))		
		if err != nil {
			assert.FailNow(t, err.Error())
		}
	})
}



