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

package helpers

import (
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

// INTEGRATION MARIADB STRUCTS
type Entity struct {
	Id      string           `json:"id"`
	Name    string           `json:"name"`
	Aliases []*logical.Alias `json:"aliases"`
	Date    time.Time        `json:"date"`
}
type MariaDBSecretEntry struct {
	KeyName        string                          `json:"keyName"`
	Versions       map[string]MariaDBSecretVersion `json:"secretVersions"`
	CurrentVersion string                          `json:"defaultVersion"`
	Created        Entity                          `json:"created"`
	Updated        Entity                          `json:"updated"`
}

// Struct of keys stored inside the Vault
type MariaDBSecretVersion struct {
	KeyVersion                string  `json:"keyVersion"`
	EncryptedSecret           string  `json:"encryptedSecret"`
	MessageAuthenticationCode *string `json:"messageAuthenticationCode"`
	InitializationVector      *string `json:"initializationVector"`
	Version                   string  `json:"version"`
	Created                   Entity  `json:"created"`
	Updated                   Entity  `json:"updated"`
}

func (s *MariaDBSecretEntry) InitSecret(keyName string, keyVersion string, messageAuthenticationCode *string, initializationVector *string, encryptedSecret string, creator Entity) {
	s.CurrentVersion = "v1"
	s.KeyName = keyName
	secretVersion := &MariaDBSecretVersion{}
	secretVersion.Version = "v1"
	secretVersion.KeyVersion = keyVersion
	secretVersion.EncryptedSecret = encryptedSecret
	secretVersion.MessageAuthenticationCode = messageAuthenticationCode
	secretVersion.InitializationVector = initializationVector
	secretVersion.Created = creator
	secretVersion.Updated = creator
	s.Created = creator
	s.Updated = creator
	s.Versions = make(map[string]MariaDBSecretVersion)
	s.Versions[s.CurrentVersion] = *secretVersion

}
func (s *MariaDBSecretEntry) RotateSecret(keyVersion string, messageAuthenticationCode *string, initializationVector *string, encryptedSecret string, updater Entity) {
	newSecretVersion := GetNewVersion(s.CurrentVersion)
	s.CurrentVersion = newSecretVersion
	secretVersion := &MariaDBSecretVersion{}
	secretVersion.Version = newSecretVersion
	secretVersion.KeyVersion = keyVersion
	secretVersion.EncryptedSecret = encryptedSecret
	secretVersion.MessageAuthenticationCode = messageAuthenticationCode
	secretVersion.InitializationVector = initializationVector
	secretVersion.Created = updater
	secretVersion.Updated = updater
	s.Updated = updater
	s.Versions[s.CurrentVersion] = *secretVersion

}
func (s *MariaDBSecretEntry) GetActiveVersion() MariaDBSecretVersion {
	return s.Versions[s.CurrentVersion]
}
func (s *MariaDBSecretEntry) GetVersion(keyVersion string) MariaDBSecretVersion {
	return s.Versions[keyVersion]
}

// END INTEGRATION MARIADB STRUCTS
