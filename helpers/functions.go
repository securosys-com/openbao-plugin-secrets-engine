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
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/rand"
	"reflect"
	"strconv"
	"strings"
	"time"
)

type approval struct {
	TypeOfKey string  `json:"type"`
	Name      *string `json:"name"`
	Value     *string `json:"value"`
}
type group struct {
	Name      string     `json:"name"`
	Quorum    int        `json:"quorum"`
	Approvals []approval `json:"approvals"`
}
type token struct {
	Name     string  `json:"name"`
	Timelock int     `json:"timelock"`
	Timeout  int     `json:"timeout"`
	Groups   []group `json:"groups"`
}
type rule struct {
	Tokens []token `json:"tokens"`
}
type keyStatus struct {
	Blocked bool `json:"blocked"`
}

// Policy structure for rules use, block, unblock, modify
type Policy struct {
	RuleUse     rule       `json:"ruleUse"`
	RuleBlock   *rule      `json:"ruleBlock,omitempty"`
	RuleUnBlock *rule      `json:"ruleUnblock,omitempty"`
	RuleModify  *rule      `json:"ruleModify,omitempty"`
	KeyStatus   *keyStatus `json:"keyStatus,omitempty"`
}

// Function converts string into char array
func StringToCharArray(text string) []string {
	var array []string = make([]string, 0)
	for i := 0; i < len(text); i++ {
		array = append(array, string(text[i]))
	}
	return array
}

// Function that helps fill a policy structure
func PreparePolicy(policyString string, simplified bool) (*Policy, error) {
	return PrepareFullPolicy(policyString, simplified, true)
}

// Function that checking if key exists in map
func ContainsKey(m, k interface{}) bool {
	v := reflect.ValueOf(m).MapIndex(reflect.ValueOf(k))
	return v != reflect.Value{}
}
func ParsePublicKeyString(publicKey string) (crypto.PublicKey, error) {
	var pkForImportingKey crypto.PublicKey
	spkiBlock, _ := pem.Decode(WrapPublicKeyWithHeaders(publicKey))
	if spkiBlock == nil {
		return nil, fmt.Errorf("Cannot parse public key")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(spkiBlock.Bytes)
	if err != nil {
		return nil, err
	}
	pkForImportingKey = pubInterface
	return pkForImportingKey, nil
}
func WrapPublicKeyWithHeaders(publicKey string) []byte {
	return []byte("-----BEGIN PUBLIC KEY-----\n" + publicKey + "\n-----END PUBLIC KEY-----")
}

// This function preparing Policy structure for generating asynchronous keys
func PrepareFullPolicy(policyString string, simplified bool, addKeyStatus bool) (*Policy, error) {
	var PolicyObj Policy
	if simplified == true {
		var simplePolicy map[string]string
		err := json.Unmarshal([]byte(policyString), &simplePolicy)
		if err != nil {
			return nil, err
		}
		token := PreparePolicyTokens(simplePolicy)
		PolicyObj.RuleUse.Tokens = append(PolicyObj.RuleUse.Tokens, token)
		PolicyObj.RuleBlock = new(rule)
		PolicyObj.RuleBlock.Tokens = append(PolicyObj.RuleBlock.Tokens, token)
		PolicyObj.RuleUnBlock = new(rule)
		PolicyObj.RuleUnBlock.Tokens = append(PolicyObj.RuleUnBlock.Tokens, token)
		PolicyObj.RuleModify = new(rule)
		PolicyObj.RuleModify.Tokens = append(PolicyObj.RuleModify.Tokens, token)
		if addKeyStatus == true {
			PolicyObj.KeyStatus = new(keyStatus)
			PolicyObj.KeyStatus.Blocked = false
		}
	} else {
		err := json.Unmarshal([]byte(policyString), &PolicyObj)
		if err != nil {
			return nil, err
		}
		if addKeyStatus == false {
			PolicyObj.KeyStatus = nil
		}

	}
	return &PolicyObj, nil
}

// This function groups from simplePolicy parameter sended with keys

func PreparePolicyTokens(policy map[string]string) token {
	var group group
	group.Name = "main"
	group.Quorum = len(policy)
	for name, element := range policy {
		var approval approval
		clonedName := name
		clonedElement := element
		_, err := ReadCertificate(element)
		if err == nil {
			approval.TypeOfKey = "certificate"
			approval.Value = &clonedElement
		} else {
			_, err := ParsePublicKeyString(element)
			if err == nil {
				approval.TypeOfKey = "public_key"
				approval.Name = &clonedName
				approval.Value = &clonedElement
			} else {
				approval.TypeOfKey = "onboarded_approver_certificate"
				approval.Name = &clonedElement
			}
		}

		group.Approvals = append(group.Approvals, approval)
	}

	var token token
	token.Name = "main"
	token.Timeout = 0
	token.Timelock = 0
	if len(policy) == 0 {
		token.Groups = nil
	} else {
		token.Groups = append(token.Groups, group)

	}

	return token

}

// Function converts attributes map into a json
func PrepareAttributes(attributes map[string]bool) string {
	json, _ := json.Marshal(attributes)
	return string(json)

}

// Function checking if string exits in string array
func Contains(s []string, str string) bool {
	for _, v := range s {
		if strings.ToLower(v) == strings.ToLower(str) {
			return true
		}
	}

	return false
}

// Function returns new version of key
func GetNewVersion(version string) string {
	versionString := strings.Replace(version, "v", "", 1)
	versionInt, _ := strconv.Atoi(versionString)
	newVersion := "v" + strconv.Itoa(versionInt+1)
	return newVersion
}
func GetVersionNumber(version string) int {
	versionString := strings.Replace(version, "v", "", 1)
	versionInt, _ := strconv.Atoi(versionString)
	return versionInt
}
func GetVersionString(version string) string {
	return strings.Replace(version, "v", "", 1)
}

// Function preparing MetaData, which We are send with all asynchronous requests
func PrepareMetaData(requestType string, additionalMetaData map[string]string, customMetaData map[string]string) (string, string, error) {
	now := time.Now().UTC()
	var metaData map[string]string = make(map[string]string)
	metaData["time"] = fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02dZ", now.Year(), int(now.Month()), now.Day(), now.Hour(), now.Minute(), now.Second())
	metaData["app"] = "OpenBao - Securosys HSM Secrets Engine"
	metaData["type"] = requestType
	for key, value := range additionalMetaData {
		metaData[key] = value
	}
	for key, value := range customMetaData {
		metaData[key] = value
	}
	metaJsonStr, errMarshal := json.Marshal(metaData)
	if errMarshal != nil {
		return "", "", errMarshal
	}
	h := sha256.New()
	h.Write(metaJsonStr)
	bs := h.Sum(nil)
	return b64.StdEncoding.EncodeToString(metaJsonStr),
		b64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(bs))), nil
}

const (
	letterBytes     = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	specialBytes    = "!@#$%^&*()_+-=[]{}\\|;':\",.<>/?`~"
	numBytes        = "0123456789"
	hexDecimalBytes = "0123456789ABCDEF"
)

func MinifyJson(requestData string) string {
	dst := &bytes.Buffer{}
	if err := json.Compact(dst, []byte(requestData)); err != nil {
		panic(err)
	}
	return dst.String()

}

func GeneratePassword(length int, useLetters bool, useSpecial bool, useNum bool, useHexadecimal bool) string {
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, length)
	arrayForRandom := make([]byte, 0)
	if useLetters {
		arrayForRandom = append(arrayForRandom, letterBytes...)
	}
	if useSpecial {
		arrayForRandom = append(arrayForRandom, specialBytes...)
	}
	if useNum {
		arrayForRandom = append(arrayForRandom, numBytes...)
	}
	if useHexadecimal {
		arrayForRandom = append(arrayForRandom, hexDecimalBytes...)

	}

	for i := range b {
		b[i] = arrayForRandom[rand.Intn(len(arrayForRandom))]
	}
	return string(b)
}
func ReadCertificate(possibleCertificate string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte("-----BEGIN CERTIFICATE-----\n" + possibleCertificate + "\n-----END CERTIFICATE-----\n"))
	if block == nil {
		return nil, fmt.Errorf("Cannot read certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}
func BytesToPublicKey(pub []byte) any {
	block, _ := pem.Decode(pub)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return nil
		}
	}
	ifc, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		return nil
	}
	return ifc
}
