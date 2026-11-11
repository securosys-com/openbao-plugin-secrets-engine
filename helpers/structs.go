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

package helpers

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
)

// STRUCTS

// Structure for all asychnronous operations
type RequestResponse struct {
	Id               string   `json:"id"`
	Status           string   `json:"status"`
	ExecutionTime    string   `json:"executionTime"`
	ApprovedBy       []string `json:"approvedBy"`
	NotYetApprovedBy []string `json:"notYetApprovedBy"`
	RejectedBy       []string `json:"rejectedBy"`
	Result           string   `json:"result"`
}

// Structure for get key attributes response
type KeyAttributes struct {
	Label              string
	Attributes         map[string]bool
	KeySize            float64
	Policy             Policy
	PublicKey          string
	Algorithm          string
	AlgorithmOid       string
	CurveOid           string
	Version            string
	Active             bool
	Xml                string
	XmlSignature       string
	AttestationKeyName string
}

// SecurosysConfig includes the minimum configuration
// required to instantiate a new HashiCups client.
type SecurosysConfig struct {
	Auth               string `json:"auth"`
	BearerToken        string `json:"bearertoken"`
	Username           string `json:"username"`
	Password           string `json:"password"`
	BasicToken         string `json:"basictoken"`
	CertPath           string `json:"certpath"`
	KeyPath            string `json:"keypath"`
	RestApi            string `json:"restapi"`
	AppName            string `json:"appName"`
	ApplicationKeyPair string `json:"applicationKeyPair"`
	ApiKeys            string `json:"apiKeys"`
}

// Structure for certificate operations
type RequestResponseCertificate struct {
	Label       string `json:"label"`
	Certificate string `json:"certificate"`
}

// Structure for certificate operations
type RequestResponseImportCertificate struct {
	Label       string `json:"label"`
	Certificate string `json:"certificate"`
}

type GenerateCertificateRequest struct {
	// The same key id as passed in the request.
	KeyID        string            `json:"keyId"`
	PluginConfig map[string]string `json:"pluginConfig,omitempty"`
	Certificate  Certificate       `json:"certificate"`
}

type CertificateAttributes struct {
	CommonName           string  `json:"commonName"`
	Country              *string `json:"country"`
	StateOrProvinceName  *string `json:"stateOrProvinceName"`
	Locality             *string `json:"locality"`
	OrganizationName     *string `json:"organizationName"`
	OrganizationUnitName *string `json:"organizationUnitName"`
	Email                *string `json:"email"`
	Title                *string `json:"title"`
	Surname              *string `json:"surname"`
	GivenName            *string `json:"givenName"`
	Initials             *string `json:"initials"`
	Pseudonym            *string `json:"pseudonym"`
	GenerationQualifier  *string `json:"generationQualifier"`
}

func (ca *CertificateAttributes) ToString() string {
	respData := map[string]interface{}{
		"commonName":       ca.CommonName,
		"country":          ca.Country,
		"organizationName": ca.OrganizationName,
	}
	jsonStr, _ := json.Marshal(respData)
	return string(jsonStr[:])
}

type Certificate struct {
	Validity   int                   `json:"validity"`
	Attributes CertificateAttributes `json:"attributes"`
}

type ImportCertificateRequest struct {
	// The same key id as passed in the request.
	KeyID        string            `json:"keyId"`
	PluginConfig map[string]string `json:"pluginConfig,omitempty"`
}

type GenerateCertificateResponse struct {
	// The same key id as passed in the request.
	KeyID       string `json:"label"`
	Certificate string `json:"certificate"`
	KeyVersion  string `json:"keyVersion"`
}

type GenerateCertificateRequestResponse struct {
	// The same key id as passed in the request.
	KeyID              string `json:"label"`
	CertificateRequest string `json:"certificateSigningRequest"`
	KeyVersion         string `json:"keyVersion"`
}

type GenerateSelfSignedCertificateResponse struct {
	// The same key id as passed in the request.
	KeyID      string `json:"label"`
	KeyVersion string `json:"keyVersion"`

	CertificateRequest string `json:"certificate"`
}
type DecryptResponse struct {
	Payload string `json:"payload"`
}
type EncryptResponse struct {
	EncryptedPayload                                 string  `json:"encryptedPayload"`
	EncryptedPayloadWithoutMessageAuthenticationCode string  `json:"encryptedPayloadWithoutMessageAuthenticationCode"`
	InitializationVector                             *string `json:"initializationVector"`
	MessageAuthenticationCode                        *string `json:"messageAuthenticationCode"`
	KeyVersion                                       string  `json:"keyVersion"`
}
type SignatureResponse struct {
	Signature  string `json:"signature"`
	KeyVersion string `json:"keyVersion"`
}
type WrapResponse struct {
	WrappedKey string `json:"wrappedKey"`
	KeyVersion string `json:"keyVersion"`
}
type KeyEntry struct {
	BaseLabel      string                `json:"baseLabel"`
	Algorithm      string                `json:"algorithm"`
	AlgorithmOid   string                `json:"algorithmOid"`
	KeySize        float64               `json:"keySize"`
	KeyTypeName    string                `json:"keyTypeName"`
	Attributes     map[string]bool       `json:"attributes"`
	CurveOid       string                `json:"curveOid"`
	Versions       map[string]KeyVersion `json:"keyVersions"`
	Created        Entity                `json:"created"`
	Updated        Entity                `json:"updated"`
	CurrentVersion string                `json:"defaultVersion"`
}
type KeyVersion struct {
	KeyLabel           string `json:"keyLabel"`
	Version            string `json:"version"`
	Policy             Policy `json:"policy"`
	PublicKey          string `json:"publicKey"`
	PrivateKey         string `json:"privateKey"`
	SecretKey          string `json:"secretKey"`
	Certificate        string `json:"certificate"`
	Xml                string `json:"xml"`
	XmlSignature       string `json:"xmlSignature"`
	AttestationKeyName string `json:"attestationKeyName"`
	Password           string `json:"-"`
	Created            Entity `json:"created"`
	Updated            Entity `json:"updated"`
}

func (r *KeyVersion) ToResponseData(key KeyEntry) map[string]interface{} {
	respData := map[string]interface{}{
		"keyLabel":           r.KeyLabel,
		"policy":             r.Policy,
		"algorithm":          key.Algorithm,
		"algorithmOid":       key.AlgorithmOid,
		"keySize":            key.KeySize,
		"attributes":         key.Attributes,
		"publicKey":          r.PublicKey,
		"privateKey":         r.PrivateKey,
		"version":            r.Version,
		"secretKey":          r.SecretKey,
		"attestationKeyName": r.AttestationKeyName,
		"certificate":        r.Certificate,
		"curveOid":           key.CurveOid,
		"created":            r.Created,
		"updated":            r.Updated,
	}
	if key.KeySize == 0 {
		delete(respData, "keySize")
	}
	if r.SecretKey == "" {
		delete(respData, "secretKey")
	}
	if r.PrivateKey == "" {
		delete(respData, "privateKey")
	}
	if r.PublicKey == "" {
		delete(respData, "publicKey")
	}
	if r.SecretKey == "" {
		delete(respData, "secretKey")
	}
	if key.CurveOid == "" {
		delete(respData, "curveOid")
	}
	if r.Certificate == "" {
		delete(respData, "certificate")
	}
	if Contains(SYMMETRIC_KEY_TYPES, key.Algorithm) {
		delete(respData, "policy")
	}
	return respData
}

// This function prints names instead of public_key using policy
func (r *KeyEntry) GetPolicyWithName(policy []string, ruleType string) map[string]string {
	var list map[string]string = make(map[string]string)
	var policyTokens []token
	if ruleType == "Block" {
		policyTokens = r.Versions[r.CurrentVersion].Policy.RuleBlock.Tokens
	} else if ruleType == "UnBlock" {
		policyTokens = r.Versions[r.CurrentVersion].Policy.RuleUnBlock.Tokens
	} else if ruleType == "Modify" {
		policyTokens = r.Versions[r.CurrentVersion].Policy.RuleModify.Tokens
	} else {
		policyTokens = r.Versions[r.CurrentVersion].Policy.RuleUse.Tokens
	}

	for _, token := range policyTokens {
		for _, group := range token.Groups {
			for _, approval := range group.Approvals {
				if Contains(policy, *approval.Value) && approval.TypeOfKey == "public_key" {
					list[*approval.Name] = *approval.Value
				} else {
					cert, err := ReadCertificate(*approval.Value)
					if err == nil {
						for _, publicKey := range policy {
							key := BytesToPublicKey([]byte("-----BEGIN PUBLIC KEY-----\n" + publicKey + "\n-----END PUBLIC KEY-----"))
							keyAlgorithm := x509.RSA
							switch key.(type) {
							case *rsa.PublicKey:
								keyAlgorithm = x509.RSA
							case *ecdsa.PublicKey:
								keyAlgorithm = x509.ECDSA
							case *ed25519.PublicKey:
								keyAlgorithm = x509.Ed25519
							}
							switch cert.PublicKeyAlgorithm {
							case x509.RSA:
								if keyAlgorithm == x509.RSA {
									if cert.PublicKey.(*rsa.PublicKey).Equal(key.(*rsa.PublicKey)) {
										list[*approval.Name] = publicKey
									}
								}
								break
							case x509.ECDSA:
								if keyAlgorithm == x509.ECDSA {
									if cert.PublicKey.(*ecdsa.PublicKey).Equal(key.(*ecdsa.PublicKey)) {
										list[*approval.Name] = publicKey
									}
								}
								break
							case x509.Ed25519:
								if keyAlgorithm == x509.Ed25519 {
									if cert.PublicKey.(*ed25519.PublicKey).Equal(key.(*ed25519.PublicKey)) {
										list[*approval.Name] = publicKey
									}
								}
								break
							}
						}

					}
				}

			}
		}
	}

	return list
}

// This function prints key information
func (r *KeyEntry) ToResponseData() map[string]interface{} {

	respData := map[string]interface{}{
		"baseLabel":          r.BaseLabel,
		"keyLabel":           r.Versions[r.CurrentVersion].KeyLabel,
		"policy":             r.Versions[r.CurrentVersion].Policy,
		"algorithm":          r.Algorithm,
		"algorithmOid":       r.AlgorithmOid,
		"keySize":            r.KeySize,
		"attributes":         r.Attributes,
		"version":            r.CurrentVersion,
		"publicKey":          r.Versions[r.CurrentVersion].PublicKey,
		"privateKey":         r.Versions[r.CurrentVersion].PrivateKey,
		"secretKey":          r.Versions[r.CurrentVersion].SecretKey,
		"attestationKeyName": r.Versions[r.CurrentVersion].AttestationKeyName,
		"certificate":        r.Versions[r.CurrentVersion].Certificate,
		"curveOid":           r.CurveOid,
		"keyTypeName":        r.KeyTypeName,
		"created":            r.Created,
		"updated":            r.Updated,
	}
	if r.KeySize == 0 {
		delete(respData, "keySize")
	}
	if r.KeyTypeName == "" {
		delete(respData, "keyTypeName")
	}
	if r.Versions[r.CurrentVersion].SecretKey == "" {
		delete(respData, "secretKey")
	}
	if r.Versions[r.CurrentVersion].PrivateKey == "" {
		delete(respData, "privateKey")
	}
	if r.Versions[r.CurrentVersion].PublicKey == "" {
		delete(respData, "publicKey")
	}
	if r.Versions[r.CurrentVersion].SecretKey == "" {
		delete(respData, "secretKey")
	}
	if r.CurveOid == "" {
		delete(respData, "curveOid")
	}
	if r.Versions[r.CurrentVersion].Certificate == "" {
		delete(respData, "certificate")
	}
	if Contains(SYMMETRIC_KEY_TYPES, r.Algorithm) {
		delete(respData, "policy")

	}
	return respData
}

// This method updates key information based on changes in HSM
func (r *KeyEntry) UpdateKeyFromHSMWithRequest(key KeyAttributes, request RequestEntry) {
	if entry, ok := request.Key.Versions[request.KeyVersion]; ok {
		entry.Policy = key.Policy
		entry.Updated = request.Created

	}

	r.Updated = request.Created

}
func (r *KeyEntry) UpdateKeyFromHSM(key KeyAttributes) {
	if entry, ok := r.Versions[r.CurrentVersion]; ok {
		entry.Policy = key.Policy
	}
}
func (r *KeyEntry) GetActiveVersionKeyLabel() string {
	return r.Versions[r.CurrentVersion].KeyLabel
}
func (r *KeyEntry) GetActiveVersion() KeyVersion {
	return r.Versions[r.CurrentVersion]
}
func (r *KeyEntry) ModifyCurrentVersion() {
	lastKey := ""
	for _, version := range r.Versions {
		lastKey = version.Version
	}
	r.CurrentVersion = lastKey
}
func (r *KeyEntry) GetVersion(keyVersion string) KeyVersion {
	return r.Versions[keyVersion]
}

// This method prints XML and Signature for a key
func (r *KeyEntry) ToResponseDataXML() map[string]interface{} {
	respData := map[string]interface{}{
		"keyLabel":     r.Versions[r.CurrentVersion].KeyLabel,
		"xml":          r.Versions[r.CurrentVersion].Xml,
		"xmlSignature": r.Versions[r.CurrentVersion].XmlSignature,
	}
	return respData
}

type RequestEntry struct {
	Id               string            `json:"id"`
	Type             string            `json:"type"`
	Status           string            `json:"status"`
	ExecutionTime    string            `json:"executionTime"`
	ApprovedBy       map[string]string `json:"approvedBy"`
	NotYetApprovedBy map[string]string `json:"notYetApprovedBy"`
	RejectedBy       map[string]string `json:"rejectedBy"`
	KeyPassword      string            `json:"keyPassword"`
	Result           string            `json:"result"`
	Request          map[string]string `json:"request"`
	Key              KeyEntry          `json:"key"`
	KeyVersion       string            `json:"keyVersion"`
	KeyUpdated       bool              `json:"-"`
	Created          Entity            `json:"created"`
	Updated          Entity            `json:"updated"`
}

func (r *RequestEntry) UpdateStatus(request RequestResponse) {
	r.Result = request.Result
	r.Status = request.Status
	r.ExecutionTime = request.ExecutionTime
	r.ApprovedBy = r.Key.GetPolicyWithName(request.ApprovedBy, r.Type)
	r.NotYetApprovedBy = r.Key.GetPolicyWithName(request.NotYetApprovedBy, r.Type)
	r.RejectedBy = r.Key.GetPolicyWithName(request.RejectedBy, r.Type)

}

// toResponseData returns response data for a role
func (r *RequestEntry) ToResponseData() map[string]interface{} {
	respData := map[string]interface{}{
		"id":               r.Id,
		"type":             r.Type,
		"request":          r.Request,
		"status":           r.Status,
		"executionTime":    r.ExecutionTime,
		"approvedBy":       r.ApprovedBy,
		"notYetApprovedBy": r.NotYetApprovedBy,
		"rejectedBy":       r.RejectedBy,
		"result":           r.Result,
		"created":          r.Created,
		"updated":          r.Updated,
	}
	return respData
}

//END STRUCTS
