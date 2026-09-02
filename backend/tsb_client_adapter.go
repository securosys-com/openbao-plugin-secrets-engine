/*
Copyright (c) 2026 Securosys SA, authors: Tomasz Madej

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
	"encoding/json"

	tsb "github.com/securosys-com/tsb-client-go"
	tsbhelpers "github.com/securosys-com/tsb-client-go/helpers"
	helpers "securosys.ch/helpers"
)

type TSBClient struct {
	*tsb.SecurosysClient
}

func NewTSBClient(config *helpers.SecurosysConfig) (*TSBClient, error) {
	client, err := tsb.NewClient(toTSBConfig(config))
	if err != nil {
		return nil, err
	}

	return &TSBClient{SecurosysClient: client}, nil
}

func (c *TSBClient) UpdateKeyPassword(label string, password string, newPassword string) (string, error) {
	return c.SecurosysClient.UpdateKeyPassword(context.Background(), label, password, newPassword)
}

func (c *TSBClient) CreateOrUpdateKey(label string, password string, attributes map[string]bool, keytype string, keySize float64, policy *helpers.Policy, curveOid string, modify bool) (string, error) {
	return c.SecurosysClient.CreateOrUpdateKey(context.Background(), label, password, attributes, keytype, keySize, toTSBPolicyPtr(policy), curveOid, modify)
}

func (c *TSBClient) RemoveKey(keyLabel string) error {
	return c.SecurosysClient.RemoveKey(context.Background(), keyLabel)
}

func (c *TSBClient) ImportKey(label string, privateKey string, publicKey string, secretKey string, certificate string, attributes map[string]bool, keytype string, policy helpers.Policy) (map[string]interface{}, error) {
	return c.SecurosysClient.ImportKey(context.Background(), label, privateKey, publicKey, secretKey, certificate, attributes, keytype, toTSBPolicy(policy))
}

func (c *TSBClient) ExportKey(label string, password string) (map[string]interface{}, error) {
	return c.SecurosysClient.ExportKey(context.Background(), label, password)
}

func (c *TSBClient) GetKey(label string, password string) (helpers.KeyAttributes, error) {
	key, err := c.SecurosysClient.GetKey(context.Background(), label, password)
	if err != nil {
		return helpers.KeyAttributes{}, err
	}

	return fromTSBKeyAttributes(key), nil
}

func (c *TSBClient) GetKeys() ([]string, error) {
	return c.SecurosysClient.GetKeys(context.Background())
}

func (c *TSBClient) RemoveKeyAllVersions(key helpers.KeyEntry) error {
	for _, version := range key.Versions {
		if err := c.RemoveKey(version.KeyLabel); err != nil {
			return err
		}
	}

	return nil
}

func (c *TSBClient) RemoveKeyVersion(keys map[string]helpers.KeyVersion, version string) error {
	keyVersion, ok := keys[version]
	if !ok {
		return nil
	}

	return c.RemoveKey(keyVersion.KeyLabel)
}

func (c *TSBClient) Block(label string, password string) (int, error) {
	return c.SecurosysClient.Block(context.Background(), label, password)
}

func (c *TSBClient) AsyncBlock(label string, password string, customMetaData map[string]string) (string, int, error) {
	return c.SecurosysClient.AsyncBlock(context.Background(), label, password, customMetaData)
}

func (c *TSBClient) UnBlock(label string, password string) (int, error) {
	return c.SecurosysClient.UnBlock(context.Background(), label, password)
}

func (c *TSBClient) AsyncUnBlock(label string, password string, customMetaData map[string]string) (string, int, error) {
	return c.SecurosysClient.AsyncUnBlock(context.Background(), label, password, customMetaData)
}

func (c *TSBClient) Modify(label string, password string, policy helpers.Policy) (int, error) {
	return c.SecurosysClient.Modify(context.Background(), label, password, toTSBPolicy(policy))
}

func (c *TSBClient) AsyncModify(label string, password string, policy helpers.Policy, customMetaData map[string]string) (string, int, error) {
	return c.SecurosysClient.AsyncModify(context.Background(), label, password, toTSBPolicy(policy), customMetaData)
}

func (c *TSBClient) GetRequest(id string) (*helpers.RequestResponse, int, error) {
	request, code, err := c.SecurosysClient.GetRequest(context.Background(), id)
	return convertPtr[tsbhelpers.RequestResponse, helpers.RequestResponse](request), code, err
}

func (c *TSBClient) RemoveRequest(id string) (int, error) {
	return c.SecurosysClient.RemoveRequest(context.Background(), id)
}

func (c *TSBClient) Sign(label string, password string, payload string, payloadType string, signatureAlgorithm string) (*helpers.SignatureResponse, int, error) {
	response, code, err := c.SecurosysClient.Sign(context.Background(), label, password, payload, payloadType, tsb.SignatureAlgorithm(signatureAlgorithm), "")
	return convertPtr[tsbhelpers.SignatureResponse, helpers.SignatureResponse](response), code, err
}

func (c *TSBClient) AsyncSign(label string, password string, payload string, payloadType string, signatureAlgorithm string, customMetaData map[string]string) (string, int, error) {
	return c.SecurosysClient.AsyncSign(context.Background(), label, password, payload, payloadType, tsb.SignatureAlgorithm(signatureAlgorithm), "", customMetaData)
}

func (c *TSBClient) Verify(label string, password string, payload string, signatureAlgorithm string, signature string) (bool, int, error) {
	return c.SecurosysClient.Verify(context.Background(), label, password, payload, tsb.SignatureAlgorithm(signatureAlgorithm), signature)
}

func (c *TSBClient) AsyncDecrypt(label string, password string, cipertext string, vector string, cipherAlgorithm string, tagLength int, additionalAuthenticationData string, customMetaData map[string]string) (string, int, error) {
	return c.SecurosysClient.AsyncDecrypt(context.Background(), label, password, cipertext, vector, tsb.CipherAlgorithm(cipherAlgorithm), tagLength, additionalAuthenticationData, customMetaData)
}

func (c *TSBClient) Decrypt(label string, password string, cipertext string, vector string, cipherAlgorithm string, tagLength int, additionalAuthenticationData string) (*helpers.DecryptResponse, int, error) {
	response, code, err := c.SecurosysClient.Decrypt(context.Background(), label, password, cipertext, vector, tsb.CipherAlgorithm(cipherAlgorithm), tagLength, additionalAuthenticationData)
	return convertPtr[tsbhelpers.DecryptResponse, helpers.DecryptResponse](response), code, err
}

func (c *TSBClient) Encrypt(label string, password string, payload string, cipherAlgorithm string, tagLength int, additionalAuthenticationData string) (*helpers.EncryptResponse, int, error) {
	response, code, err := c.SecurosysClient.Encrypt(context.Background(), label, password, payload, tsb.CipherAlgorithm(cipherAlgorithm), tagLength, additionalAuthenticationData)
	return convertPtr[tsbhelpers.EncryptResponse, helpers.EncryptResponse](response), code, err
}

func (c *TSBClient) Wrap(wrapKeyName string, wrapKeyPassword string, keyToBeWrapped string, keyToBeWrappedPassword string, wrapMethod string) (*helpers.WrapResponse, int, error) {
	response, code, err := c.SecurosysClient.Wrap(wrapKeyName, wrapKeyPassword, keyToBeWrapped, keyToBeWrappedPassword, tsb.WrapMethod(wrapMethod))
	return convertPtr[tsbhelpers.WrapResponse, helpers.WrapResponse](response), code, err
}

func (c *TSBClient) AsyncUnWrap(wrappedKey string, label string, attributes map[string]bool, unwrapKeyName string, unwrapKeyPassword string, wrapMethod string, policy *helpers.Policy, customMetaData map[string]string) (string, int, error) {
	return c.SecurosysClient.AsyncUnWrap(wrappedKey, label, attributes, unwrapKeyName, unwrapKeyPassword, tsb.WrapMethod(wrapMethod), toTSBPolicyPtr(policy), customMetaData)
}

func (c *TSBClient) UnWrap(wrappedKey string, label string, attributes map[string]bool, unwrapKeyName string, unwrapKeyPassword string, wrapMethod string, policy *helpers.Policy) (int, error) {
	return c.SecurosysClient.UnWrap(wrappedKey, label, attributes, unwrapKeyName, unwrapKeyPassword, tsb.WrapMethod(wrapMethod), toTSBPolicyPtr(policy))
}

func (c *TSBClient) CreateCertificate(signKeyName string, keyPassword string, signatureAlgorithm string, validity int, certAttributes helpers.CertificateAttributes, keyUsage []string, extendedKeyUsage []string) (*helpers.GenerateCertificateRequestResponse, int, error) {
	response, code, err := c.SecurosysClient.CreateCertificate(signKeyName, keyPassword, signatureAlgorithm, validity, convert[helpers.CertificateAttributes, tsbhelpers.CertificateAttributes](certAttributes), keyUsage, extendedKeyUsage)
	return convertPtr[tsbhelpers.GenerateCertificateRequestResponse, helpers.GenerateCertificateRequestResponse](response), code, err
}

func (c *TSBClient) CreateSelfSignedCertificate(signKeyName string, keyPassword string, signatureAlgorithm string, validity int, commonName string, keyUsage []string, extendedKeyUsage []string, certificateAuthority bool) (*helpers.GenerateSelfSignedCertificateResponse, int, error) {
	response, code, err := c.SecurosysClient.CreateSelfSignedCertificate(signKeyName, keyPassword, signatureAlgorithm, validity, commonName, keyUsage, extendedKeyUsage, certificateAuthority)
	return convertPtr[tsbhelpers.GenerateSelfSignedCertificateResponse, helpers.GenerateSelfSignedCertificateResponse](response), code, err
}

func (c *TSBClient) SignCertificate(signKeyName string, keyPassword string, signatureAlgorithm string, certificateSigningRequest string, commonName string, keyUsage []string, extendedKeyUsage []string, certificateAuthority bool) (*helpers.GenerateSelfSignedCertificateResponse, int, error) {
	response, code, err := c.SecurosysClient.SignCertificate(signKeyName, keyPassword, signatureAlgorithm, certificateSigningRequest, commonName, keyUsage, extendedKeyUsage, certificateAuthority)
	return convertPtr[tsbhelpers.GenerateSelfSignedCertificateResponse, helpers.GenerateSelfSignedCertificateResponse](response), code, err
}

func (c *TSBClient) AsyncCreateCertificate(signKeyName string, keyPassword string, signatureAlgorithm string, validity int, certAttributes helpers.CertificateAttributes, keyUsage []string, extendedKeyUsage []string, userMetaData map[string]string) (string, int, error) {
	return c.SecurosysClient.AsyncCreateCertificate(signKeyName, keyPassword, signatureAlgorithm, validity, convert[helpers.CertificateAttributes, tsbhelpers.CertificateAttributes](certAttributes), keyUsage, extendedKeyUsage, userMetaData)
}

func (c *TSBClient) AsyncSelfSignedCertificate(signKeyName string, keyPassword string, signatureAlgorithm string, validity int, commonName string, keyUsage []string, extendedKeyUsage []string, certificateAuthority bool, userMetaData map[string]string) (string, int, error) {
	return c.SecurosysClient.AsyncSelfSignedCertificate(signKeyName, keyPassword, signatureAlgorithm, validity, commonName, keyUsage, extendedKeyUsage, certificateAuthority, userMetaData)
}

func (c *TSBClient) AsyncSignCertificate(signKeyName string, keyPassword string, signatureAlgorithm string, certificateSigningRequest string, commonName string, keyUsage []string, extendedKeyUsage []string, certificateAuthority bool, userMetaData map[string]string) (string, int, error) {
	return c.SecurosysClient.AsyncSignCertificate(signKeyName, keyPassword, signatureAlgorithm, certificateSigningRequest, commonName, keyUsage, extendedKeyUsage, certificateAuthority, userMetaData)
}

func (c *TSBClient) ImportCertificate(label string, certificate string) (*helpers.RequestResponseImportCertificate, int, error) {
	response, code, err := c.SecurosysClient.ImportCertificate(label, certificate)
	return convertPtr[tsbhelpers.RequestResponseImportCertificate, helpers.RequestResponseImportCertificate](response), code, err
}

func (c *TSBClient) GetCertificate(label string) (*helpers.RequestResponseCertificate, int, error) {
	response, code, err := c.SecurosysClient.GetCertificate(label)
	return convertPtr[tsbhelpers.RequestResponseCertificate, helpers.RequestResponseCertificate](response), code, err
}

func (c *TSBClient) DeleteCertificate(label string) (int, error) {
	return c.SecurosysClient.DeleteCertificate(label)
}

func (c *TSBClient) CheckConnection() (string, int, error) {
	return c.SecurosysClient.CheckConnection(context.Background())
}

func toTSBConfig(config *helpers.SecurosysConfig) *tsbhelpers.SecurosysConfig {
	if config == nil {
		return nil
	}

	return &tsbhelpers.SecurosysConfig{
		Auth:               config.Auth,
		BearerToken:        config.BearerToken,
		CertPath:           config.CertPath,
		KeyPath:            config.KeyPath,
		RestApi:            config.RestApi,
		AppName:            config.AppName,
		ApplicationKeyPair: config.ApplicationKeyPair,
		ApiKeys:            config.ApiKeys,
	}
}

func toTSBPolicy(policy helpers.Policy) tsbhelpers.Policy {
	return convert[helpers.Policy, tsbhelpers.Policy](policy)
}

func toTSBPolicyPtr(policy *helpers.Policy) *tsbhelpers.Policy {
	return convertPtr[helpers.Policy, tsbhelpers.Policy](policy)
}

func fromTSBKeyAttributes(key tsbhelpers.KeyAttributes) helpers.KeyAttributes {
	return convert[tsbhelpers.KeyAttributes, helpers.KeyAttributes](key)
}

func convert[S any, D any](src S) D {
	var dst D
	data, _ := json.Marshal(src)
	_ = json.Unmarshal(data, &dst)
	return dst
}

func convertPtr[S any, D any](src *S) *D {
	if src == nil {
		return nil
	}

	dst := convert[S, D](*src)
	return &dst
}
