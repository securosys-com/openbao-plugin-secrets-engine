package tests

import (
	"context"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

const pqcSignaturePayload = "cGF5bG9hZA=="

type pqcSignatureCase struct {
	name               string
	keyAlgorithm       string
	signatureAlgorithm string
}

func pqcSignatureCases() []pqcSignatureCase {
	return []pqcSignatureCase{
		{name: "ML-DSA ML_DSA", keyAlgorithm: "ML-DSA-44", signatureAlgorithm: "ML_DSA"},
		{name: "ML-DSA ML_DSA_M", keyAlgorithm: "ML-DSA-44", signatureAlgorithm: "ML_DSA_M"},
		{name: "ML-DSA SHA2_224", keyAlgorithm: "ML-DSA-44", signatureAlgorithm: "SHA2_224_WITH_ML_DSA"},
		{name: "ML-DSA SHA2_256", keyAlgorithm: "ML-DSA-44", signatureAlgorithm: "SHA2_256_WITH_ML_DSA"},
		{name: "ML-DSA SHA2_384", keyAlgorithm: "ML-DSA-44", signatureAlgorithm: "SHA2_384_WITH_ML_DSA"},
		{name: "ML-DSA SHA2_512", keyAlgorithm: "ML-DSA-44", signatureAlgorithm: "SHA2_512_WITH_ML_DSA"},
		{name: "ML-DSA SHA3_224", keyAlgorithm: "ML-DSA-44", signatureAlgorithm: "SHA3_224_WITH_ML_DSA"},
		{name: "ML-DSA SHA3_256", keyAlgorithm: "ML-DSA-44", signatureAlgorithm: "SHA3_256_WITH_ML_DSA"},
		{name: "ML-DSA SHA3_384", keyAlgorithm: "ML-DSA-44", signatureAlgorithm: "SHA3_384_WITH_ML_DSA"},
		{name: "ML-DSA SHA3_512", keyAlgorithm: "ML-DSA-44", signatureAlgorithm: "SHA3_512_WITH_ML_DSA"},
		{name: "ML-DSA SHAKE_128", keyAlgorithm: "ML-DSA-44", signatureAlgorithm: "SHAKE_128_WITH_ML_DSA"},
		{name: "ML-DSA SHAKE_256", keyAlgorithm: "ML-DSA-44", signatureAlgorithm: "SHAKE_256_WITH_ML_DSA"},
		{name: "SLH-DSA SLH_DSA", keyAlgorithm: "SLH-DSA-SHA2-128f", signatureAlgorithm: "SLH_DSA"},
		{name: "SLH-DSA SHA2_224", keyAlgorithm: "SLH-DSA-SHA2-128f", signatureAlgorithm: "SHA2_224_WITH_SLH_DSA"},
		{name: "SLH-DSA SHA2_256", keyAlgorithm: "SLH-DSA-SHA2-128f", signatureAlgorithm: "SHA2_256_WITH_SLH_DSA"},
		{name: "SLH-DSA SHA2_384", keyAlgorithm: "SLH-DSA-SHA2-128f", signatureAlgorithm: "SHA2_384_WITH_SLH_DSA"},
		{name: "SLH-DSA SHA2_512", keyAlgorithm: "SLH-DSA-SHA2-128f", signatureAlgorithm: "SHA2_512_WITH_SLH_DSA"},
		{name: "SLH-DSA SHA3_224", keyAlgorithm: "SLH-DSA-SHA2-128f", signatureAlgorithm: "SHA3_224_WITH_SLH_DSA"},
		{name: "SLH-DSA SHA3_256", keyAlgorithm: "SLH-DSA-SHA2-128f", signatureAlgorithm: "SHA3_256_WITH_SLH_DSA"},
		{name: "SLH-DSA SHA3_384", keyAlgorithm: "SLH-DSA-SHA2-128f", signatureAlgorithm: "SHA3_384_WITH_SLH_DSA"},
		{name: "SLH-DSA SHA3_512", keyAlgorithm: "SLH-DSA-SHA2-128f", signatureAlgorithm: "SHA3_512_WITH_SLH_DSA"},
		{name: "SLH-DSA SHAKE_128", keyAlgorithm: "SLH-DSA-SHAKE-128f", signatureAlgorithm: "SHAKE_128_WITH_SLH_DSA"},
		{name: "SLH-DSA SHAKE_256", keyAlgorithm: "SLH-DSA-SHAKE-128f", signatureAlgorithm: "SHAKE_256_WITH_SLH_DSA"},
		{name: "LMS", keyAlgorithm: "LMS", signatureAlgorithm: "LMS"},
		{name: "XMSS SHA256", keyAlgorithm: "XMSS-SHA256_10_256", signatureAlgorithm: "XMSS-SHA256_10_256"},
		{name: "XMSS SHAKE256", keyAlgorithm: "XMSS-SHAKE256_10_256", signatureAlgorithm: "XMSS-SHAKE256_10_256"},
	}
}

func preparePQCSignatureTestKeys(t *testing.T, b logical.Backend, s logical.Storage) map[string]string {
	t.Helper()

	keyAlgorithms := []string{
		"ML-DSA-44",
		"SLH-DSA-SHA2-128f",
		"SLH-DSA-SHAKE-128f",
		"LMS",
		"XMSS-SHA256_10_256",
		"XMSS-SHAKE256_10_256",
	}
	keyNames := make(map[string]string, len(keyAlgorithms))
	timeStr := time.Now().UTC().Format("20060102T150405.000000000Z")

	for _, keyAlgorithm := range keyAlgorithms {
		keyName := "custom_pqc_sign_" + safeKeyName(keyAlgorithm)
		keyLabel := "TEST_SECUROSYS_SECRETS_ENGINE_PQC_SIGN_" + strings.ToUpper(safeKeyName(keyAlgorithm)) + "_" + timeStr

		err := testKeyPQCCreate(t, b, s, map[string]interface{}{
			"algorithm":  keyAlgorithm,
			"keyLabel":   keyLabel,
			"attributes": pqcSignAttributes,
		}, keyName)
		require.NoError(t, err)

		keyNames[keyAlgorithm] = keyName
		keyNameForCleanup := keyName
		t.Cleanup(func() {
			_ = deleteTestKey(b, s, keyNameForCleanup)
		})
	}

	return keyNames
}

func deleteTestKey(b logical.Backend, s logical.Storage, keyName string) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "keys/" + keyName,
		Data:      map[string]interface{}{"removeFromHSM": true},
		Storage:   s,
	})
	if err != nil {
		return err
	}
	if resp != nil && resp.IsError() {
		return resp.Error()
	}
	return nil
}

func payloadForPQCSignature(t *testing.T, b logical.Backend, s logical.Storage, keyName string, signatureAlgorithm string) string {
	t.Helper()

	if signatureAlgorithm != "ML_DSA_M" {
		return pqcSignaturePayload
	}

	message, err := base64.StdEncoding.DecodeString(pqcSignaturePayload)
	require.NoError(t, err)

	publicKeyBase64 := readTestKeyPublicKey(t, b, s, keyName)
	mu, err := calculateMLDSAMu(publicKeyBase64, message)
	require.NoError(t, err)

	return base64.StdEncoding.EncodeToString(mu)
}

func readTestKeyPublicKey(t *testing.T, b logical.Backend, s logical.Storage, keyName string) string {
	t.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "keys/" + keyName,
		Storage:   s,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError(), "read key %s failed: %v", keyName, resp.Error())

	publicKey, ok := resp.Data["publicKey"].(string)
	require.True(t, ok, "key %s read response should contain publicKey string", keyName)
	require.NotEmpty(t, publicKey, "key %s publicKey should not be empty", keyName)

	return publicKey
}

func calculateMLDSAMu(publicKeyBase64 string, message []byte) ([]byte, error) {
	publicKey, err := rawMLDSAPublicKey(publicKeyBase64)
	if err != nil {
		return nil, err
	}

	tr := make([]byte, 64)
	shake := sha3.NewShake256()
	if _, err := shake.Write(publicKey); err != nil {
		return nil, err
	}
	if _, err := shake.Read(tr); err != nil {
		return nil, err
	}

	mu := make([]byte, 64)
	shake = sha3.NewShake256()
	if _, err := shake.Write(tr); err != nil {
		return nil, err
	}
	if _, err := shake.Write(message); err != nil {
		return nil, err
	}
	if _, err := shake.Read(mu); err != nil {
		return nil, err
	}

	return mu, nil
}

func rawMLDSAPublicKey(publicKeyBase64 string) ([]byte, error) {
	der, err := decodePublicKeyBytes(publicKeyBase64)
	if err != nil {
		return nil, err
	}

	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	rest, err := asn1.Unmarshal(der, &spki)
	if err == nil && len(rest) == 0 && len(spki.SubjectPublicKey.Bytes) > 0 {
		return spki.SubjectPublicKey.Bytes, nil
	}

	return der, nil
}

func decodePublicKeyBytes(publicKey string) ([]byte, error) {
	if block, _ := pem.Decode([]byte(publicKey)); block != nil {
		return block.Bytes, nil
	}

	cleanPublicKey := strings.Join(strings.Fields(publicKey), "")
	der, err := base64.StdEncoding.DecodeString(cleanPublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}

	return der, nil
}

func safeTestName(value string) string {
	replacer := strings.NewReplacer("/", "_", " ", "_")
	return replacer.Replace(value)
}
