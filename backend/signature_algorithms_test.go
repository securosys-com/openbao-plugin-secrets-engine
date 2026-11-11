package backend

import "testing"

func TestValidateSignatureAlgorithmForPQCKey(t *testing.T) {
	testCases := []struct {
		keyAlgorithm       string
		signatureAlgorithm string
	}{
		{"ML-DSA-44", "ML_DSA"},
		{"ML-DSA-65", "SHA2_256_WITH_ML_DSA"},
		{"ML-DSA-87", "SHAKE_256_WITH_ML_DSA"},
		{"SLH-DSA-SHA2-128s", "SLH_DSA"},
		{"SLH-DSA-SHAKE-256f", "SHA3_512_WITH_SLH_DSA"},
		{"LMS", "LMS"},
		{"HSS-LMS", "LMS"},
		{"XMSS", "XMSS-SHA256_10_256"},
		{"XMSS-SHAKE256_10_256", "XMSS-SHAKE256_10_256"},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.keyAlgorithm+"/"+tc.signatureAlgorithm, func(t *testing.T) {
			if err := validateSignatureAlgorithmForKey(tc.keyAlgorithm, tc.signatureAlgorithm); err != nil {
				t.Fatalf("expected signature algorithm to be valid: %v", err)
			}
		})
	}
}

func TestValidateSignatureAlgorithmRejectsWrongPQCSignature(t *testing.T) {
	if err := validateSignatureAlgorithmForKey("ML-DSA-44", "SLH_DSA"); err == nil {
		t.Fatal("expected ML-DSA key to reject SLH-DSA signature algorithm")
	}
}
