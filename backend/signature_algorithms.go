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

package backend

import (
	"fmt"
	"strings"

	helpers "securosys.ch/helpers"
)

func signatureAlgorithmsForKeyAlgorithm(keyAlgorithm string) ([]string, bool) {
	switch {
	case keyAlgorithm == "EC":
		return helpers.EC_SIGNATURE_LIST, true
	case keyAlgorithm == "ED":
		return helpers.ED_SIGNATURE_LIST, true
	case keyAlgorithm == "RSA":
		return helpers.RSA_SIGNATURE_LIST, true
	case keyAlgorithm == "DSA":
		return helpers.DSA_SIGNATURE_LIST, true
	case keyAlgorithm == "BLS":
		return helpers.BLS_SIGNATURE_LIST, true
	case keyAlgorithm == "LMS" || keyAlgorithm == "HSS-LMS":
		return helpers.LMS_SIGNATURE_LIST, true
	case keyAlgorithm == "XMSS" || strings.HasPrefix(keyAlgorithm, "XMSS-"):
		return helpers.XMSS_SIGNATURE_LIST, true
	case strings.HasPrefix(keyAlgorithm, "ML-DSA"):
		return helpers.ML_DSA_SIGNATURE_LIST, true
	case strings.HasPrefix(keyAlgorithm, "SLH-DSA"):
		return helpers.SLH_DSA_SIGNATURE_LIST, true
	default:
		return nil, false
	}
}

func validateSignatureAlgorithmForKey(keyAlgorithm string, signatureAlgorithm string) error {
	signatureAlgorithms, ok := signatureAlgorithmsForKeyAlgorithm(keyAlgorithm)
	if !ok {
		return fmt.Errorf("Key type %s is not supported. Available key types %s", keyAlgorithm, helpers.SUPPORTED_SIGN_KEYS)
	}
	if !helpers.Contains(signatureAlgorithms, signatureAlgorithm) {
		return fmt.Errorf("Not supported signatureAlgorithm %s for %s key type. Available signature algorithms %s", signatureAlgorithm, keyAlgorithm, signatureAlgorithms)
	}
	return nil
}
