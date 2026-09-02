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

package testHelpers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const (
	envTSBURL                     = "TSB_URL"
	envTSBAuth                    = "TSB_AUTH"
	envBearerToken                = "TSB_BEARER_TOKEN"
	envCertPath                   = "TSB_CERT_PATH"
	envKeyPath                    = "TSB_KEY_PATH"
	envApplicationKeyPair         = "TSB_APPLICATION_KEY_PAIR"
	envApplicationPrivateKey      = "TSB_APPLICATION_PRIVATE_KEY"
	envApplicationPublicKey       = "TSB_APPLICATION_PUBLIC_KEY"
	envAPIKeys                    = "TSB_API_KEYS"
	envKeyManagementToken         = "TSB_KEY_MANAGEMENT_TOKEN"
	envKeyOperationToken          = "TSB_KEY_OPERATION_TOKEN"
	envApproverToken              = "TSB_APPROVER_TOKEN"
	envServiceToken               = "TSB_SERVICE_TOKEN"
	envApproverKeyManagementToken = "TSB_APPROVER_KEY_MANAGEMENT_TOKEN"
)

// ConfigParams contains the parameters needed by tests to access TSB.
// Values are read from environment variables first and then from an optional .env file.
var ConfigParams map[string]interface{} = loadConfigParams()

func HasTSBConfig() bool {
	value, ok := ConfigParams["restapi"].(string)
	return ok && value != ""
}

func RequireTSBConfig(tb testing.TB) {
	tb.Helper()
	if !HasTSBConfig() {
		tb.Skipf("set %s or add it to .env to run TSB integration tests", envTSBURL)
	}
}

func loadConfigParams() map[string]interface{} {
	envFileValues := readDotEnvFiles()

	config := map[string]interface{}{}
	if value := configValue(envTSBURL, envFileValues); value != "" {
		config["restapi"] = value
	}

	auth := configValue(envTSBAuth, envFileValues)
	if auth == "" {
		auth = "NONE"
		if configValue(envBearerToken, envFileValues) != "" {
			auth = "TOKEN"
		} else if configValue(envCertPath, envFileValues) != "" || configValue(envKeyPath, envFileValues) != "" {
			auth = "CERT"
		}
	}
	config["auth"] = auth

	if value := configValue(envBearerToken, envFileValues); value != "" {
		config["bearertoken"] = value
	}
	if value := configValue(envCertPath, envFileValues); value != "" {
		config["certpath"] = value
	}
	if value := configValue(envKeyPath, envFileValues); value != "" {
		config["keypath"] = value
	}
	if value := applicationKeyPairConfig(envFileValues); value != "" {
		config["applicationKeyPair"] = value
	}
	if value := apiKeysConfig(envFileValues); value != "" {
		config["apiKeys"] = value
	}

	return config
}

func applicationKeyPairConfig(envFileValues map[string]string) string {
	if value := configValue(envApplicationKeyPair, envFileValues); value != "" {
		return value
	}

	privateKey := configValue(envApplicationPrivateKey, envFileValues)
	publicKey := configValue(envApplicationPublicKey, envFileValues)
	if privateKey == "" && publicKey == "" {
		return ""
	}

	keyPair := map[string]string{
		"privateKey": privateKey,
		"publicKey":  publicKey,
	}
	data, err := json.Marshal(keyPair)
	if err != nil {
		return ""
	}
	return string(data)
}

func apiKeysConfig(envFileValues map[string]string) string {
	if value := configValue(envAPIKeys, envFileValues); value != "" {
		return value
	}

	apiKeys := map[string][]string{}
	addAPIKeyValue(apiKeys, "KeyManagementToken", configValue(envKeyManagementToken, envFileValues))
	addAPIKeyValue(apiKeys, "KeyOperationToken", configValue(envKeyOperationToken, envFileValues))
	addAPIKeyValue(apiKeys, "ApproverToken", configValue(envApproverToken, envFileValues))
	addAPIKeyValue(apiKeys, "ServiceToken", configValue(envServiceToken, envFileValues))
	addAPIKeyValue(apiKeys, "ApproverKeyManagementToken", configValue(envApproverKeyManagementToken, envFileValues))
	if len(apiKeys) == 0 {
		return ""
	}

	data, err := json.Marshal(apiKeys)
	if err != nil {
		return ""
	}
	return string(data)
}

func addAPIKeyValue(apiKeys map[string][]string, key string, value string) {
	values := splitEnvList(value)
	if len(values) > 0 {
		apiKeys[key] = values
	}
}

func splitEnvList(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			values = append(values, part)
		}
	}
	return values
}

func configValue(name string, envFileValues map[string]string) string {
	if value, ok := os.LookupEnv(name); ok {
		return value
	}
	return envFileValues[name]
}

func readDotEnvFiles() map[string]string {
	values := map[string]string{}
	for _, path := range dotEnvCandidates() {
		readDotEnvFile(path, values)
	}
	return values
}

func dotEnvCandidates() []string {
	seen := map[string]bool{}
	var candidates []string
	add := func(path string) {
		if path == "" || seen[path] {
			return
		}
		seen[path] = true
		candidates = append(candidates, path)
	}

	if cwd, err := os.Getwd(); err == nil {
		dir := cwd
		for {
			add(filepath.Join(dir, ".env"))
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return candidates
}

func readDotEnvFile(path string, values map[string]string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		value = parseDotEnvValue(value)
		if name != "" {
			if _, exists := values[name]; !exists {
				values[name] = value
			}
		}
	}
}

func parseDotEnvValue(value string) string {
	value = strings.TrimSpace(stripDotEnvComment(value))
	if len(value) < 2 {
		return value
	}
	if strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) {
		if unquoted, err := strconv.Unquote(value); err == nil {
			return unquoted
		}
	}
	if strings.HasPrefix(value, `'`) && strings.HasSuffix(value, `'`) {
		return strings.TrimSuffix(strings.TrimPrefix(value, `'`), `'`)
	}
	return value
}

func stripDotEnvComment(value string) string {
	inSingleQuote := false
	inDoubleQuote := false
	for i, r := range value {
		switch r {
		case '\'':
			if !inDoubleQuote {
				inSingleQuote = !inSingleQuote
			}
		case '"':
			if !inSingleQuote {
				inDoubleQuote = !inDoubleQuote
			}
		case '#':
			if !inSingleQuote && !inDoubleQuote {
				return value[:i]
			}
		}
	}
	return value
}
