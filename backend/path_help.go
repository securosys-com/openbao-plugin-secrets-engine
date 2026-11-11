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

const backendHelp = `
The Securosys Secrets Engine plugin implements a platform-agnostic REST-based
HSM interface with zero library installation, while eliminating connectivity hurdles
by using secure web connections (TLS).
This facilitates the use and deployment in clustered and multi-cloud environments.
Moreover, all Securosys HSM innovations like hardware enforced multi-authorization
and high-performance encryption (ECIES, AES-GCM) are at one�s disposal,
for Vault Enterprise and Community Edition. The plugin allows to
- Manage keys securely stored on the HSM
- Perform cryptographic operations on the HSM
- Use enhanced Primus HSM features such as high-performance encryption (ECIES, AES-GCM),
  or hardware-enforced multi-authorization workflows
  for compliance, signature services, or blockchain transactions.

After registering and enabling this plugin, configure access and authorization for
HSMs REST/TSB interface with the "config/" endpoint.
`

const pathConfigHelpSynopsis = `Configure the Securosys Secrets Engine Plugin for HSM access`
const pathConfigHelpDescription = `The Securosys Secrets Engine requires configuration to access the HSM via REST(TSB). Authorization type can be token (JWT), cert (mTLS client certificate), or disabled.
        Example: $ vault write securosys-hsm/config     
                   auth={authorization-type}      # Possible values (NONE,TOKEN,CERT)
                   restapi={rest-api-url}         # REST API URL to access the REST/TSB endpoint
                   bearertoken={bearer-token}     # If Auth=TOKEN
                   certpath={path-to-certificate} # If Auth=CERT
        `

const (
	pathHealthHelpSynopsis    = `Get status of connection`
	pathHealthHelpDescription = `Get the status of the connection between Secrets Engin plugin and TSB.
        Example: $ vault read securosys-hsm/health`
)

const (
	pathKeyAESHelpSynopsis    = `Create AES key`
	pathKeyAESHelpDescription = `
    Create an AES key. Arguments required: keyLabel, keySize, attributes. Optional: password
        Example: $ vault write securosys-hsm/keys/aes/{key-name} 
                   keyLabel="{key-label-hsm}"
                   keySize={key-size}
                   #{key-attriute}:{true/false}
                   attributes='{"decrypt": true,"sign": false,"unwrap": true,"derive": true,"sensitive": true,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}'       
                   password={password-for-the-key}
`
)

const (
	pathKeyBLSHelpSynopsis    = `Create BLS key`
	pathKeyBLSHelpDescription = `
    Create a BLS key. Arguments required: keyLabel, keySize, attributes. Optional: password, policy, simplePolicy
        Example: $ vault write securosys-hsm/keys/bls/{key-name} 
                   keyLabel="{key-label-hsm}"
                   keySize={key-size} 
                   #{key-attriute}:{true/false}
                   attributes='{"decrypt": true,"sign": false,"unwrap": true,"derive": true,"sensitive": true,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}'       
                   password={password-for-the-key}
                   policy=@path_to_policy_file.json
                   #or
                   #JSON object (Key => Approver Name, Value=>Approver Public Key)
                   simplePolicy=-<<EOF
                                {
                                    "NameOfApprover": "Approver Public Key"
                                }
                                EOF`
)
const (
	pathKeyCamelliaHelpSynopsis    = `Create Camellia key`
	pathKeyCamelliaHelpDescription = `
    Create a Camellia key. Arguments required: keyLabel, keySize, attributes. Optional: password
        Example: $ vault write securosys-hsm/keys/camellia/{key-name} 
                   keyLabel="{key-label-hsm}"
                   keySize={key-size}
                   #{key-attriute}:{true/false}
                   attributes='{"decrypt": true,"sign": false,"unwrap": true,"derive": true,"sensitive": true,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}'       
                   password={password-for-the-key}
`
)

const (
	pathKeyChaCha20HelpSynopsis    = `Create ChaCha20 key`
	pathKeyChaCha20HelpDescription = `
    Create a ChaCha20 key. Arguments required: keyLabel, attributes. Optional: password
        Example: $ vault write securosys-hsm/keys/chacha20/{key-name} 
                   keyLabel="{key-label-hsm}"
                   #{key-attriute}:{true/false}
                   attributes='{"decrypt": true,"sign": false,"unwrap": true,"derive": true,"sensitive": true,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}'       
                   password={password-for-the-key}
`
)

const (
	pathKeyDSAHelpSynopsis    = `Create DSA key`
	pathKeyDSAHelpDescription = `
    Create a DSA key pair. Arguments required: keyLabel, keySize, attributes. Optional: password, policy, simplePolicy
        Example: $ vault write securosys-hsm/keys/dsa/{key-name} 
                   keyLabel="{key-label-hsm}"
                   keySize={key-size}
                   #{key-attriute}:{true/false}
                   attributes='{"decrypt": true,"sign": false,"unwrap": true,"derive": true,"sensitive": true,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}'       
                   password={password-for-the-key}
                   policy=@path_to_policy_file.json
                   #or
                   #JSON object (Key => Approver Name, Value=>Approver Public Key)
                   simplePolicy=-<<EOF
                                {
                                    "NameOfApprover": "Approver Public Key"
                                }
                                EOF`
)

const (
	pathKeyECHelpSynopsis    = `Create EC key`
	pathKeyECHelpDescription = `
    Create an EC key pair. Arguments required: keyLabel, curveOid, attributes. Optional: password, policy, simplePolicy
        Example: $ vault write securosys-hsm/keys/ec/{key-name} 
                   keyLabel="{key-label-hsm}"
                   curveOid={curve-oid} 
                   #{key-attriute}:{true/false}
                   attributes='{"decrypt": true,"sign": false,"unwrap": true,"derive": true,"sensitive": true,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}'       
                   password={password-for-the-key}  
                   policy=@path_to_policy_file.json
                   #or
                   #JSON object (Key => Approver Name, Value=>Approver Public Key)
                   simplePolicy=-<<EOF
                                {
                                    "NameOfApprover": "Approver Public Key"
                                }
                                EOF`
)
const (
	pathKeyEDHelpSynopsis    = `Create ED key`
	pathKeyEDHelpDescription = `
    Create an ED key pair. Arguments required: keyLabel, curveOid, attributes. Optional: password, policy, simplePolicy
        Example: $ vault write securosys-hsm/keys/ed/{key-name} 
                   keyLabel="{key-label-hsm}"
                   curveOid={curve-oid} 
                   #{key-attriute}:{true/false}
                   attributes='{"decrypt": true,"sign": false,"unwrap": true,"derive": true,"sensitive": true,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}'       
                   password={password-for-the-key}  
                   policy=@path_to_policy_file.json
                   #or
                   #JSON object (Key => Approver Name, Value=>Approver Public Key)
                   simplePolicy=-<<EOF
                                {
                                    "NameOfApprover": "Approver Public Key"
                                }
                                EOF`
)

const (
	pathKeyImportHelpSynopsis    = `Import key into Vault and HSM`
	pathKeyImportHelpDescription = `
    Import a key to Vault and HSM . Arguments required: keyLabel, keySize, attributes, algorithm. Optional: policy, simplePolicy, privateKey, publicKey, secretKey, certificate
        Example: $ vault write securosys-hsm/keys/{key-name}/import 
                   keyLabel="{key-label-hsm}"
                   #For symmetric key
                   secretKey="{secret-key}" 
                   #For asymmetric key
                   privateKey="{private-key}" 
                   publicKey="{public-key}" 
                   algorithm="{key-algorithm}" #It has to be [EC,ED,RSA,DSA,BLS,AES,ChaCha20,Camellia,TDEA]
                   #{key-attriute}:{true/false}
                   attributes='{"decrypt": true,"sign": false,"unwrap": true,"derive": true,"sensitive": true,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}'           
                   policy=@path_to_policy_file.json
                   #or
                   #JSON object (Key => Approver Name, Value=>Approver Public Key)
                   simplePolicy=-<<EOF
                                {
                                    "NameOfApprover": "Approver Public Key"
                                }
                                EOF`
)

const (
	pathKeyRSAHelpSynopsis    = `Create RSA key`
	pathKeyRSAHelpDescription = `
    Create an RSA key pair. Arguments required: keyLabel, keySize, attributes. Optional: password, policy, simplePolicy
        Example: $ vault write securosys-hsm/keys/rsa/{key-name} 
                   keyLabel="{key-label-hsm}"
                   keySize={key-size} 
                   #{key-attriute}:{true/false}
                   attributes='{"decrypt": true,"sign": false,"unwrap": true,"derive": true,"sensitive": true,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}'       
                   password={password-for-the-key}
                   policy=@path_to_policy_file.json
                   #or
                   #JSON object (Key => Approver Name, Value=>Approver Public Key)
                   simplePolicy=-<<EOF
                                {
                                    "NameOfApprover": "Approver Public Key"
                                }
                                EOF`
)
const (
	pathKeyTDEAHelpSynopsis    = `Create TDEA key`
	pathKeyTDEAHelpDescription = `
    Create a TDEA key. Arguments required: keyLabel, attributes. Optional: password
        Example: $ vault write securosys-hsm/keys/tdea/{key-name} 
                   keyLabel="{key-label-hsm}"
                   #{key-attriute}:{true/false}
                   attributes='{"decrypt": true,"sign": false,"unwrap": true,"derive": true,"sensitive": true,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}'       
                   password={password-for-the-key}
`
)
const (
	pathKeysUsingNameHelpSynopsis    = `Create key using defined name`
	pathKeysUsingNameHelpDescription = `
    Create a key using key types defined by OpenBao: 
        - aes256-gcm96 - AES-GCM with a 256-bit AES key and a 96-bit nonce (symmetric)
        - rsa-2048     - RSA with bit size of 2048 (asymmetric)
        - rsa-3072     - RSA with bit size of 3072 (asymmetric)
        - rsa-4096     - RSA with bit size of 4096 (asymmetric)
        - ecdsa-p256   - ECDSA using the P-256 elliptic curve (asymmetric)
        - ecdsa-p384   - ECDSA using the P-384 elliptic curve (asymmetric)
        - ecdsa-p521   - ECDSA using the P-521 elliptic curve (asymmetric)
    Arguments required: keyLabel, attributes. Optional: password, policy, simplePolicy.
        Example: $ vault write securosys-hsm/keys/type/{key-type-name}/{key-name} 
                   keyLabel="{key-label-hsm}"
                   #{key-attriute}:{true/false}
                   attributes='{"decrypt": true,"sign": false,"unwrap": true,"derive": true,"sensitive": true,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}'       
                   password={password-for-the-key}
                   policy=@path_to_policy_file.json
                   #or
                   #JSON object (Key => Approver Name, Value=>Approver Public Key)
                   simplePolicy=-<<EOF
                                {
                                    "NameOfApprover": "Approver Public Key"
                                }
                                EOF`
)

const (
	pathKeyUpdatePasswordHelpSynopsis    = `Update key password on HSM`
	pathKeyUpdatePasswordHelpDescription = `Update the password of a key on the HSM. Arguments required: newPassword. Optional: password
        Example: $ vault write securosys-hsm/keys/{key-name}/update-password
                   password="{current-password}"
                   newPassword="{new-password}"
    `

	pathKeyRegisterHelpSynopsis    = `Register key from HSM to Secrets Engine`
	pathKeyRegisterHelpDescription = `Register an existing key stored on the HSM to Secrets Engine. Arguments required: keyLabel.
        Example: $ vault write securosys-hsm/keys/{key-name}/register
                   keyLabel="{key-label-hsm}"
    `

	pathKeyRotateHelpSynopsis    = `Rotate key`
	pathKeyRotateHelpDescription = `Rotate a key. A new key will be generated on the HSM with incremented version tag (_v2, _v3, ...). The previous key version will remain on the HSM. Arguments Optional: password  
        Example: $ vault write securosys-hsm/keys/{key-name}/rotate
                   password="{password-for-the-key}"`

	pathKeyBlockHelpSynopsis    = `Block key on HSM`
	pathKeyBlockHelpDescription = `Block a key stored on the HSM. In case of SKA policy on the key, the returned request-id indicates the required approvals. Arguments Optional: password 
        Example: $ vault write securosys-hsm/keys/{key-name}/block
                    password="{password-for-the-key}"`

	pathKeyUnBlockHelpSynopsis    = `Unblock key on HSM`
	pathKeyUnBlockHelpDescription = `Unblock a key stored on the HSM. In case of SKA policy on the key, the returned request-id indicates the required approvals. Arguments Optional: password   
        Example: $ vault write securosys-hsm/keys/{key-name}/unblock
                   password="{password-for-the-key}"`

	pathKeyExportHelpSynopsis    = `Export key from HSM`
	pathKeyExportHelpDescription = `Export a key stored on the HSM.  Arguments Optional: password  
        Example: $ vault write securosys-hsm/keys/{key-name}/export
                   password="{password-for-the-key}"`

	pathKeyModifyHelpSynopsis    = `Modify key on HSM`
	pathKeyModifyHelpDescription = `Modify the SKA policy of a key stored on the HSM. In case of SKA policy on the key, the returned request-id indicates the required approvals. Arguments Optional: password, policy, simplePolicy   
        Example: $ vault write securosys-hsm/keys/{key-name}/modify
                   password="{password-for-the-key}"
                   policy=@path_to_policy_file.json
                   #or
                   #JSON object (Key => Approver Name, Value=>Approver Public Key)
                   simplePolicy=-<<EOF
                                {
                                    "NameOfApprover": "Approver Public Key"
                                }
                                EOF`
	pathKeyReadDeleteHelpSynopsis    = `Read stored key information, or delete it from Secrets Engine and optionally from Securosys HSM`
	pathKeyReadDeleteHelpDescription = `Return stored key information from Secrets Engine or deletes existing key. This endpoint returns keyLabel, attributes, policy, algorithm, keySize, curveOid of requested key.
        Read operation:
        Example: $ vault read securosys-hsm/keys/{key-name}
        Delete operation: Arguments Optional: removeFromHSM
        Example: $ vault delete securosys-hsm/keys/{key-name}
                   removeFromHSM={true/false}
        `

	pathKeyReadXMLHelpSynopsis    = `Get key attestation`
	pathKeyReadXMLHelpDescription = `Get a key attestation from the HSM in XML format, signed with the HSMs attestatin key.
        Example: $ vault read securosys-hsm/keys/{key-name}/xml`

	pathKeyReadDeleteVersionHelpSynopsis    = `Read or delete stored key version`
	pathKeyReadDeleteVersionHelpDescription = `Return stored key version information keyLabel on HSM, XML and signature, or delete key version.
      Read operation:
        Example: $ vault read securosys-hsm/keys/{key-name}/{key-version}
      Delete operation:
        Example: $ vault delete securosys-hsm/keys/{key-name}/{key-version}
        `

	pathKeyListHelpSynopsis    = `List stored keys`
	pathKeyListHelpDescription = `List the existing keys in Secrets Engine. 
        Example: $ vault list securosys-hsm/keys
            Or more detailed view
        Example: $ vault list -detailed securosys-hsm/keys
        `
	pathKeyHSMListHelpSynopsis    = `List key labels stored on HSM`
	pathKeyHSMListHelpDescription = `List key labels stored on HSM. 
        Example: $ vault list securosys-hsm/keys/hsm
        `

	pathKeyVersionsListHelpSynopsis    = `List stored key versions`
	pathKeyVersionsListHelpDescription = `List the existing key versions in Secrets Engine.
        Example: $ vault list securosys-hsm/keys/{key-name}
            Or more detailed view
        Example: $ vault list -detailed securosys-hsm/keys/{key-name}`
)

const (
	pathOperationsWrapHelpSyn  = `Operation wrap key`
	pathOperationsWrapHelpDesc = `Wrap a key with anoter key. Arguments required: wrapMethod. Optional: keyToBeWrappedPassword, wrapKeyPassword.
        Example: $ vault write securosys-hsm/operation/wrap/{key-to-be-wrapped}/{wrap-key-name}
                   keyToBeWrappedPassword="{password-for-first-key}"
                   wrapKeyPassword="{password-for-second-key}"
                   wrapMethod="{wrap-method}"            
    `

	pathOperationsUnWrapHelpSyn  = `Operation unwrap key`
	pathOperationsUnWrapHelpDesc = `Unwrap a key using a wrapper key. In case of SKA policy on the key, the returned request-id indicates the required approvals. Arguments required: keyLabel, wrappedKey, attributes, wrapMethod. Optional: password, policy, simplePolicy.
        Example: $ securosys-hsm/operation/unwrap/{new-unwrapped-key-name}/{wrap-key-name}/{key-version}
                   keyLabel="{key-label-hsm}"
                   wrapMethod="{wrap-method}"            
                   wrappedKey="{wrapped-key}"            
                   #{key-attriute}:{true/false}
                   attributes='{"decrypt": true,"sign": false,"unwrap": true,"derive": true,"sensitive": true,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}'       
                   password={password-for-the-key}
                   policy=@path_to_policy_file.json
                   #or
                   #JSON object (Key => Approver Name, Value=>Approver Public Key)
                   simplePolicy=-<<EOF
                                {
                                    "NameOfApprover": "Approver Public Key"
                                }
                                EOF`

	pathOperationsSignHelpSyn  = `Operation sign`
	pathOperationsSignHelpDesc = `Sign a payload. In case of SKA policy on the key, the returned request-id indicates the required approvals. Arguments required: signatureAlgorithm, payload. Optional: password, payloadType, metaData, metaDataSignature
        Example: $ vault write securosys-hsm/operation/sign/{key-name}
                   password="{key-password}"
                   signatureAlgorithm="{signature-algorithm}"
                   payload="{payload-base64-encoded}"
                   payloadType="{payload-type}"
`
	pathOperationsCertificateSignHelpSyn  = `Operation certificate sign`
	pathOperationsCertificateSignHelpDesc = `Sign a CSR. In case of SKA policy on the key, the returned request-id indicates the required approvals. Arguments required: signatureAlgorithm, commonName, csr. Optional: password, certificateAuthority, keyUsage, extendedKeyUsage
    Example: $ vault write securosys-hsm/operation/certificate/sign/{key-name}
               password="{key-password}"
               signatureAlgorithm="{signature-algorithm}"
               csr="{certificate-csr}"
               commonName="{common-name}"
               keyUsage="[\"{key-usage-1}\",\"{key-usage-2}\",\"{key-usage-3}\" ...]"
               extendedKeyUsage="[\"{ext-key-usage-1}\",\"{ext-key-usage-2}\",\"{ext-key-usage-3}\" ...]"
               certificateAuthority="true/false"
`
	pathOperationsCertificateSelfSignHelpSyn  = `Operation certificate self sign`
	pathOperationsCertificateSelfSignHelpDesc = `Self sign certificate. In case of SKA policy on the key, the returned request-id indicates the required approvals. Arguments required: signatureAlgorithm, commonName, validity. Optional: password, certificateAuthority, keyUsage, extendedKeyUsage
Example: $ vault write securosys-hsm/operation/certificate/selfsign/{key-name}
           password="{key-password}"
           signatureAlgorithm="{signature-algorithm}"
           validity={certificate-validity-days}
           commonName="{common-name}"
           keyUsage="[\"{key-usage-1}\",\"{key-usage-2}\",\"{key-usage-3}\" ...]"
           extendedKeyUsage="[\"{ext-key-usage-1}\",\"{ext-key-usage-2}\",\"{ext-key-usage-3}\" ...]"
           certificateAuthority="true/false"
`
	pathOperationsCertificateRequestHelpSyn  = `Operation create certificate request (csr)`
	pathOperationsCertificateRequestHelpDesc = `Creates CSR. In case of SKA policy on the key, the returned request-id indicates the required approvals. Arguments required: signatureAlgorithm, certificateAttributes, validity. Optional: password, certificateAuthority, keyUsage, extendedKeyUsage
Example: $ vault write securosys-hsm/operation/certificate/request/{key-name}
       password="{key-password}"
       signatureAlgorithm="{signature-algorithm}"
       validity={certificate-validity-days}
       certificateAttributes="{\"commonName\": \"{attribute-value}\",\"country\": \"{attribute-value}\",\"stateOrProvinceName\": \"{attribute-value}\",\"locality\": \"{attribute-value}\",\"organizationName\": \"{attribute-value}\",\"organizationUnitName\": \"{attribute-value}\",\"email\": \"{attribute-value}\",\"title\": \"{attribute-value}\",\"surname\": \"{attribute-value}\",\"givenName\": \"{attribute-value}\",\"initials\": \"{attribute-value}\",\"pseudonym\": \"{attribute-value}\",\"generationQualifier\": \"{attribute-value}\"}"
       keyUsage="[\"{key-usage-1}\",\"{key-usage-2}\",\"{key-usage-3}\" ...]"
       extendedKeyUsage="[\"{ext-key-usage-1}\",\"{ext-key-usage-2}\",\"{ext-key-usage-3}\" ...]"
       certificateAuthority="true/false"
`

	pathOperationsVerifyHelpSyn  = `Operation verify`
	pathOperationsVerifyHelpDesc = `Verify the signature of a signed payload. Arguments required: signatureAlgorithm, signature, payload. Optional: password
        Example: $ vault write securosys-hsm/operation/verify/{key-name}/{key-version}
                   password="{key-password}"
                   signatureAlgorithm="{signature-algorithm}"
                   payload="{payload-base64-encoded}"
                   signature="{signature}"

    `

	pathOperationsEncryptHelpSyn  = `Operation encrypt`
	pathOperationsEncryptHelpDesc = `Encrypt a payload. Arguments required: payload, cipherAlgorithm. Optional: password, tagLength, additionalAuthenticationData.
        Example: $ vault write securosys-hsm/operation/encrypt/{key-name} 
                   payload="{payload-base64-encoded}"
                   password="{key-password}"
                   cipherAlgorithm="{cipher-algorithm}"
                   tagLength="{tag-length}"
                   additionalAuthenticationData="{additional-authentication-data}"
    `

	pathOperationsDecryptHelpSyn  = `Operation decrypt`
	pathOperationsDecryptHelpDesc = `Decrypt an encrypted payload. In case of SKA policy on the key, the returned request-id indicates the required approvals. Arguments required: encryptedPayload, cipherAlgorithm. Optional: password, initializationVector, tagLength, additionalAuthenticationData.
        Example: $ vault write securosys-hsm/operation/decrypt/{key-name}/{key-version}
                   encryptedPayload="{encrypted-payload}"
                   password="{key-password}"
                   cipherAlgorithm="{cipher-algorithm}"
                   tagLength="{tag-length}"
                   initializationVector="{initialization-vector}"
                   additionalAuthenticationData="{additional-authentication-data}"
    `
)

const (
	pathRequestListHelpSynopsis    = `List the existing requests in Secrets Engine`
	pathRequestListHelpDescription = `List all existing requests in Secrets Engine (from key operations having an SKA policy)
        Example: $ vault list securosys-hsm/requests
            Or more detailed view
        Example: $ vault list -detailed securosys-hsm/requests`

	pathRequestReadDeleteHelpSynopsis    = `Read or Delete request`
	pathRequestReadDeleteHelpDescription = `Read or Delete a request in Secrets Engine and HSM (from key operations having an SKA policy).
        Read operation:
        Example: $ vault read securosys-hsm/requests/{id}
        Delete operation:
        Example: $ vault delete securosys-hsm/requests/{id}
        
    `
)
const (
	pathIntegrationMariaDBListHelpSynopsis    = `List the existing secrets for MariaDB in Secrets Engine`
	pathIntegrationMariaDBListHelpDescription = `List the existing secrets for MariaDB in Secrets Engine.
        Example: $ vault list securosys-hsm/integrations/mariadb
            Or more detailed view
        Example: $ vault list -detailed securosys-hsm/integrations/mariadb        
        `
	pathIntegrationMariaDBWriteHelpSynopsis    = `Generate new, rotate or delete MariaDB secret`
	pathIntegrationMariaDBWriteHelpDescription = `Generate new, rotate or delete MariaDB secret. When using same {secret_name} and {key_name} as previous one, cause secret rotation.
        Create/Rotate operation:
        Example: $ vault write securosys-hsm/integrations/mariadb/{secret_name}
        keyName={key-name-from-secret-engine}
        cipherAlgorithm={cipher-algorithm}
        [additionalAuthenticationData={additional-authentication-data}]
        [tagLength={tag-length}]
        [password={password-for-a-key}]

        Delete operation:
        Example: $ vault delete securosys-hsm/integrations/mariadb/{secret_name}`
	pathIntegrationMariaDBReadV1HelpSynopsis    = `Read MariaDB secret (version 1)`
	pathIntegrationMariaDBReadV1HelpDescription = `Read MariaDB secret (version 1)
    Latest version of secret:
    Example: $ vault read securosys-hsm/integrations/mariadb/{secret_name}/?key_name={key-name}&cipher_algorithm={cipher_algorithm}&tag_length={tag_length}&aad={additional_authentication_data}&password={password}
    
    Selected version of secret:
    Example: $ vault read securosys-hsm/integrations/mariadb/{secret_name}/?key_name={key-name}&cipher_algorithm={cipher_algorithm}&tag_length={tag_length}&aad={additional_authentication_data}&password={password}&version=/data/1?version={selected_version}`
	pathIntegrationMariaDBReadV2HelpSynopsis    = `Read MariaDB secret (version 2)`
	pathIntegrationMariaDBReadV2HelpDescription = `Read MariaDB secret (version 2)
    Latest version of secret:
    Example: $ vault read securosys-hsm/integrations/mariadb/?key_name={key-name}&cipher_algorithm={cipher_algorithm}&tag_length={tag_length}&aad={additional_authentication_data}&password={password}
    
    Selected version of secret:
    Example: $ vault read securosys-hsm/integrations/mariadb/{secret_name}/v{selected_version}?key_name={key-name}&cipher_algorithm={cipher_algorithm}&tag_length={tag_length}&aad={additional_authentication_data}&password={password}`
)
