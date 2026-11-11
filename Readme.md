# Securosys Secrets Engine for OpenBao
This plugin implements a platform-agnostic REST-based HSM interface with zero library installation, while eliminating connectivity hurdles by using secure web connections (TLS). This facilitates the use and deployment in clustered and multi-cloud environments. Moreover, all Securosys HSM innovations like hardware enforced multi-authorization and high-performance encryption (ECIES, AES-GCM) are at one's disposal, for Vault Enterprise and Community Edition. 
 - Manage keys securely stored on the HSM
 - Perform cryptographic operations on the HSM
 - Use enhanced Primus HSM features such as high-performance encryption (ECIES, AES-GCM), or hardware-enforced multi-authorization workflows for compliance, signature services, or blockchain transactions.

This plugin is actively maintained by Securosys SA. 

## Table of Contents

- [Glossary](#glossary)
- [How to build](#how-to-build)
  - [Using pre-built releases](#using-pre-built-releases)
  - [Build from sources](#build-from-sources)
- [How to run](#how-to-run)
  - [Register the plugin](#register-the-plugin)
  - [Upgrade the plugin](#upgrade-the-plugin)
  - [How to enable the plugin](#how-to-enable-the-plugin)
  - [Configure the plugin](#configure-the-plugin)
    - [MetaData Signature](#metadata-signature)
    - [TSB ApiKeys](#tsb-apikeys)
  - [Manage Keys](#manage-keys)
  - [Cryptographic Operations](#cryptographic-operations)
  - [Requests](#requests)
- [Additional command options](#additional-command-options)
- [Help](#help)
- [Test Suite](#test-suite)
  - [Preparing](#preparing)
  - [Running tests](#running-tests)
- [Integrations](#integrations)
  - [MariaDB](#mariadb)
    - [Example usage](#mariadb-usage-example)
- [Appendix](#appendix)
  - [Frequently Asked Questions](#frequently-asked-questions)
  - [Key arguments](#key-arguments)
  - [Full Policy JSON example](#full-policy-json-example)
- [Getting Support](#getting-support)
- [License](#license)

---
## Glossary
| Term|      Description      |
|:----------|:-------------|
| CloudsHSM | HSM as a service, operated by Securosys|
| HSM| Hardware Security Module |
| JSON | JavaScript Object Notation object |
| JWT | JSON Web Token, used to authenticate and authorize users in web applications and APIs |
| SKA | Smart Key Attributes, attributes adding rules to individual keys |
| TSB | Transaction Security Broker, providing the REST interface |
| XML | Extensible Markup Language, defines a set of rules for encoding documents in a format that is both human-readable and machine-readable. Format used for HSM key attestation. |


## How to build
### Using pre-built releases
You can find pre-built releases of the plugin on the Securosys JFrog artifactory. Download the latest binary file corresponding to your target OS.

Further documentation and credentials are available via the [Securosys Support Portal](https://support.securosys.com/external/knowledge-base/article/191) or the Securosys [web-site](https://www.securosys.com/en/hashicorp-vault). 

### Build from sources

>**Prerequisites:** Install Golang 1.16+ ([download](https://go.dev/dl/))

1. Run `go mod init`.

1. Build the secrets engine as plugin using Go.
   ```shell
   $ CGO_ENABLED=0 go build -o vault/plugins/securosys_hsm cmd/securosys_hsm/main.go
   ```

1. Find the binary in `vault/plugins/`.
   ```shell
   $ ls vault/plugins/
   ```

1. Run a Vault server in `dev` mode to register and try out the plugin.
   ```shell
   $ vault server -dev -dev-root-token-id=root -dev-plugin-dir=./vault/plugins
   ```
1. Build and test in `dev` mode. 
    ```shell
    $ make
    ```
1.  Or to build `production` plugin with the same `architecture` and `os` on used machine

      ```shell
      $ make build
      ```
1. To build `production` version of this plugin, then use the command 
    ```shell
    $ make release VERSION="1.0" #builds the plugin for the same architecture as the current machine
    ```
    ```shell
    $ make release VERSION="1.0" OS="win" ARCH="i386" #builds the defined plugin version
    ```
1. To build `production` for all versions of this plugin, then use the command 
    ```shell
    $ make release-all VERSION="1.0" #builds all available versions of the plugin
    ```
    This command will build `production` versions for the following architectures and operating systems
    | OS   |      Arch      |
    |----------|:-------------:|
    | Darwin |  amd64 |
    | Darwin |  arm64  |
    | Windows | 386 | 
    | Windows | amd64 | 
    | Linux | 386 | 
    | Linux | amd64 | 
    | Linux | arm | 
    | Linux | arm64 | 
    | FreeBSD | 386 | 
    | FreeBSD | amd64 | 
    | FreeBSD | arm | 
    | NetBSD | 386 | 
    | NetBSD | amd64 | 
    | NetBSD | arm | 
    | OpenBSD | 386 | 
    | OpenBSD | amd64 | 
    | OpenBSD | arm | 
    | Solaris | amd64 | 

    All these builds will be zipped, calculated and stored inside the build folder of this project.


## How to run
### Register the plugin
In production mode the plugin has to be registered manually.
Add the following parameter in the configuration file `config.hcl`
- `plugin_directory` - must contain the absolute path to the directory where the plugins are stored 

Command to register the plugin
```shell
$ vault plugin register -sha256={binary_checksum} secret securosys-hsm
```
### Upgrade the plugin
To upgrade a binary of an existing working plugin, follow the steps below:
1) Copy the new plugin binary to the plugin_directory.
1) Register a new version of the plugin.
    ```shell
    $ vault plugin register -sha256={binary_checksum} -version={new-version} secret securosys-hsm
    ```
1) Tune the existing mount to reconfigure it to use the newly registered version.
    ```shell
    $ vault secrets tune -plugin-version={new-version}  securosys-hsm
    ```
1) Reload the plugin
    ```shell
    $ vault plugin reload -plugin securosys-hsm
    ```

### How to enable the plugin
After building the plugin, before running it on test server, it must be enabled with the following command:
```shell
$ vault secrets enable securosys-hsm
```
The result should be
```shell
$ Success! Enabled the securosys-hsm secrets engine at: securosys-hsm/
```
---
### Configure the plugin
Configure the plugin for accessing the  Securosys Primus HSM or CloudsHSM.

Required attributes:
- `auth` - Attribute defines the authorization type to TSB. Values for this attribute can be `TOKEN`, `CERT` or `NONE`
- `restapi` - REST API URL to access the REST/TSB endpoint (available from your Security Officer or CloudsHSM service provider)

Define additional attributes based on the selected authorization type `auth`: 
1.  `TOKEN`
    Add the attribute `bearertoken` with the JWT token
1.  `CERT`
    Setup `certpath` with local PATH to the certificate and `keypath` with local PATH to the key.
1.  `NONE`
    No additional attributes required.

Command to write the configuration to the plugin
```shell
$ vault write securosys-hsm/config {config_attributes}
```
```shell
curl --location --request PUT '<server_addr>/v1/securosys-hsm/config' \
--header 'X-Vault-Token: <vault_access_token>' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode '{config_attribute_key}={config_attribute_value}' \
```
**Example for disabled authorization**:
```shell
$ vault write securosys-hsm/config 
auth="NONE" 
restapi="https://primusdev.cloudshsm.com"
```

```shell
curl --location --request PUT '<server_addr>/v1/securosys-hsm/config' \
--header 'X-Vault-Token: <vault_access_token>' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'auth=NONE' \
--data-urlencode 'restapi=https://primusdev.cloudshsm.com'
```
**Example for JWT token authorization**:
```shell
$ vault write securosys-hsm/config 
auth="TOKEN" 
bearertoken="jwt token string"
restapi="https://primusdev.cloudshsm.com"
```

```shell
curl --location --request PUT '<server_addr>/v1/securosys-hsm/config' \
--header 'X-Vault-Token: <vault_access_token>' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'auth=TOKEN' \
--data-urlencode 'bearertoken=jwt token string' \
--data-urlencode 'restapi=https://primusdev.cloudshsm.com'
```
**Example for Certificate authorization**:
```shell
$ vault write securosys-hsm/config 
auth="CERT" 
certpath="local_absolute_path_to_certificate.pem"
keypath="local_absolute_path_to_private.key"
restapi="https://primusdev.cloudshsm.com"
```

```shell
curl --location --request PUT '<server_addr>/v1/securosys-hsm/config' \
--header 'X-Vault-Token: <vault_access_token>' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'auth=CERT' \
--data-urlencode 'certpath=local_absolute_path_to_certificate.pem' \
--data-urlencode 'keypath=local_absolute_path_to_private.pem' \
--data-urlencode 'restapi=https://primusdev.cloudshsm.com'
```


<!-- There are multiple options for authorization -->
> **Note:** On any changes of the configuration, the plugin will try to reach out the defined TSB using the provided configuration. If the connection was successful, the plugin will write/overwrite the configuration, otherwise the previous configuration remains unchanged.
---
#### MetaData signature
**From version 1.2.0**

Additionally there is a option to generate signature for metadata on all asynchronous requests.
**applicationKeyPair** option is using to provide RSA public key and private key.
Using this key will be generated signature for metadata.
format ```'{\"privateKey\":\"private_key_string\",\"publicKey\":\"public_key_string\"}'```
> **Note:** You have to provide **private key** and **public key** without headers

Example:
```shell
$ vault write securosys-hsm/config 
auth="CERT" 
certpath="local_absolute_path_to_certificate.pem"
keypath="local_absolute_path_to_private.key"
restapi="https://primusdev.cloudshsm.com"
applicationKeyPair="{\"privateKey\":\"MIIEvgIBADANBg...\",\"publicKey\":\"MIIBIjANBgkqh...\"}"
```

#### TSB ApiKeys
**From version 1.2.0**
Secrets engine use only 3 of TSB api keys:
- **ServiceToken** - for health check
- **KeyManagementToken** - for creating/listing/deleting keys
- **KeyOperationToken** - for operations on keys like decrypt/encrypt, sign/verify etc.

> **Structure for api keys**: There is a option to provide multiple api keys per single **token**. Plugin will check witch one of the list is correct one, and use only working  token for operation.

```
apiKeys="{\"KeyManagementToken\":[\"tsb-x-token_key_management1\",\"tsb-x-token_key_management2\",\"tsb-x-token_key_management3\" ...],\"KeyOperationToken\":[\tsb-x-token_key_operation\"],\"ServiceToken\":[\"tsb-x-token_service\"]}" 
```

Plugin configuration with api keys:
```shell
$ vault write securosys-hsm/config 
auth="CERT" 
certpath="local_absolute_path_to_certificate.pem"
keypath="local_absolute_path_to_private.key"
restapi="https://primusdev.cloudshsm.com"
apiKeys="{\"KeyManagementToken\":[\"tsb-x-token_key_management\"],\"KeyOperationToken\":[\tsb-x-token_key_operation\"],\"ServiceToken\":[\"tsb-x-token_service\"]}" 
```

### Manage Keys
The plugin allows to create, modify, and manage keys on the Securosys Primus HSM or CloudsHSM by the following command sets:
1) **list** - List all keys stored in the **HSM**
    ```shell
    $ vault list securosys-hsm/keys_hsm
    ```
    
    ```shell
    curl --location --request LIST '<server_addr>/v1/securosys-hsm/keys_hsm' \
    --header 'X-Vault-Token: <vault_access_token>'
    ```

1) **list** - List all keys stored in the **Secrets Engine**
    ```shell
    $ vault list securosys-hsm/keys
    ```
    or for more a more detailed list
    ```shell
    $ vault list -detailed securosys-hsm/keys
    ```
    
    ```shell
    curl --location --request LIST '<server_addr>/v1/securosys-hsm/keys' \
    --header 'X-Vault-Token: <vault_access_token>'
    ```
1) **list key versions** - List all key versions stored in the **Secrets Engine**
    ```shell
    $ vault list securosys-hsm/keys/{key-name}
    ```
    or for a more detailed list
    ```shell
    $ vault list -detailed securosys-hsm/keys/{key-name}
    ```
    
    ```shell
    curl --location --request LIST '<server_addr>/v1/securosys-hsm/keys' \
    --header 'X-Vault-Token: <vault_access_token>'
    ```
    
1) **read** - Read stored key info like **key label**, **policy** or **public key**
    ```shell
    $ vault read securosys-hsm/keys/{key-name} 
    ```
    ```shell
    curl --location --request GET '<server_addr>/v1/securosys-hsm/keys/{key-name}' \
    --header 'X-Vault-Token: <vault_access_token>'
    ```

    Result of this command will be
    ```
    Key           Value
    ---           ---
    algorithm     {key-type}            //For example: RSA, AES etc.
    attributes    {key-attributes}
    key_size      {key-size}
    keyLabel      {key-label-hsm}
    policy        {policy}              //If exists
    public_key    {public-key-from-hsm} //If exists. Only in asymetric key
    curveOid      {cureveoid}           //If exists. Only in EC or ED algorithms
    ...
    ```

1) **write** - Create or update a key on the **HSM** and store the reference in **Secrets Engine**
    Available key types:
    - **aes**
        > *Required:* **keyLabel**, **attributes** and **keySize**[128,192,256]
        > *Optionally:* **password**

    - **bls**         
        > *Required:* **keyLabel** and **attributes**
        > *Optionally:* **policy** and **password**

    - **camellia**
        > *Required:* **keyLabel**, **attributes** and **keySize**[128,192,256]
        > *Optionally:*  **password**
 
    - **chacha20**
        > *Required:* **keyLabel** and **attributes**
        > *Optionally:* **password**

    - **dsa**
        > *Required:* **keyLabel**, **attributes** and **keySize**[512,1024,2048]
        > *Optionally:* **policy** and **password**
        
    - **ec**
        > *Required:* **keyLabel**, **attributes** and **curveOid**
        > *Optionally:* **policy** and **password**
        
    - **ed**
        > *Required:* **keyLabel**, **attributes** and **curveOid**
        > *Optionally:* **policy** and **password**
        
    - **rsa**
        > *Required:* **keyLabel**, **attributes** and **keySize**[1024,2048,3072,4096]
        > *Optionally:* **policy** and **password**
        
    - **tdea**
        > *Required:* **keyLabel**, **attributes**
        > *Optionally:* **password**
    
    > **NOTE:** All fields are described in **Appendix: Key Arguments**

    > **IMPORTANT:** All keys created via Secrets Engine, have by default set the key attributes [destroyable] and [modifiable]. These attributes can be changed or extended by defining them in the `attributes` argument.  

    ```shell
    $ vault write securosys-hsm/keys/{key-type}/{key-name} 
    keyLabel="{key-label-hsm}"
    keySize={key-size} 
    #{key-attriute}:{true/false}
    attributes='{"decrypt": true,"sign": false,"unwrap": true,"derive": true,"sensitive": true,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}'
    ```
    ```shell
    curl --location --request PUT '<server_addr>/v1/securosys-hsm/keys/{key-type}/{key-name}' \
    --header 'X-Vault-Token: <vault_access_token>' \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'keyLabel={key-label-hsm}' \
    --data-urlencode 'keySize={key-size}' \
    --data-urlencode 'attributes={
        #{key-attriute}:{true/false}
        "decrypt": true,
        "sign": false,
        "unwrap": true,
        "derive": true,
        "sensitive": true,
        "alwaysSensitive": true,
        "extractable": false,
        "neverExtractable": true,
        "modifiable": true,
        "copyable": false,
        "destroyable": true
    }'
    ```

    Or here an example creating a key with attached simple approval policy:
 
    ```shell
    $ vault write securosys-hsm/keys/{key-type}/{key-name} 
    keyLabel="{key-label-hsm}"
    keySize={key-size} 
    #{key-attriute}:{true/false}
    attributes='{"decrypt": true,"sign": false,"unwrap": true,"derive": true,"sensitive": true,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}' 
    simplePolicy=-<<EOF
        {
        "NameOfApprover": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArBohRHhXXjQMNlxWMmCX0fxbpcMyu3bwBerkfeTl8QoOZbDV003t1n9drCuGOJJP16sZRBkYa5C7QkFCyb10Lbp1sp8jqWVu5PQy9qEaLl4y2BW+AOs0pURv1nlyo+gFgJD6lX0QmtZDjaD98C/wC5RVXipr4nJmT5XvwCPmgz9TpgVgFMwrflPJK9mHgYKwvmPODLYSLbohkj4TWKAoL417URhPazNWJBC7fKRui3EA7a8yzuzOSVgGxjY3aeqitmZyCTJtWa2U2/UwLZRT2ISwXv0zvsBhRSbXXcFdCApgKiy9uL1tPq40DnT8cesZzKd8hDYJ5S34wwmSZKbtGwIDAQAB"
        }
    EOF
    ```
    ```shell
    curl --location --request PUT '<server_addr>/v1/securosys-hsm/keys/{key-type}/{key-name}' \
    --header 'X-Vault-Token: <vault_access_token>' \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'keyLabel={key-label-hsm}' \
    --data-urlencode 'keySize={key-size}' \
    --data-urlencode 'attributes={
        #{key-attriute}:{true/false}
        "decrypt": true,
        "sign": false,
        "unwrap": true,
        "derive": true,
        "sensitive": true,
        "alwaysSensitive": true,
        "extractable": false,
        "neverExtractable": true,
        "modifiable": true,
        "copyable": false,
        "destroyable": true
    }' \
    --data-urlencode 'simplePolicy={
        #{name}:{public_key}
        "NameOfApprover": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArBohRHhXXjQMNlxWMmCX0fxbpcMyu3bwBerkfeTl8QoOZbDV003t1n9drCuGOJJP16sZRBkYa5C7QkFCyb10Lbp1sp8jqWVu5PQy9qEaLl4y2BW+AOs0pURv1nlyo+gFgJD6lX0QmtZDjaD98C/wC5RVXipr4nJmT5XvwCPmgz9TpgVgFMwrflPJK9mHgYKwvmPODLYSLbohkj4TWKAoL417URhPazNWJBC7fKRui3EA7a8yzuzOSVgGxjY3aeqitmZyCTJtWa2U2/UwLZRT2ISwXv0zvsBhRSbXXcFdCApgKiy9uL1tPq40DnT8cesZzKd8hDYJ5S34wwmSZKbtGwIDAQAB"
    }'
    ```
 
    Where `simplePolicy` has to be a **JSON** object in which **Key** is the name of the approval (or the approver) and **Value** has to be a valid **RSA public key** (without the "-- Begin..." and "-- End..." lines nor line breaks).

    The result of these commands will show information about the created key.

    > **NOTE:** Full SKA policy **json** can be provided by using the **policy** attribute in place of **simplePolicy**. As a policy json statement can  be very large it might be difficult to edit it on command line. In such case it is recommended to attach a file with the json, using the attribute **"policy=@file.json"**. An example of the policy json file can be found in **Appendix: Full Policy JSON Example**

1) **register** - Register an existing key stored on the HSM to Secrets Engine
    ```shell
    $ vault write securosys-hsm/keys/{key-name}/register keyLabel={label-of-key-on-hsm}
    ```
    ```shell
    curl --location --request PUT '<server_addr>/v1/securosys-hsm/keys/{key-name}/register' \
    --header 'X-Vault-Token: <vault_access_token>'
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'keyLabel={label-of-key-on-hsm}'
    ```
    > **NOTE:** This key will be registered in Secrets Engine with the name **{key-name}**

1) **create key by type name** - Create a key using key types compatible with OpenBao Key Management. (https://developer.hashicorp.com/vault/api-docs/secret/key-management)

    **Available key types:**
    | Key Type  |      Description      |
    |----------|-------------|
    | aes128-gcm96 |  AES-GCM with a 128-bit AES key and a 96-bit nonce (**symmetric**) |
    | aes256-gcm96 |  AES-GCM with a 256-bit AES key and a 96-bit nonce (**symmetric**) |
    | chacha20-poly1305 |  ChaCha20 (**symmetric**) |
    | rsa-2048 |  RSA with bit size of 2048 (**asymmetric**) |
    | rsa-3072 |  RSA with bit size of 3072 (**asymmetric**) |
    | rsa-4096 |  RSA with bit size of 4096 (**asymmetric**) |
    | ecdsa-p256 |  ECDSA using the P-256 elliptic curve (**asymmetric**) |
    | ecdsa-p384 |  ECDSA using the P-384 elliptic curve (**asymmetric**) |
    | ecdsa-p521 |  ECDSA using the P-521 elliptic curve (**asymmetric**) |
    | ed25519    |  ED (**asymmetric**) |

    ```shell
    $ vault write securosys-hsm/keys/type/{key-type-name}/{key-name} keyLabel={label-of-key-on-hsm}
    algorithm={key-algorithm}
    attributes={key-attributes}
    password={password}
    simplePolicy={policy} or policy={full-policy} or policy=@policy-file.json
    ```
    ```shell
    curl --location --request PUT '<server_addr>/v1/securosys-hsm/keys/type/{key-type-name}/{key-name}' \
    --header 'X-Vault-Token: <vault_access_token>'
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'keyLabel={label-of-key-on-hsm}' \
    --data-urlencode 'algorithm={key-algorithm}' \
    --data-urlencode 'attributes={key-attributes}' \
    --data-urlencode 'password={password}' \
    --data-urlencode 'simplePolicy={policy}' or --data-urlencode 'policy={full-policy}'
    ```
    > **NOTE:** This key will be generated in Secrets Engine with the name **{key-name}**

1) **create PQC key** - Create a post-quantum cryptography key on the **HSM** and store the reference in **Secrets Engine**

    **Available PQC key algorithms:**
    | Key Algorithm | Usage |
    |----------|-------------|
    | ML-DSA-44 | Sign and verify |
    | ML-DSA-65 | Sign and verify |
    | ML-DSA-87 | Sign and verify |
    | SLH-DSA-SHA2-128s | Sign and verify |
    | SLH-DSA-SHA2-128f | Sign and verify |
    | SLH-DSA-SHA2-192s | Sign and verify |
    | SLH-DSA-SHA2-192f | Sign and verify |
    | SLH-DSA-SHA2-256s | Sign and verify |
    | SLH-DSA-SHA2-256f | Sign and verify |
    | SLH-DSA-SHAKE-128s | Sign and verify |
    | SLH-DSA-SHAKE-128f | Sign and verify |
    | SLH-DSA-SHAKE-192s | Sign and verify |
    | SLH-DSA-SHAKE-192f | Sign and verify |
    | SLH-DSA-SHAKE-256s | Sign and verify |
    | SLH-DSA-SHAKE-256f | Sign and verify |
    | ML-KEM-512 | Wrap and unwrap |
    | ML-KEM-768 | Wrap and unwrap |
    | ML-KEM-1024 | Wrap and unwrap |
    | LMS | Sign and verify |
    | XMSS-SHA256_10_256 | Sign and verify |
    | XMSS-SHAKE256_10_256 | Sign and verify |

    ```shell
    $ vault write securosys-hsm/keys/pqc/{pqc-algorithm}/{key-name} \
    keyLabel="{key-label-hsm}" \
    attributes='{"decrypt": false,"encrypt": false,"sign": true,"verify": true,"wrap": false,"unwrap": false,"extractable": true,"destroyable": true}'
    ```
    ```shell
    curl --location --request PUT '<server_addr>/v1/securosys-hsm/keys/pqc/{pqc-algorithm}/{key-name}' \
    --header 'X-Vault-Token: <vault_access_token>' \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'keyLabel={key-label-hsm}' \
    --data-urlencode 'attributes={"decrypt": false,"encrypt": false,"sign": true,"verify": true,"wrap": false,"unwrap": false,"extractable": true,"destroyable": true}'
    ```

    For ML-KEM keys, use wrap/unwrap attributes instead:

    ```json
    {"decrypt": false,"encrypt": false,"sign": false,"verify": false,"wrap": true,"unwrap": true,"extractable": true,"destroyable": true}
    ```

    > **NOTE:** TSB returns LMS keys with algorithm `HSS-LMS` and XMSS keys with algorithm `XMSS`; Secrets Engine accepts these returned names for sign/verify validation.

    **PQC signature algorithms:**
    | Key family | Signature algorithms |
    |----------|-------------|
    | ML-DSA | `ML_DSA`, `ML_DSA_M`, `SHA2_224_WITH_ML_DSA`, `SHA2_256_WITH_ML_DSA`, `SHA2_384_WITH_ML_DSA`, `SHA2_512_WITH_ML_DSA`, `SHA3_224_WITH_ML_DSA`, `SHA3_256_WITH_ML_DSA`, `SHA3_384_WITH_ML_DSA`, `SHA3_512_WITH_ML_DSA`, `SHAKE_128_WITH_ML_DSA`, `SHAKE_256_WITH_ML_DSA` |
    | SLH-DSA | `SLH_DSA`, `SHA2_224_WITH_SLH_DSA`, `SHA2_256_WITH_SLH_DSA`, `SHA2_384_WITH_SLH_DSA`, `SHA2_512_WITH_SLH_DSA`, `SHA3_224_WITH_SLH_DSA`, `SHA3_256_WITH_SLH_DSA`, `SHA3_384_WITH_SLH_DSA`, `SHA3_512_WITH_SLH_DSA`, `SHAKE_128_WITH_SLH_DSA`, `SHAKE_256_WITH_SLH_DSA` |
    | LMS | `LMS` |
    | XMSS | `XMSS-SHA256_10_256`, `XMSS-SHAKE256_10_256` |

1) **import** - Import a new key into the HSM
    ```shell
    $ vault write securosys-hsm/keys/{key-name}/import 
    keyLabel={label-of-key-on-hsm}
    privateKey={private-key-base64}
    publicKey={public-key-base64}
    secretKey={secret-key-base64}
    certificate={certificate-base64}
    algorithm={key-algorithm}
    attributes={key-attributes}
    simplePolicy={policy} or policy={full-policy} or policy=@policy-file.json
    ```
    ```shell
    curl --location --request PUT '<server_addr>/v1/securosys-hsm/keys/{key-name}/import' \
    --header 'X-Vault-Token: <vault_access_token>'
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'keyLabel={label-of-key-on-hsm}' \
    --data-urlencode 'privateKey={private-key-base64}' \
    --data-urlencode 'publicKey={public-key-base64}' \
    --data-urlencode 'secretKey={secret-key-base64}' \
    --data-urlencode 'certificate={certificate-base64}' \
    --data-urlencode 'algorithm={key-algorithm}' \
    --data-urlencode 'attributes={key-attributes}' \
    --data-urlencode 'simplePolicy={policy}' or --data-urlencode 'policy={full-policy}'
    ```
    > **NOTE:** This key will be labeled in Secrets Engine with **{key-name}**
    
1) **export** - Export public_key, private_key, or secret from a key stored on the HSM
    ```shell
    $ vault write securosys-hsm/keys/{key-name}/export [password={password-for-a-key}]
    ```
    ```shell
    curl --location --request PUT '<server_addr>/v1/securosys-hsm/keys/{key-name}/export' \
    --header 'X-Vault-Token: <vault_access_token>'
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'password={password-for-a-key}'
    ```
    > **NOTE:** Omit the **password** parameter in case no password is set.
    

1) **modify** - Modify the SKA policy of a key stored on the HSM
In case the key has a policy attached, then a request-id is returned indicating the required approvals to collect. See section [Requests](#requests).
    ```shell
    $ vault write securosys-hsm/keys/{key-name}/modify     
    [simplePolicy={policy} | policy={full-policy} | policy=@policy-file.json]
    [password={password-for-a-key}]
    [additionalMetaData={additional-meta-data-in-json-object-format}]
    ```
    ```shell
    curl --location --request PUT '<server_addr>/v1/securosys-hsm/keys/{key-name}/modify' \
    --header 'X-Vault-Token: <vault_access_token>'
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'simplePolicy={policy}' or  --data-urlencode 'policy={full-policy}' \
    --data-urlencode 'password={password-for-a-key}' \
    --data-urlencode 'additionalMetaData={additional-meta-data-in-json-object-format}'
    ```
    > **NOTE:** Omit the **password** parameter in case no password is set.
    
1) **update-password** - Modify the password of a key on the HSM
    ```shell
    $ vault write securosys-hsm/keys/{key-name}/update-password password={current-password} newPassword="{new-password}"
    ```
    ```shell
    curl --location --request PUT '<server_addr>/v1/securosys-hsm/keys/{key-name}/update-password' \
    --header 'X-Vault-Token: <vault_access_token>'
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'password={current-password}' \
    --data-urlencode 'newPassword={new-password}' \
    ```
    
1) **rotate** - Rotate a key. A new key will be generated on the HSM with the same base name as the original key with an incremented version tag at the end of the original key name (_v2, _v3, ...). The previous key will remain on the HSM. 

    ```shell
    $ vault write securosys-hsm/keys/{key-name}/rotate
    ```
    ```shell
    curl --location --request PUT '<server_addr>/v1/securosys-hsm/keys/{key-name}/rotate' \
    --header 'X-Vault-Token: <vault_access_token>' \
    --header 'Content-Type: application/x-www-form-urlencoded' 
    ```
    > **NOTE:** Decrypt, verify, unwrap etc. is still possible by providing the parameter  **keyVersion** in the request. All other operations like encrypt, sign, wrap, block, unblock, password etc. will always use the last key version.

1) **block** - Block a key stored on the HSM
In case the key has a policy attached, then a request-id is returned indicating the required approvals to collect. See section [Requests](#requests).
    ```shell
    $ vault write securosys-hsm/keys/{key-name}/block [password={password-for-a-key}] [additionalMetaData={additional-meta-data-in-json-object-format}]
    ```
    ```shell
    curl --location --request PUT '<server_addr>/v1/securosys-hsm/keys/{key-name}/block' \
    --header 'X-Vault-Token: <vault_access_token>'
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'password={password-for-a-key}' \
    --data-urlencode 'additionalMetaData={additional-meta-data-in-json-object-format}'
    ```
    > **NOTE:** Omit the **password** parameter in case no password is set.
    
1) **unblock** - Unblock a key stored on the HSM 
In case the key has a policy attached, then a request-id is returned indicating the required approvals to collect. See section [Requests](#requests).
    ```shell
    $ vault write securosys-hsm/keys/{key-name}/unblock [password={password-for-a-key}] [additionalMetaData={additional-meta-data-in-json-object-format}]
    ```
    ```shell
    curl --location --request PUT '<server_addr>/v1/securosys-hsm/keys/{key-name}/unblock' \
    --header 'X-Vault-Token: <vault_access_token>'
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'password={password-for-a-key}' \
    --data-urlencode 'additionalMetaData={additional-meta-data-in-json-object-format}'
    ```
    > **NOTE:** Omit the **password** parameter in case no password is set.
    
1) **delete** - Remove a key from the **HSM** and **Secrets Engine**
    ```shell
    $ vault delete securosys-hsm/keys/{key-name} [removeFromHSM=true]
    ```
    ```shell
    curl --location --request DELETE '<server_addr>/v1/securosys-hsm/keys/{key-name}' \
    --header 'X-Vault-Token: <vault_access_token>'
    ```
    > **NOTE:** This operation removes the key only from the **Secrets Engine**. It does not remove the key from the **HSM**. To remove all key versions from the HSM as well, then add the property **removeFromHSM** with **_true_** value. 
    
1) **xml** - Fetch a key attestation from the HSM in XML format, signed with the HSMs attestation key.
    ```shell
    $ vault read securosys-hsm/keys/{key-name}/xml
    ```
    ```shell
    curl --location --request GET '<server_addr>/v1/securosys-hsm/keys/{key-name}/xml' \
    --header 'X-Vault-Token: <vault_access_token>'
    --header 'Content-Type: application/x-www-form-urlencoded' \
    ```


---
### Cryptographic Operations
Below are the cryptographic operations that can be done using keys on the HSM.

1) **Encrypt** - Encrypt a payload

    ```shell
    $ vault write securosys-hsm/operation/encrypt/{key-name} 
    payload={base64-encoded-string}
    password={password-of-the-key}
    cipherAlgorithm={cipher-algorithm}
    tagLength={tag-length}
    additionalAuthenticationData={additional-authentication-data}
    ```

    ```shell
    curl --location --request PUT '<server_addr>/v1/securosys-hsm/operation/encrypt/{key-name}' \
    --header 'X-Vault-Token: <vault_access_token>'
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'payload={base64-encoded-string}' \
    --data-urlencode 'password={password-for-a-key}' \
    --data-urlencode 'cipherAlgorithm={cipher-algorithm}' \
    --data-urlencode 'tagLength={tag-length}' \
    --data-urlencode 'additionalAuthenticationData={additional-authentication-data}'
    ```

1) **Decrypt** - Decrypt an encrypted payload
In case the referenced key has a policy attached, then a request-id is returned indicating the required approvals to collect.  See section [Requests](#requests).
    > **Note:** The **keyVersion** has to be provided in this request, either by adding it in the url (e.g. `securosys-hsm/operation/decrypt/{key-name}/{key-version}`), or by passing it as parameter (e.g.`keyVersion={key-version}`).

    ```shell
    $ vault write securosys-hsm/operation/decrypt/{key-name} 
    password={password-for-a-key}
    keyVersion={key-version}
    encryptedPayload={base64-encoded-string}
    cipherAlgorithm={cipher-algorithm}
    initializationVector={initialization-vector}
    tagLength={tag-length}
    additionalAuthenticationData={additional-authentication-data}
    additionalMetaData={additional-meta-data-in-json-object-format}
    ```
    ```shell
    curl --location --request PUT '<server_addr>/v1/securosys-hsm/operation/decrypt/{key-name}' \
    --header 'X-Vault-Token: <vault_access_token>'
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'encryptedPayload={base64-encoded-string}' \
    --data-urlencode 'keyVersion={key-version}' \
    --data-urlencode 'cipherAlgorithm={cipher-algorithm}' \
    --data-urlencode 'password={password-for-a-key}' \
    --data-urlencode 'tagLength={tag-length}' \
    --data-urlencode 'initializationVector={initialization-vector}' \
    --data-urlencode 'additionalAuthenticationData={additional-authentication-data}' \
    --data-urlencode 'additionalMetaData={additional-meta-data-in-json-object-format}'
    ```

1) **Sign** - Sign a payload
In case the referenced key has a policy attached, then a request-id is returned, indicating the required approvals to be collected. See section [Requests](#requests)

    ```shell
    $ vault write securosys-hsm/operation/sign/{key-name}
    password={password-for-the-key}
    signatureAlgorithm={algorithm}
    payload={payload-base64}
    payloadType={payload-type}
    additionalMetaData={additional-meta-data-in-json-object-format}
    ```

    ```shell
    curl --location --request PUT '<server_addr>/v1/securosys-hsm/operation/sign/{key-name}' \
    --header 'X-Vault-Token: <vault_access_token>'
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'signatureAlgorithm={algorithm}' \
    --data-urlencode 'payload={payload-base64}' \
    --data-urlencode 'payloadType={payload-type}' \
    --data-urlencode 'password={password-for-a-key}' \
    --data-urlencode 'additionalMetaData={additional-meta-data-in-json-object-format}'
    ```
    
1) **Verify** - Verify the signature of a signed payload
    > **Note:** The **keyVersion** has to be provided in this request, either by adding it in the url (e.g. `securosys-hsm/operation/verify/{key-name}/{key-version}`), or by passing it as parameter (e.g.`keyVersion={key-version}`).
    ```shell
    $ vault write securosys-hsm/operation/verify/{key-name}
    password={password-for-the-key}
    signatureAlgorithm={algorithm}
    payload={payload-base64}
    signature={signature}
    ```

    ```shell
    curl --location --request PUT '<server_addr>/v1/securosys-hsm/operation/verify/{key-name}' \
    --header 'X-Vault-Token: <vault_access_token>'
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'signatureAlgorithm={algorithm}' \
    --data-urlencode 'payload={payload-base64}' \
    --data-urlencode 'password={password-for-a-key}' \
    --data-urlencode 'signature={meta-data-signature}'
    ```
    
1) **Wrap** - Wrap a key with another (wrapper) key

    ```shell
    $ vault write securosys-hsm/operation/wrap/{key-to-be-wrapped}/{wrap-key-name}
    keyToBeWrappedPassword={password-for-first-key}
    wrapKeyPassword={password-for-second-key}
    wrapMethod={wrap-method}
    ```

    ```shell
    curl --location --request PUT '<server_addr>/v1/securosys-hsm/operation/wrap/{key-to-be-wrapped}/{wrap-key-name}' \
    --header 'X-Vault-Token: <vault_access_token>'
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'keyToBeWrappedPassword={password-for-first-key}' \
    --data-urlencode 'wrapKeyPassword={password-for-second-key}' \
    --data-urlencode 'wrapMethod={wrap-method}'
    ```
    
1) **UnWrap** - Unwrap a key using a wrapper key
In case the referenced key has a policy attached, then a request-id is returned, indicating the required approvals to collect.  See section [Requests](#requests).

    > **Note:** The **keyVersion** has to be provided in this request, either by adding it in the url (e.g. `securosys-hsm/operation/unwrap/{new-unwrapped-key-name}/{wrap-key-name}/{key-version}`), or by passing it as parameter (e.g.`keyVersion={key-version}`).

    ```shell
    $ vault write securosys-hsm/operation/unwrap/{new-unwrapped-key-name}/{wrap-key-name}
    keyLabel={key-label-for-new-key}
    keyVersion={key-version}
    wrappedKey={wrapped-key-base64-encoded}
    password={password-for-wrap-key}
    wrapMethod={wrap-method}
    simplePolicy={policy} or policy={full-policy} or policy=@policy-file.json
    attributes={attributes}
    additionalMetaData={additional-meta-data-in-json-object-format}
    ```

    ```shell
    curl --location --request PUT '<server_addr>/v1/securosys-hsm/operation/unwrap/{new-unwrapped-key-name}/{wrap-key-name}' \
    --header 'X-Vault-Token: <vault_access_token>'
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'keyLabel={key-label-for-new-key}' \
    --data-urlencode 'keyVersion={key-version}' \
    --data-urlencode 'wrappedKey={wrapped-key-base64-encoded}' \
    --data-urlencode 'wrapMethod={wrap-method}' \
    --data-urlencode 'simplePolicy={policy}' or --data-urlencode 'policy={full-policy}' \
    --data-urlencode 'password={password-for-wrap-key}' \
    --data-urlencode 'attributes={attributes}' \
    --data-urlencode 'additionalMetaData={additional-meta-data-in-json-object-format}'
    ```

    
---
### Requests
In case a key has an SKA policy attached, a request object is returned instead of an instant result response, indicating the required approvals to be collected to process this request. 

For example:

```shell
Key                 Value
---                 -----
approvedBy          map[]
executionTime       n/a
id                  a0d1dc5c-3c0a-415f-a184-6eaffcb9fd07
notYetApprovedBy    map[NameOfApprover:MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAouyYMgsCbxdr6cN7EDIR4ZcB82/fAIZusqyNXpX6gcRTwnrxZfIlyATdAm7ascxgYIK+L2M9UFVKTPUxus/Hzfuq0Fro5tdH+DWwfYQtcB5vap3UTw3yNpi6/MUe1x1Odwwi3no3jE2OuF1k6wjyrbWBkyktF3g8BmOD0DFpGl4IIlE8u1NgOMyAzlIuzAiyl4aCHrddhfV6gFtrRqfpUMz0twXYYoHlK0khzVEVn757WZZcIQFZmjKMfp/Yl/CAkBrTGVnFHMmNOYq7L9vhoR71rPmU9u2sy6IaT97qox/e7HSW47N2YNSiuJeq08I3Tn/kyw6+pSjAMu4A48PrfQIDAQAB]
rejectedBy          map[]
request             map[key:custom_rsa3 keyLabel:CUSTOM_RSA_4]
result              n/a
status              PENDING
type                UnBlock
...
etc.
```

To handle such requests there are the following additional commands:
1) **list** - List all requests initialized in **Secrets Engine**
    ```shell
    $ vault list securosys-hsm/requests
    ```
    or for a more detailed list
    ```shell
    $ vault list -detailed securosys-hsm/requests
    ```
    
    ```shell
    curl --location --request LIST '<server_addr>/v1/securosys-hsm/requests' \
    --header 'X-Vault-Token: <vault_access_token>'
    ```
1) **read** - Show detailed request information
    
    ```shell
    $ vault read securosys-hsm/requests/{id} 
    ```
    ```shell
    curl --location --request GET '<server_addr>/v1/securosys-hsm/requests/{id}' \
    --header 'X-Vault-Token: <vault_access_token>'
    ```

1) **delete** - Remove a request from **Secrets Engine** and **HSM**
    ```shell
    $ vault delete securosys-hsm/requests/{id} 
    ```
    ```shell
    curl --location --request DELETE '<server_addr>/v1/securosys-hsm/requests/{id}' \
    --header 'X-Vault-Token: <vault_access_token>'
    ```

---
### Additional Command Options
All Securosys Secrets Engine commands have the additional options:
1) **-field** (string: "") - Print only the field with the given name. Specifying this option will take precedence over other formatting directives. The result will not have a trailing newline making it ideal for piping to other processes.
1) **-format** (string: "table") - Print the output in the given format. Valid formats are "table", "json", "yaml", or "raw". This can also be specified via the VAULT_FORMAT environment variable.

---
### Help
The command **path-help** will print help information of a specific path
```shell
$ vault path-help {path}
```

## Test Suite
This plugin contains prepared tests written in Golang, which can be used to test changes or all features with the used Securosys Transaction Security Broker (TSB) instance.

### Preparing
First adapt the test configuration file `additional_test_config.go`
```go
var configParams map[string]interface{} = map[string]interface{}{
	"restapi":     "TSB_ADDRESS",
	"auth":        "TOKEN",
	"bearertoken": "BEARER_TOKEN",
}
```
Provide all necessary information in the test configuration file to gain access to the REST/TSB instance of your HSM. See [Configuration](#configure-the-plugin) section.

### Running tests
To run all tests execute the following command in a terminal
```shell
$ go test -timeout 30m -run ^(TestOperationsEncrypt|TestOperationsSign|TestOperationsWrap|TestConfig|TestAESKey|TestBLSKey|TestCHACHA20Key|TestCamelliaKey|TestECKey|TestEDKey|TestIMPORTKey|TestRSAKey|TestTDEAKey|TestDSAKey|TestOperationsDecrypt|TestOperationsVerify|TestOperationsUnWrap|TestRequests|TestRotateKeys|TestCreateKeyUsingTypeName)$ secretengine
```
Or run each test separately:
| Test   |      Description      |
|:----------|:-------------|
| TestConfig | Tests write and read configuration of the plugin |
| TestAESKey | Tests connection, create, read, and delete an **AES** key  |
| TestBLSKey | Tests connection, create, read, and delete a **BLS** key | 
| TestCamelliaKey | Tests connection, create, read, and delete a **Camellia** key | 
| TestCHACHA20Key | Tests connection, create, read, and delete a **ChaCha20** key | 
| TestDSAKey | Tests connection, create, read, and delete a **DSA** key | 
| TestECKey | Tests connection, create, read, and delete an **EC** key | 
| TestEDKey | Tests connection, create, read, and delete an **ED** key | 
| TestIMPORTKey | Tests connection, import, read, and delete an **Imported AES** key | 
| TestRSAKey | Tests connection, create, read, and delete an **RSA** key | 
| TestTDEAKey | Tests connection, create, read, and delete a **TDEA** key | 
| TestKeys | Tests connection and all key operations (**modify**, **block**, **unblock**, **list**, **register**) | 
| TestOperationsDecrypt | Tests connection and synchronous decrypt operations for all types of keys| 
| TestOperationsEncrypt | Tests connection and encrypt operations for all types of keys | 
| TestOperationsSign | Tests connection and synchronous sign operations for all types of keys | 
| TestOperationsUnWrap | Tests connection and synchronous unwrap operations for all types of keys | 
| TestOperationsVerify | Tests connection and verify operations for all types of keys | 
| TestOperationsWrap | Tests connection and wrap operations for all types of keys | 
| TestRequests | Tests connection and all asynchronous operations (with policy) for all types of keys | 
| TestRotateKeys | Tests key rotation option for all type of keys | 
| TestCreateKeyUsingTypeName | Tests key creation based on types supported by OpenBao Key Management| 

## Integrations
### MariaDB
Encryption on MariaDB can be enabled using existing plugin [OpenBao Key Management Plugin](https://mariadb.com/kb/en/hashicorp-key-management-plugin/) 
This integration stores generated secret in Secrets engine, encrypted by provided key.
**Supported Key Types**/**Algorithm** combinations:
| Key Type | Algorithm |
|----------|:-------------:|
| **RSA** |RSA_PADDING_OAEP_WITH_SHA512<br>RSA<br> RSA_PADDING_OAEP_WITH_SHA224<br> RSA_PADDING_OAEP_WITH_SHA256<br>RSA_PADDING_OAEP_WITH_SHA1<br>RSA_PADDING_OAEP<br> RSA_PADDING_OAEP_WITH_SHA384<br> RSA_NO_PADDING|
|**AES**|AES_GCM<br>AES_CTR<br>AES_ECB<br>AES_CBC_NO_PADDING<br>AES |
| **CHACHA20** | CHACHA20<br>CHACHA20_AEAD|
| **CAMELLIA** | CAMELLIA<br>CAMELLIA_CBC_NO_PADDING<br>CAMELLIA_ECB |
|**TDEA**| TDEA_CBC<br>TDEA_ECB<br>TDEA_CBC_NO_PADDING |

>**Note** - Plugin supports **asynchronous decrypt operation** using key type **RSA** with **policy** with setup **ruleUse**. Using the key with policy will **stop** the decrypt operation and **wait for approvals** to be collected.

There are a **serval steps** that is needed to be done before setup encryption on MariaDB
1) [Create / Register key](#manage-keys) into **Secrets Engine**
1) Generate new **secret** and encrypt it using stored key 
    ```shell
    $ vault write securosys-hsm/integrations/mariadb/{secret-name}     
    keyName={key-name-from-secret-engine}
    cipherAlgorithm={cipher-algorithm}
    [additionalAuthenticationData={additional-authentication-data}]
    [tagLength={tag-length}]
    [password={password-for-a-key}]
    ```

    ```shell
    curl --location --request PUT '<server_addr>/v1/securosys-hsm/integrations/mariadb/{secret-name} ' \
    --header 'X-Vault-Token: <vault_access_token>'
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'keyName={key-name-from-secret-engine}' \
    --data-urlencode 'cipherAlgorithm={cipher-algorithm}' \
    --data-urlencode 'tagLength={tag-length}' \
    --data-urlencode 'additionalAuthenticationData={additional-authentication-data}' \
    --data-urlencode 'password={password-for-a-key}'
    ```
    >**Note** - Every request on this endpoint using same **key name** and **secret name** will **rotate secret**
1) The last step is add this configuration to **my.cfg**
    ```ini
    [mariadb]
    plugin-load-add=hashicorp_key_management.so
    loose-hashicorp-key-management
    loose-hashicorp-key-management-vault-url="{vault_address}/v1/securosys-hsm/integrations/mariadb/{secret_name}/?key_name={key-name}&cipher_algorithm={cipher_algorithm}&tag_length={tag_length}&aad={additional_authentication_data}&password={password}&version="
    loose-hashicorp-key-management-token="{vault_access_token}"
    loose-hashicorp-key-management-check-kv-version="off"
    #max timeout is 86400 seconds
    loose-hashicorp-key-management-timeout=3000 
    loose-hashicorp-key-management-retries=0
    loose-hashicorp-key-management-use-cache-on-timeout="on"
    loose-hashicorp-key-management-caching-enabled="on"
    #1 year in miliseconds
    loose-hashicorp-key-management-cache-timeout=31556952000 
    #1 year in miliseconds
    loose-hashicorp-key-management-cache-version-timeout=31556952000

    #Example of innodb config
    innodb_encrypt_tables = ON
    innodb_encrypt_temporary_tables = ON
    innodb_encrypt_log = ON
    innodb_encryption_threads = 4
    innodb_encryption_rotate_key_age = 1
    ```
    >**Note** - In **loose-hashicorp-key-management-vault-url** url need to ends with **&version=**. Plugin from **MariaDB** automatically add to end of url **number of secret version** 
#### MariaDB usage example
This example using default configuration for **OpenBao dev server**.
| Data | Value |
|----------|:-------------:|
| **vault address** | https://localhost:8200 |
| **vault access token** | root |
1) **Create key** *MariaDBEncryptionKey* with key size *4096* with attributes at last "decrypt" equals *true* on HSM and store it as *mariadb_encryption_key* on **Secrets engine**
    ```shell
    $ vault write securosys-hsm/keys/rsa/mariadb_encryption_key 
    keyLabel="MariaDBEncryptionKey"
    keySize=4096 
    attributes='{"decrypt": true,"sign": false,"unwrap": false,"derive": true,"sensitive": true,"extractable": false,"modifiable": false,"copyable": false,"destroyable": true}'
    ```
    or
    ```shell
    curl --location --request PUT 'https://localhost:8200/v1/securosys-hsm/keys/rsa/mariadb_encryption_key' \
    --header 'X-Vault-Token: root' \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'keyLabel=MariaDBEncryptionKey' \
    --data-urlencode 'keySize=4096' \
    --data-urlencode 'attributes={
        "decrypt": true,
        "sign": false,
        "unwrap": false,
        "derive": true,
        "sensitive": true,
        "extractable": false,
        "neverExtractable": true,
        "modifiable": false,
        "copyable": false,
        "destroyable": true
    }'
    ```
1) Generate new **secret** called *mariadb_secret* and **encrypt it** using cipher algorithm *RSA* and stored key *mariadb_encryption_key* in **Secrets engine** 
    ```shell
    $ vault write securosys-hsm/integrations/mariadb/mariadb_secret   
    keyName=mariadb_encryption_key
    cipherAlgorithm=RSA
    ```
    or
    ```shell
    curl --location --request PUT 'https://localhost:8200/v1/securosys-hsm/integrations/mariadb/mariadb_secret ' \
    --header 'X-Vault-Token: root'
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'keyName=mariadb_encryption_key' \
    --data-urlencode 'cipherAlgorithm=RSA'
    ```
3. Configure **MariaDB plugin** "OpenBao Key Management" in database configuration in **my.cnf**

    ```ini
    [mariadb]
    plugin-load-add=hashicorp_key_management.so
    loose-hashicorp-key-management
    loose-hashicorp-key-management-vault-url="https://localhost:8200/v1/securosys-hsm/integrations/mariadb/mariadb_secret/?key_name=mariadb_encryption_key&cipher_algorithm=RSA&version="
    loose-hashicorp-key-management-token="root"
    loose-hashicorp-key-management-check-kv-version="off"
    #max timeout is 86400 seconds
    loose-hashicorp-key-management-timeout=3000 
    loose-hashicorp-key-management-retries=0
    loose-hashicorp-key-management-use-cache-on-timeout="on"
    loose-hashicorp-key-management-caching-enabled="on"
    #1 year in miliseconds
    loose-hashicorp-key-management-cache-timeout=31556952000 
    #1 year in miliseconds
    loose-hashicorp-key-management-cache-version-timeout=31556952000

    #Example of innodb config
    innodb_encrypt_tables = ON
    innodb_encrypt_temporary_tables = ON
    innodb_encrypt_log = ON
    innodb_encryption_threads = 4
    innodb_encryption_rotate_key_age = 1
    ```



---
## Appendix
### Frequently Asked Questions
1) > **I got the error 'no handler for route "securosys-hsm/...". route entry found, but backend is nil.'** 
    In case of ```no handler for route "securosys-hsm/...". route entry found, but backend is nil.``` error, try to replace the secrets engine binary and to register the new upgraded plugin. See [How to run > Upgrade plugin](#upgrade-the-plugin)

1) > **Why I don't get a public key and policy on some key types** 
    Some key types are symmetric, and therefore don't have a public key nor a SKA policy.

1) > **I have an error on unwrapping a key - status: 500, body: {"errorCode":701,"reason":"res.error.in.hsm","message":"Error unwrapping key"}** 
    Probably the provided key label is already in use with another key on the HSM, or the request contains a policy for a symmetric key.

### Key Arguments

> **keyLabel:** The created key will be stored on the HSM with this name. This parameter is **required**. 

> **attributes:** The attributes of the key that should be created. At least one cryptographic operation (**decrypt**, **sign**, **unwrap**) must be allowed (**true**). This parameter is **required**. 

**Available key attributes:**
1) **encrypt** - The key can be used to encrypt data. 
1) **decrypt** - The key can be used to decrypt data.
1) **verify** - The key can be used to verify signatures. 
1) **sign** - The key can be used to create signatures.
1) **wrap** - The key can be used to wrap another key.
1) **unwrap** - The key can be used to unwrap keys.
1) **derive** - The key can be derivable. **default**: *false*
1) **bip32** - Key derivation is done using BIP32. This option can only be true if the key's algorithm is EC and the derive attribute is true. **default**: *false*
1) **extractable** - The key is extractable. This option can only be true for keys without smart key attributes. **default**: *false*
1) **modifiable** - The key can be modified. **default**: *true*
1) **destroyable** - The key can be deleted. **default**: *true*
1) **sensitive** - The key is sensitive. To export a key sensitive must be false
1) **copyable** - The encrypted key is stored in an external memory. **default**: *false*

**Structure** Allows to define the attributes as a **JSON object**. Key = Value structure.
For example:
```json
{
  "decrypt": true,
  "sign": true,
  "unwrap": true,
  "derive": true,
  "modifiable": true,
  "copyable": false,
  "destroyable": true
}
```
> **curveOid:** The oid of the curve used for the EC or ED algorithm. Mandatory if the chosen algorithm is set to EC or ED. Sample OID's: secp256k1=1.3.132.0.10, Ed25519=1.3.101.112, secp384r1=1.3.132.0.34, (prime256v1 / secp256r1): 1.2.840.10045.3.1.7 

> **keySize:** The length of the key. Only applicable for AES, Camellia, RSA , DSA.

> **policy:** Defines the SKA policy of a key. Contains the rules to use this key for signing a payload in a sign request, the rules to block and unblock this key, and the rules to modify the policy of this key. If a rule is empty the associated operation can be performed without any approvals. If the policy is empty the key does not use smart key attributes, and it is not possible to add them later. If a policy is used with the key, the key cannot be exported.
**Structure** Allows to define all required approvals as a **JSON object**. Key = Value structure.

For example:
```json
{
  "TM": public_key_1,
  "WK": public_key_2,
}
```
### Full Policy JSON Example
```json
{
  "ruleUse": {
    "tokens": [
      {
        "name": "Token Name",
        "timelock": 0,
        "timeout": 0,
        "groups": [
          {
            "name": "Group Name",
            "quorum": 1,
            "approvals": [
              {
                "type": "public_key",
                "name": "Name",
                "value": "RSA_PUBLIC_KEY"
              }
            ]
          }
        ]
      }
    ]
  },
  "ruleBlock": {
    "tokens": [
      {
        "name": "Token Name",
        "timelock": 0,
        "timeout": 0,
        "groups": [
          {
            "name": "Group Name",
            "quorum": 1,
            "approvals": [
              {
                "type": "public_key",
                "name": "Name",
                "value": "RSA_PUBLIC_KEY"
              }
            ]
          }
        ]
      }
    ]
  },
  "ruleUnblock": {
    "tokens": [
      {
        "name": "Token Name",
        "timelock": 0,
        "timeout": 0,
        "groups": [
          {
            "name": "Group Name",
            "quorum": 1,
            "approvals": [
              {
                "type": "public_key",
                "name": "Name",
                "value": "RSA_PUBLIC_KEY"
              }
            ]
          }
        ]
      }
    ]
  },
  "ruleModify": {
    "tokens": [
      {
        "name": "Token Name",
        "timelock": 0,
        "timeout": 0,
        "groups": [
          {
            "name": "Group Name",
            "quorum": 1,
            "approvals": [
              {
                "type": "public_key",
                "name": "Name",
                "value": "RSA_PUBLIC_KEY"
              }
            ]
          }
        ]
      }
    ]
  },
  "keyStatus": {
    "blocked": false
  }
}
```
## Getting Support
**Community Support for Securosys open source software:**
In our Community we welcome contributions. The Community software is open source and community supported, there is no support SLA, but a helpful best-effort Community.

 - To report a problem or suggest a new feature, use the [Issues](https://github.com/securosys-com/hcvault-plugin-secrets-engine/issues) tab. 

**Commercial Support for REST/TSB and HSM related issues:** 
Securosys customers having an active support contract, open a support ticket via [Securosys Support Portal](https://support.securosys.com/external/service-catalogue/21).

**Getting a temporary CloudsHSM developer account:**
Check-out a time limited developer account by registering [here](https://app.securosys.com) and choosing *Trial Account*.

## License
 Securosys Secrets Engine is licensed under the Apache License, please see [LICENSE](https://github.com/securosys-com/hcvault-plugin-secrets-engine/LICENSE). 
