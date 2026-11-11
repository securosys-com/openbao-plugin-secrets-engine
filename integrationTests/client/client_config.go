package integrationClient

type VaultClientConfig struct {
	Port int
    Url string
	RootToken string
	SecretsEnginePath string
}

var VaultConfig VaultClientConfig=VaultClientConfig{
	Port: 8251,
	Url: "http://127.0.0.1",
	RootToken: "root",
	SecretsEnginePath: "securosys-hsm",
}