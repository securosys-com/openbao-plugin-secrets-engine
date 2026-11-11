package integrationClient

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/hashicorp/vault-client-go"
)

func InitVaultClient() *vault.Client {

	// prepare a client with the given base address
	client, err := vault.New(
		vault.WithAddress(VaultConfig.Url+":"+fmt.Sprint(VaultConfig.Port)),
		vault.WithRequestTimeout(300*time.Second),
	)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	// authenticate with a root token (insecure)
	if err := client.SetToken(VaultConfig.RootToken); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	return client
}
