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
	"context"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	helpers "securosys.ch/helpers"
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(conf)
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// securosysBackend defines an object that
// extends the Vault backend and stores the
// target API's client.
type SecurosysBackend struct {
	*framework.Backend
	lock   sync.RWMutex
	client *TSBClient
	conf   *logical.BackendConfig
}

// backend defines the target API backend
// for Vault. It must include each path
// and the secrets it will store.
func Backend(conf *logical.BackendConfig) *SecurosysBackend {
	var b = SecurosysBackend{}
	b.conf = conf
	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{},
			SealWrapStorage: []string{
				"config",
				"keys/*",
			},
		},
		Paths: framework.PathAppend(
			pathHSM_AESKeys(&b),
			pathHSM_RSAKeys(&b),
			pathHSM_DSAKeys(&b),
			pathHSM_ChaCha20Keys(&b),
			pathHSM_CamelliaKeys(&b),
			pathHSM_TDEAKeys(&b),
			pathHSM_ECKeys(&b),
			pathHSM_EDKeys(&b),
			pathHSM_BLSKeys(&b),
			pathHSM_PQCKeys(&b),
			pathHSM_ImportKeys(&b),
			pathHSM_KeyNamesKeys(&b),
			pathHSMHealth(&b),
			pathHSMKeys(&b),
			pathOperations(&b),
			pathRequests(&b),
			pathMariaDBIntegration(&b),
			[]*framework.Path{
				pathConfig(&b),
			},
		),
		Secrets:     []*framework.Secret{},
		BackendType: logical.TypeLogical,
		Invalidate:  b.Invalidate,
	}
	return &b
}

// reset clears any client configuration for a new
// backend to be configured
func (b *SecurosysBackend) Reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
}

// invalidate clears an existing client configuration in
// the backend
func (b *SecurosysBackend) Invalidate(ctx context.Context, key string) {
	if key == "config" {
		b.Reset()
	}
}

// getClient locks the backend as it configures and creates a
// a new client for the target API
func (b *SecurosysBackend) GetClient(ctx context.Context, s logical.Storage) (*TSBClient, error) {
	b.lock.RLock()
	unlockFunc := b.lock.RUnlock
	defer func() { unlockFunc() }()

	if b.client != nil {
		return b.client, nil
	}

	b.lock.RUnlock()
	b.lock.Lock()
	unlockFunc = b.lock.Unlock

	config, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}

	if config == nil {
		config = new(helpers.SecurosysConfig)
	}

	b.client, err = NewTSBClient(config)
	if err != nil {
		return nil, err
	}

	return b.client, nil
}
