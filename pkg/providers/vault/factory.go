/*******************************************************************************
 * Copyright 2019 Dell Inc.
 * Copyright 2020 Intel Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *******************************************************************************/

package vault

import (
	"context"
	"time"

	"github.com/edgexfoundry/go-mod-secrets/pkg"
)

// a map variable to handle the case of the same caller to have
// multiple secret clients with potentially the same tokens while renewing token
// in the background go-routine
type vaultTokenToCancelFuncMap map[string]context.CancelFunc

type secretClientFactory struct {
	tokenCancelFunc vaultTokenToCancelFuncMap
}

// NewSecretClientFactory creates a new factory for manufactoring secret clients
// the facotry is maintaining an internal map of Vault tokens and context cancel functions
// for gracefully terminating the background goroutine per token
func NewSecretClientFactory() *secretClientFactory {
	return &secretClientFactory{
		tokenCancelFunc: make(vaultTokenToCancelFuncMap),
	}
}

// NewSecretClient constructs a SecretClient which communicates with Vault via HTTP(S)
//
// lc is any logging client that implements the loggingClient interface;
// today EdgeX's logger.LoggingClient from go-mod-core-contracts satisfies this implementation
//
// ctx is the background context that can be used to cancel or cleanup the background process when it is no longer needed
//
// errChan is the error channel to receive any error from the background go-routine calls
func (factory *secretClientFactory) NewSecretClient(ctx context.Context, config SecretConfig, lc loggingClient, errChan chan<- error) (pkg.SecretClient, error) {
	if ctx == nil {
		return nil, pkg.NewErrSecretStore("background ctx is required and cannot be nil")
	}

	tokenStr := config.Authentication.AuthToken
	if tokenStr == "" {
		return nil, pkg.NewErrSecretStore("AuthToken is required in config")
	}

	httpClient, err := createHTTPClient(config)
	if err != nil {
		return Client{}, err
	}

	if config.RetryWaitPeriod != "" {
		retryTimeDuration, err := time.ParseDuration(config.RetryWaitPeriod)
		if err != nil {
			return nil, err
		}
		config.retryWaitPeriodTime = retryTimeDuration
	}

	secretClient := Client{
		HttpConfig: config,
		HttpCaller: httpClient,
		lc:         lc,
	}

	// if there is context already associated with the given token,
	// then we cancel it first
	if cancel, exists := factory.tokenCancelFunc[tokenStr]; exists {
		cancel()
	}

	cCtx, cancel := context.WithCancel(ctx)
	if err = secretClient.refreshToken(cCtx, errChan); err != nil {
		cancel()
	} else {
		factory.tokenCancelFunc[tokenStr] = cancel
	}

	return secretClient, err
}