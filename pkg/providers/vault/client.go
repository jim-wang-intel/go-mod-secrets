/*******************************************************************************
 * Copyright 2019 Dell Inc.
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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/edgexfoundry/go-mod-secrets/pkg"
)

const (
	AuthTypeHeader = "X-Vault-Token"
)

// Client defines the behavior for interacting with the Vault REST secret key/value store via HTTP(S).
type Client struct {
	HttpConfig SecretConfig
	HttpCaller Caller

	// internal member variables
	lc loggingClient
}

// package stateful map variable to handle the case of the same caller to have
// multiple secret clients with potentially the same tokens while renewing token
// in the background go-routine
var vaultTokenToCancelFunc = make(map[string]context.CancelFunc)

// NewSecretClient constructs a SecretClient which communicates with Vault via HTTP(S)
//
// lc is any logging client that implements the loggingClient interface;
// today EdgeX's logger.LoggingClient from go-mod-core-contracts satisfies this implementation
//
// bkgCtx is the background context that can be used to cancel or cleanup the background process when it is no longer needed
//
// errChan is the error channel to receive any error from the background go-routine calls
func NewSecretClient(config SecretConfig, lc loggingClient, bkgCtx context.Context, errChan chan<- error) (pkg.SecretClient, error) {
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

	if bkgCtx == nil {
		bkgCtx = context.Background()
	}
	// if there is context already associated with the given token,
	// then we cancel it first
	if cancel, exists := vaultTokenToCancelFunc[tokenStr]; exists {
		cancel()
	}

	ctx, cancel := context.WithCancel(bkgCtx)
	if err = secretClient.refreshToken(ctx, errChan); err != nil {
		cancel()
	} else {
		vaultTokenToCancelFunc[tokenStr] = cancel
	}

	return secretClient, err
}

func (c Client) refreshToken(ctx context.Context, errChan chan<- error) error {
	token := c.HttpConfig.Authentication.AuthToken

	tokenData, err := c.getTokenLookupResponseData()

	if err != nil {
		return err
	}

	if !tokenData.Data.Renewable {
		// token is not renewable, log warning and return
		c.lc.Warn(fmt.Sprintf("token '%s' is not renewable from the secret store", token))
		return nil
	}

	// the renew internval is half of period value
	tokenPeriod := time.Duration(tokenData.Data.Period) * time.Second
	renewInterval := tokenPeriod / 2
	if renewInterval <= 0 {
		// no renew
		c.lc.Warn(fmt.Sprintf("token '%s' renewInterval is 0, no token renewal", token))
		return nil
	}

	ttl := time.Duration(tokenData.Data.Ttl) * time.Second

	// if the current time-to-live is already less than the half of period
	// need to renew the token right away
	if ttl <= renewInterval {
		// call renew self api
		c.lc.Info("ttl already <= half of the renewal period")
		if err := c.renewToken(); err != nil {
			return err
		}
	}

	// goroutine to periodically renew the service token based on renewInterval
	go func() {
		ticker := time.NewTicker(renewInterval)
		for {
			select {
			case <-ctx.Done():
				ticker.Stop()
				c.lc.Info("context cancelled, dismiss the token renewal process")
				return
			case <-ticker.C:
				// renew token
				// if err happens then stop the ticker and return
				if err := c.renewToken(); err != nil {
					errChan <- err
					ticker.Stop()
					return
				}
			}
		}
	}()

	return nil
}

func (c Client) getTokenLookupResponseData() (*TokenLookupResponse, error) {
	// call Vault's token self lookup API
	url := c.HttpConfig.BuildURL() + "/v1/auth/token/lookup-self"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set(AuthTypeHeader, c.HttpConfig.Authentication.AuthToken)

	resp, err := c.HttpCaller.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, pkg.NewErrSecretStore(fmt.Sprintf("tried to lookup token but received a '%d' response from the secret store", resp.StatusCode))
	}

	defer resp.Body.Close()
	var result TokenLookupResponse
	jsonDec := json.NewDecoder(resp.Body)
	if jsonDec == nil {
		return nil, pkg.NewErrSecretStore("failed to obtain json decoder")
	}

	jsonDec.UseNumber()
	if err = jsonDec.Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (c Client) renewToken() error {
	// call Vault's renew self API
	url := c.HttpConfig.BuildURL() + "/v1/auth/token/renew-self"
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return err
	}

	req.Header.Set(AuthTypeHeader, c.HttpConfig.Authentication.AuthToken)

	resp, err := c.HttpCaller.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return pkg.NewErrSecretStore(fmt.Sprintf("tried to renew token but received a '%d' response from the secret store", resp.StatusCode))
	}

	defer resp.Body.Close()

	c.lc.Debug(fmt.Sprintf("successfully renewed token %s", c.HttpConfig.Authentication.AuthToken))
	return nil
}

// GetSecrets retrieves the secrets at the provided path that match the specified keys.
func (c Client) GetSecrets(path string, keys ...string) (map[string]string, error) {
	data := make(map[string]string)
	var err error
	addRetryAttempts := c.HttpConfig.AdditionalRetryAttempts
	switch {
	case addRetryAttempts < 0:
		return nil, pkg.NewErrSecretStore(fmt.Sprintf("invalid retry attempts setting %d", addRetryAttempts))
	case addRetryAttempts == 0:
		// no retries
		data, err = c.getAllKeys(path)
		if err != nil {
			return nil, err
		}
	case addRetryAttempts > 0:
		// do some retries
		// note the limit is 1 + additional retry attempts, cause we always need
		// to do the first try
		data, err = c.getAllKeys(path)

		for tryNum := 1; err != nil && tryNum < 1+addRetryAttempts; tryNum++ {
			time.Sleep(c.HttpConfig.retryWaitPeriodTime)

			data, err = c.getAllKeys(path)
		}

		// since we finished the above loop, then check if the last iteration
		// failed
		if err != nil {
			return nil, err
		}
	}

	// Do not filter any of the secrets
	if len(keys) <= 0 {
		return data, nil
	}

	values := make(map[string]string)
	var notFound []string

	for _, key := range keys {
		value, success := data[key]
		if !success {
			notFound = append(notFound, key)
			continue
		}

		values[key] = value
	}

	if len(notFound) > 0 {
		return nil, pkg.NewErrSecretsNotFound(notFound)
	}

	return values, nil
}

// getAllKeys obtains all the keys that reside at the provided path.
func (c Client) getAllKeys(path string) (map[string]string, error) {
	url := c.HttpConfig.BuildURL() + path
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set(c.HttpConfig.Authentication.AuthType, c.HttpConfig.Authentication.AuthToken)

	if c.HttpConfig.Namespace != "" {
		req.Header.Set(NamespaceHeader, c.HttpConfig.Namespace)
	}

	resp, err := c.HttpCaller.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, pkg.NewErrSecretStore(fmt.Sprintf("Received a '%d' response from the secret store", resp.StatusCode))
	}

	defer resp.Body.Close()
	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, err
	}

	data, success := result["data"].(map[string]interface{})
	if !success || len(data) <= 0 {
		return nil, pkg.NewErrSecretStore(fmt.Sprintf("No secrets are present at the path: '%s'", path))
	}

	// Cast the secret values to strings
	secrets := make(map[string]string)
	for k, v := range data {
		secrets[k] = v.(string)
	}

	return secrets, nil
}

// createHTTPClient creates and configures an HTTP client which can be used to communicate with the underlying
// secret-store based on the SecretConfig.
// Returns ErrCaRootCert is there is an error with the certificate.
func createHTTPClient(config SecretConfig) (Caller, error) {

	if config.RootCaCertPath == "" {
		return http.DefaultClient, nil
	}

	// Read and load the CA Root certificate so the client will be able to use TLS without skipping the verification of
	// the cert received by the server.
	caCert, err := ioutil.ReadFile(config.RootCaCertPath)
	if err != nil {
		return nil, ErrCaRootCert{
			path:        config.RootCaCertPath,
			description: err.Error(),
		}
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    caCertPool,
				ServerName: config.ServerName,
			},
		},
	}, nil
}

func (c Client) StoreSecrets(path string, secrets map[string]string) error {

	var err error
	addRetryAttempts := c.HttpConfig.AdditionalRetryAttempts
	switch {
	case addRetryAttempts < 0:
		err = pkg.NewErrSecretStore(fmt.Sprintf("invalid retry attempts setting %d", addRetryAttempts))
	case addRetryAttempts == 0:
		// no retries
		err = c.store(path, secrets)
	case addRetryAttempts > 0:
		// do some retries
		// note the limit is 1 + additional retry attempts, cause we always need
		// to do the first try
		err = c.store(path, secrets)

		for tryNum := 1; err != nil && tryNum < 1+addRetryAttempts; tryNum++ {
			time.Sleep(c.HttpConfig.retryWaitPeriodTime)

			err = c.store(path, secrets)
		}
	}

	return err
}

func (c Client) store(path string, secrets map[string]string) error {
	if len(secrets) == 0 {
		// nothing to store
		return nil
	}

	url := c.HttpConfig.BuildURL() + path

	payload, err := json.Marshal(secrets)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(payload))
	if err != nil {
		return err
	}

	req.Header.Set(c.HttpConfig.Authentication.AuthType, c.HttpConfig.Authentication.AuthToken)

	if c.HttpConfig.Namespace != "" {
		req.Header.Set(NamespaceHeader, c.HttpConfig.Namespace)
	}

	resp, err := c.HttpCaller.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		if resp.Body != nil {
			resp.Body.Close()
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return pkg.NewErrSecretStore(fmt.Sprintf("Received a '%d' response from the secret store", resp.StatusCode))
	}

	return nil
}
