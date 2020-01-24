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
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/edgexfoundry/go-mod-secrets/pkg"
)

var TestPath = "/data"
var TestConnError = pkg.NewErrSecretStore("testing conn error")
var TestNamespace = "database"
var testData = map[string]map[string]string{
	"data": {
		"one":   "uno",
		"two":   "dos",
		"three": "tres",
	},
}

type ErrorMockCaller struct {
	StatusCode  int
	ReturnError bool
	DoCallCount int
}

func (emc *ErrorMockCaller) Do(req *http.Request) (*http.Response, error) {
	emc.DoCallCount++
	if emc.ReturnError {
		return &http.Response{
			StatusCode: emc.StatusCode,
		}, TestConnError
	}

	return &http.Response{
		StatusCode: emc.StatusCode,
	}, nil
}

type InMemoryMockCaller struct {
	Data                 map[string]map[string]string
	Result               map[string]string
	DoCallCount          int
	nErrorsReturned      int
	NErrorsBeforeSuccess int
}

func (immc *InMemoryMockCaller) Do(req *http.Request) (*http.Response, error) {
	immc.DoCallCount++
	if immc.NErrorsBeforeSuccess != 0 {
		if immc.nErrorsReturned != immc.NErrorsBeforeSuccess {
			immc.nErrorsReturned++
			return &http.Response{
				StatusCode: 404,
			}, nil
		}
	}
	if req.Header.Get(NamespaceHeader) != TestNamespace {
		return nil, errors.New("namespace header is expected but not present in request")
	}

	switch req.Method {
	case http.MethodGet:
		if req.URL.Path != TestPath {
			return &http.Response{
				StatusCode: 404,
			}, nil
		}
		r, _ := json.Marshal(immc.Data)
		return &http.Response{
			Body:       ioutil.NopCloser(bytes.NewBufferString(string(r))),
			StatusCode: 200,
		}, nil

	case http.MethodPost:
		if req.URL.Path != TestPath {
			return &http.Response{
				StatusCode: 404,
			}, nil
		}
		var result map[string]string
		_ = json.NewDecoder(req.Body).Decode(&result)
		immc.Result = result
		return &http.Response{
			StatusCode: 200,
		}, nil
	default:
		return nil, errors.New("unsupported HTTP method")
	}
}

func TestNewSecretClient(t *testing.T) {
	authToken := "testToken"
	var tokenDataMap sync.Map
	tokenDataMap.Store(authToken, TokenLookupMetadata{
		Renewable: true,
		Ttl:       10000,
		Period:    10000,
	})
	server := getMockTokenServer(&tokenDataMap)
	defer server.Close()
	serverUrl, err := url.Parse(server.URL)
	if err != nil {
		t.Errorf("error on parsing server url %s: %s", server.URL, err)
	}
	host, port, _ := net.SplitHostPort(serverUrl.Host)
	portNum, _ := strconv.Atoi(port)

	cfgHTTP := SecretConfig{Protocol: "http", Host: host, Port: portNum, Authentication: AuthenticationInfo{AuthToken: authToken}}
	cfgInvalidCertPath := SecretConfig{Protocol: "https", Host: host, Port: portNum, RootCaCertPath: "/non-existent-directory/rootCa.crt", Authentication: AuthenticationInfo{AuthToken: authToken}}
	cfgNamespace := SecretConfig{Protocol: "http", Host: host, Port: portNum, Namespace: "database", Authentication: AuthenticationInfo{AuthToken: authToken}}
	cfgInvalidTime := SecretConfig{Protocol: "http", Host: host, Port: portNum, RetryWaitPeriod: "not a real time spec", Authentication: AuthenticationInfo{AuthToken: authToken}}
	cfgValidTime := SecretConfig{Protocol: "http", Host: host, Port: portNum, RetryWaitPeriod: "1s", Authentication: AuthenticationInfo{AuthToken: authToken}}
	cfgEmptyToken := SecretConfig{Protocol: "http", Host: host, Port: portNum, RetryWaitPeriod: "1s"}
	s := time.Second
	bkgCtx := context.Background()

	tests := []struct {
		name         string
		cfg          SecretConfig
		expectErr    bool
		expectedTime *time.Duration
	}{
		{"NewSecretClient HTTP configuration", cfgHTTP, false, nil},
		{"NewSecretClient invalid CA root certificate path", cfgInvalidCertPath, true, nil},
		{"NewSecretClient with Namespace", cfgNamespace, false, nil},
		{"NewSecretClient with invalid RetryWaitPeriod", cfgInvalidTime, true, nil},
		{"NewSecretClient with valid RetryWaitPeriod", cfgValidTime, false, &s},
		{"NewSecretClient with empty token", cfgEmptyToken, true, nil},
	}
	mockLogger := NewMockClient()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errCh := make(chan error, 1)

			c, err := NewSecretClient(tt.cfg, mockLogger, bkgCtx, errCh)
			if err != nil {
				if !tt.expectErr {
					t.Errorf("unexpected error: %v", err)
				}
			} else {
				if tt.expectErr {
					t.Errorf("did not receive expected error: %s", tt.name)
				}
				if tt.expectedTime != nil {
					if client, ok := c.(Client); ok {
						if *tt.expectedTime != client.HttpConfig.retryWaitPeriodTime {
							t.Errorf("expected parsed time as %v, got %v", *tt.expectedTime, client.HttpConfig.retryWaitPeriodTime)
						}
					} else {
						t.Errorf("returned client type is not Client, is %T", c)
					}
				}
			}
		})
	}
}

func TestHttpSecretStoreManager_GetValue(t *testing.T) {
	tests := []struct {
		name              string
		path              string
		keys              []string
		expectedValues    map[string]string
		expectError       bool
		expectedErrorType error
		retries           int
		expectedDoCallNum int
		caller            Caller
	}{
		{
			name:              "Get Key",
			path:              TestPath,
			keys:              []string{"one"},
			expectedValues:    map[string]string{"one": "uno"},
			expectError:       false,
			expectedErrorType: nil,
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:              "Get Keys",
			path:              TestPath,
			keys:              []string{"one", "two"},
			expectedValues:    map[string]string{"one": "uno", "two": "dos"},
			expectError:       false,
			expectedErrorType: nil,
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:              "Get all keys",
			path:              TestPath,
			keys:              nil,
			expectedValues:    map[string]string{"one": "uno", "two": "dos", "three": "tres"},
			expectError:       false,
			expectedErrorType: nil,
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:              "Get non-existent Key",
			path:              TestPath,
			keys:              []string{"Does not exist"},
			expectedValues:    nil,
			expectError:       true,
			expectedErrorType: pkg.NewErrSecretsNotFound([]string{"Does not exist"}),
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:              "Get all non-existent Keys",
			path:              TestPath,
			keys:              []string{"Does not exist", "Also does not exist"},
			expectedValues:    nil,
			expectError:       true,
			expectedErrorType: pkg.NewErrSecretsNotFound([]string{"Does not exist", "Also does not exist"}),
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:              "Get some non-existent Keys",
			path:              TestPath,
			keys:              []string{"one", "Does not exist", "Also does not exist"},
			expectedValues:    nil,
			expectError:       true,
			expectedErrorType: pkg.NewErrSecretsNotFound([]string{"Does not exist", "Also does not exist"}),
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:              "Handle HTTP error",
			path:              TestPath,
			keys:              []string{"Does not exist"},
			expectedValues:    nil,
			expectError:       true,
			expectedErrorType: TestConnError,
			expectedDoCallNum: 1,
			caller: &ErrorMockCaller{
				ReturnError: true,
				StatusCode:  404,
			},
		},
		{
			name:              "Handle non-200 HTTP response",
			path:              TestPath,
			keys:              []string{"Does not exist"},
			expectedValues:    nil,
			expectError:       true,
			expectedErrorType: TestConnError,
			expectedDoCallNum: 1,
			caller: &ErrorMockCaller{
				ReturnError: false,
				StatusCode:  404,
			},
		},
		{
			name:              "Get Key with unknown path",
			path:              "/nonexistentpath",
			keys:              []string{"one"},
			expectedValues:    nil,
			expectError:       true,
			expectedErrorType: TestConnError,
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:              "URL Error",
			path:              "bad path for URL",
			keys:              []string{"one"},
			expectedValues:    nil,
			expectError:       true,
			expectedErrorType: &url.Error{},
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:              "Retry 10 times, 1st success",
			retries:           10,
			path:              TestPath,
			keys:              []string{"one"},
			expectedValues:    map[string]string{"one": "uno"},
			expectError:       false,
			expectedErrorType: nil,
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:              "Retry 9 times, all HTTP status failures",
			retries:           9,
			path:              TestPath,
			keys:              []string{"one"},
			expectedValues:    map[string]string{"one": "uno"},
			expectError:       true,
			expectedErrorType: TestConnError,
			// expected is retries + 1
			expectedDoCallNum: 10,
			caller: &ErrorMockCaller{
				ReturnError: false,
				StatusCode:  404,
			},
		},
		{
			name:              "Retry 9 times, all catastrophic failure",
			retries:           9,
			path:              TestPath,
			keys:              []string{"one"},
			expectedValues:    map[string]string{"one": "uno"},
			expectError:       true,
			expectedErrorType: TestConnError,
			expectedDoCallNum: 10,
			caller: &ErrorMockCaller{
				ReturnError: true,
			},
		},
		{
			name:              "Retry 9 times, last works",
			retries:           9,
			path:              TestPath,
			keys:              []string{"one"},
			expectedValues:    map[string]string{"one": "uno"},
			expectError:       false,
			expectedDoCallNum: 10,
			caller: &InMemoryMockCaller{
				NErrorsBeforeSuccess: 9,
				Data:                 testData,
			},
		},
		{
			name:              "Invalid retry num",
			retries:           -1,
			path:              TestPath,
			keys:              []string{"one"},
			expectedValues:    map[string]string{"one": "uno"},
			expectError:       true,
			expectedErrorType: TestConnError,
			expectedDoCallNum: 0,
			caller: &ErrorMockCaller{
				ReturnError: true,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfgHTTP := SecretConfig{
				Host:                    "localhost",
				Port:                    8080,
				Protocol:                "http",
				Namespace:               TestNamespace,
				AdditionalRetryAttempts: test.retries,
			}
			ssm := Client{
				HttpConfig: cfgHTTP,
				HttpCaller: test.caller,
			}

			actual, err := ssm.GetSecrets(test.path, test.keys...)
			if test.expectedErrorType != nil && err == nil {
				t.Errorf("Expected error %v but none was recieved", test.expectedErrorType)
			}

			switch v := test.caller.(type) {
			case *ErrorMockCaller:
				if test.expectedDoCallNum != v.DoCallCount {
					t.Errorf("Expected %d ErrorMockCaller.Do calls, got %d", test.expectedDoCallNum, v.DoCallCount)
				}
			case *InMemoryMockCaller:
				if test.expectedDoCallNum != v.DoCallCount {
					t.Errorf("Expected %d InMemoryMockCaller.Do calls, got %d", test.expectedDoCallNum, v.DoCallCount)
				}
			}

			if !test.expectError && err != nil {
				t.Errorf("Unexpected error: %s", err.Error())
			}

			if test.expectError && test.expectedErrorType != nil {
				eet := reflect.TypeOf(test.expectedErrorType)
				aet := reflect.TypeOf(err)
				if !aet.AssignableTo(eet) {
					t.Errorf("Expected error of type %v, but got an error of type %v", eet, aet)
				}
			}

			if !test.expectError {
				for k, expected := range test.expectedValues {
					if actual[k] != expected {
						t.Errorf("Expected value '%s', but got '%s'", expected, actual[k])

					}
				}
			}
		})

	}
}

func TestHttpSecretStoreManager_SetValue(t *testing.T) {
	tests := []struct {
		name              string
		path              string
		secrets           map[string]string
		expectedValues    map[string]string
		expectError       bool
		expectedErrorType error
		retries           int
		expectedDoCallNum int
		caller            Caller
	}{
		{
			name:              "Set One Secret",
			path:              TestPath,
			secrets:           map[string]string{"one": "uno"},
			expectedValues:    map[string]string{"one": "uno"},
			expectError:       false,
			expectedErrorType: nil,
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:              "Set Multiple Secrets",
			path:              TestPath,
			secrets:           map[string]string{"one": "uno", "two": "dos"},
			expectedValues:    map[string]string{"one": "uno", "two": "dos"},
			expectError:       false,
			expectedErrorType: nil,
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:              "Handle non-200 HTTP response",
			path:              TestPath,
			secrets:           map[string]string{"": "empty"},
			expectedValues:    nil,
			expectError:       true,
			expectedErrorType: TestConnError,
			expectedDoCallNum: 1,
			caller: &ErrorMockCaller{
				ReturnError: false,
				StatusCode:  404,
			},
		},
		{
			name:              "Set One Secret with unknown path",
			path:              "/nonexistentpath",
			secrets:           map[string]string{"one": "uno"},
			expectedValues:    nil,
			expectError:       true,
			expectedErrorType: TestConnError,
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:              "URL Error",
			path:              "bad path for URL",
			secrets:           map[string]string{"one": "uno"},
			expectedValues:    nil,
			expectError:       true,
			expectedErrorType: &url.Error{},
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:              "Retry 10 times, 1st success",
			retries:           10,
			path:              TestPath,
			secrets:           map[string]string{"one": "uno"},
			expectedValues:    map[string]string{"one": "uno"},
			expectError:       false,
			expectedErrorType: nil,
			expectedDoCallNum: 1,
			caller: &InMemoryMockCaller{
				Data: testData,
			},
		},
		{
			name:              "Retry 9 times, all HTTP status failures",
			retries:           9,
			path:              TestPath,
			secrets:           map[string]string{"one": "uno"},
			expectedValues:    map[string]string{"one": "uno"},
			expectError:       true,
			expectedErrorType: TestConnError,
			// expected is retries + 1
			expectedDoCallNum: 10,
			caller: &ErrorMockCaller{
				ReturnError: false,
				StatusCode:  404,
			},
		},
		{
			name:              "Retry 9 times, all catastrophic failure",
			retries:           9,
			path:              TestPath,
			secrets:           map[string]string{"one": "uno"},
			expectedValues:    nil,
			expectError:       true,
			expectedErrorType: TestConnError,
			expectedDoCallNum: 10,
			caller: &ErrorMockCaller{
				ReturnError: true,
			},
		},
		{
			name:              "Retry 9 times, last works",
			retries:           9,
			path:              TestPath,
			secrets:           map[string]string{"one": "uno"},
			expectedValues:    map[string]string{"one": "uno"},
			expectError:       false,
			expectedDoCallNum: 10,
			caller: &InMemoryMockCaller{
				NErrorsBeforeSuccess: 9,
				Data:                 testData,
			},
		},
		{
			name:              "Invalid retry num",
			retries:           -1,
			path:              TestPath,
			secrets:           map[string]string{"one": "uno"},
			expectedValues:    nil,
			expectError:       true,
			expectedErrorType: TestConnError,
			expectedDoCallNum: 0,
			caller: &ErrorMockCaller{
				ReturnError: true,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfgHTTP := SecretConfig{
				Host:                    "localhost",
				Port:                    8080,
				Protocol:                "http",
				Namespace:               TestNamespace,
				AdditionalRetryAttempts: test.retries,
			}
			ssm := Client{
				HttpConfig: cfgHTTP,
				HttpCaller: test.caller,
			}

			err := ssm.StoreSecrets(test.path, test.secrets)
			if test.expectedErrorType != nil && err == nil {
				t.Errorf("Expected error %v but none was recieved", test.expectedErrorType)
			}

			switch v := test.caller.(type) {
			case *ErrorMockCaller:
				if test.expectedDoCallNum != v.DoCallCount {
					t.Errorf("Expected %d ErrorMockCaller.Do calls, got %d", test.expectedDoCallNum, v.DoCallCount)
				}
			case *InMemoryMockCaller:
				if test.expectedDoCallNum != v.DoCallCount {
					t.Errorf("Expected %d InMemoryMockCaller.Do calls, got %d", test.expectedDoCallNum, v.DoCallCount)
				}
			}

			if !test.expectError && err != nil {
				t.Errorf("Unexpected error: %s", err.Error())
			}

			if test.expectError && test.expectedErrorType != nil && err != nil {
				eet := reflect.TypeOf(test.expectedErrorType)
				aet := reflect.TypeOf(err)
				if !aet.AssignableTo(eet) {
					t.Errorf("Expected error of type %v, but got an error of type %v", eet, aet)
				}
			}

			if !test.expectError && test.secrets != nil {
				keys := make([]string, 0, len(test.secrets))
				for k, _ := range test.secrets {
					keys = append(keys, k)
				}
				actual, _ := ssm.GetSecrets(test.path, keys...)
				for k, expected := range test.expectedValues {
					if actual[k] != expected {
						t.Errorf("After storing secrets, expected value '%s', but got '%s'", expected, actual[k])

					}
				}
			}
		})
	}
}

func TestMultipleTokneRenewals(t *testing.T) {
	// setup
	tokenPeriod := 6
	var tokenDataMap sync.Map
	// ttl > half of period
	tokenDataMap.Store("testToken1", TokenLookupMetadata{
		Renewable: true,
		Ttl:       tokenPeriod * 7 / 10,
		Period:    tokenPeriod,
	})
	// ttl = half of period
	tokenDataMap.Store("testToken2", TokenLookupMetadata{
		Renewable: true,
		Ttl:       tokenPeriod / 2,
		Period:    tokenPeriod,
	})
	// ttl < half of period
	tokenDataMap.Store("testToken3", TokenLookupMetadata{
		Renewable: true,
		Ttl:       tokenPeriod * 3 / 10,
		Period:    tokenPeriod,
	})
	// expired token
	tokenDataMap.Store("expiredToken", TokenLookupMetadata{
		Renewable: true,
		Ttl:       0,
		Period:    tokenPeriod,
	})
	// not renewable token
	tokenDataMap.Store("unrenewableToken", TokenLookupMetadata{
		Renewable: false,
		Ttl:       0,
		Period:    tokenPeriod,
	})

	server := getMockTokenServer(&tokenDataMap)
	defer server.Close()

	serverUrl, err := url.Parse(server.URL)
	if err != nil {
		t.Errorf("error on parsing server url %s: %s", server.URL, err)
	}
	host, port, _ := net.SplitHostPort(serverUrl.Host)
	portNum, _ := strconv.Atoi(port)

	bkgCtx := context.Background()

	// error channel to receive any error from background process
	errCh := make(chan error, 1)
	go func() {
		tokenErr := <-errCh

		if tokenErr != nil {
			t.Errorf("error on handling token renewal: %s", tokenErr)
		}
	}()

	mockLogger := NewMockClient()
	tests := []struct {
		name              string
		authToken         string
		expectError       bool
		expectedErrorType error
	}{
		{
			name:              "New secret client with testToken1, more than half of TTL remaining",
			authToken:         "testToken1",
			expectError:       false,
			expectedErrorType: nil,
		},
		{
			name:              "New secret client with the same first token again",
			authToken:         "testToken1",
			expectError:       false,
			expectedErrorType: nil,
		},
		{
			name:              "New secret client with testToken2, half of TTL remaining",
			authToken:         "testToken2",
			expectError:       false,
			expectedErrorType: nil,
		},
		{
			name:              "New secret client with testToken3, less than half of TTL remaining",
			authToken:         "testToken3",
			expectError:       false,
			expectedErrorType: nil,
		},
		{
			name:              "New secret client with expired token, no TTL remaining",
			authToken:         "expiredToken",
			expectError:       true,
			expectedErrorType: pkg.NewErrSecretStore("forbidden"),
		},
		{
			name:              "New secret client with unauthenticated token",
			authToken:         "invalidToken",
			expectError:       true,
			expectedErrorType: pkg.NewErrSecretStore("forbidden"),
		},
		{
			name:              "New secret client with unrenewable token",
			authToken:         "unrenewableToken",
			expectError:       false,
			expectedErrorType: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfgHTTP := SecretConfig{
				Host:           host,
				Port:           portNum,
				Protocol:       "http",
				Authentication: AuthenticationInfo{AuthToken: test.authToken},
			}
			c, err := NewSecretClient(cfgHTTP, mockLogger, bkgCtx, errCh)

			if test.expectedErrorType != nil && err == nil {
				t.Errorf("Expected error %v but none was recieved", test.expectedErrorType)
			}

			if !test.expectError && err != nil {
				t.Errorf("Unexpected error: %s", err.Error())
			}

			if test.expectError && test.expectedErrorType != nil && err != nil {
				eet := reflect.TypeOf(test.expectedErrorType)
				aet := reflect.TypeOf(err)
				if !aet.AssignableTo(eet) {
					t.Errorf("Expected error of type %v, but got an error of type %v", eet, aet)
				}
			}

			client := c.(Client)

			// look up the token data again after renewal
			lookupTokenData, err := client.getTokenLookupResponseData()
			if !test.expectError && err != nil {
				t.Errorf("error on cfgAuthToken %s: %s", test.authToken, err)
			}

			if !test.expectError && lookupTokenData.Data.Renewable &&
				lookupTokenData.Data.Ttl < tokenPeriod/2 {
				tokenData, _ := tokenDataMap.Load(test.authToken)
				tokenTtl := tokenData.(TokenLookupMetadata).Ttl
				t.Errorf("the token period %d and failed to renew token: the current TTL %d and the old TTL: %d",
					tokenPeriod, lookupTokenData.Data.Ttl, tokenTtl)
			}
		})
	}
	// wait for some time to allow errCh to be consumed if any
	time.Sleep(7 * time.Second)
}

func getMockTokenServer(tokenDataMap *sync.Map) *httptest.Server {

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		urlPath := req.URL.String()
		if req.Method == http.MethodGet && urlPath == "/v1/auth/token/lookup-self" {
			token := req.Header.Get(AuthTypeHeader)
			sampleTokenLookup, exists := tokenDataMap.Load(token)
			if !exists {
				rw.WriteHeader(403)
				_, _ = rw.Write([]byte("permission denied"))
			} else {
				resp := &TokenLookupResponse{
					Data: sampleTokenLookup.(TokenLookupMetadata),
				}
				if ret, err := json.Marshal(resp); err != nil {
					rw.WriteHeader(500)
					_, _ = rw.Write([]byte(err.Error()))
				} else {
					rw.WriteHeader(200)
					_, _ = rw.Write(ret)
				}
			}
		} else if req.Method == http.MethodPost && urlPath == "/v1/auth/token/renew-self" {
			token := req.Header.Get(AuthTypeHeader)
			sampleTokenLookup, exists := tokenDataMap.Load(token)
			if !exists {
				rw.WriteHeader(403)
				_, _ = rw.Write([]byte("permission denied"))
			} else {
				currentTtl := sampleTokenLookup.(TokenLookupMetadata).Ttl
				if currentTtl <= 0 {
					// already expired
					rw.WriteHeader(403)
					_, _ = rw.Write([]byte("permission denied"))
				} else {
					tokenPeriod := sampleTokenLookup.(TokenLookupMetadata).Period

					tokenDataMap.Store(token, TokenLookupMetadata{
						Renewable: true,
						Ttl:       tokenPeriod,
						Period:    tokenPeriod,
					})
					rw.WriteHeader(200)
					_, _ = rw.Write([]byte("token renewed"))
				}
			}
		} else {
			rw.WriteHeader(404)
			_, _ = rw.Write([]byte(fmt.Sprintf("Unknown urlPath: %s", urlPath)))
		}
	}))
	return server
}
