package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/edgexfoundry/go-mod-core-contracts/clients/logger"
	"github.com/edgexfoundry/go-mod-secrets/pkg/providers/vault"
)

var rootTokenPtr = flag.String("token", "s.KhQILbtzYTGKbFQtonjuqNEQ", "token string (should be root token)")
var timeWindowPrt = flag.Int("window", 15, "how long to run the test in seconds")
var tokenPeriodPtr = flag.Int("period", 10, "token period in seconds")
var vaultHostPtr = flag.String("host", "localhost", "host of vault server")

func init() {
	// example with short version for long flag
	flag.StringVar(rootTokenPtr, "t", "s.KhQILbtzYTGKbFQtonjuqNEQ", "token string (should be root token)")
	flag.IntVar(timeWindowPrt, "w", 15, "how long to run the test in seconds")
	flag.IntVar(tokenPeriodPtr, "p", 10, "token period in seconds")
	flag.StringVar(vaultHostPtr, "h", "localhost", "host of vault server")
}

func main() {
	//Read root token
	flag.Parse()
	rootToken := *rootTokenPtr
	totalTimeWindow := time.Duration(*timeWindowPrt) * time.Second
	tokenPeriod := time.Duration(*tokenPeriodPtr) * time.Second
	vaultHost := *vaultHostPtr

	logger := logger.NewClientStdOut("test", false, "DEBUG")

	// Create token
	vaultPort := 8200
	tokenCreatPath := "/v1/auth/token/create"
	tokenLookupSelfPath := "/v1/auth/token/lookup-self"

	urlCreateToken := fmt.Sprintf("http://%s:%d%s", vaultHost, vaultPort, tokenCreatPath)
	urlLookupSelf := fmt.Sprintf("http://%s:%d%s", vaultHost, vaultPort, tokenLookupSelfPath)

	createTokenData := fmt.Sprintf(`{"ttl": "%s", "renewable": true, "period":"%s", "no_parent" : true}`, tokenPeriod.String(), tokenPeriod.String())

	response := makeHTTPCall(urlCreateToken, "POST", createTokenData, rootToken)
	var createTokenResp creatTokenResponse

	if err := json.Unmarshal(response, &createTokenResp); err != nil {
		panic(err)
	}

	authToken := createTokenResp.Auth.ClientToken

	logger.Debug(fmt.Sprintf("Created new client token: %v", authToken))

	config := vault.SecretConfig{
		Protocol:       "http",
		Host:           vaultHost,
		Port:           vaultPort,
		Authentication: vault.AuthenticationInfo{AuthToken: authToken}}

	ctx := context.Background()
	errChan := make(chan error)

	// Create SecrectClient to start the token refresh cycle
	_, err := vault.NewSecretClient(config, logger, ctx, errChan)
	if err != nil {
		panic(err)
	}

	timesUpticker := time.NewTicker(totalTimeWindow)
	lookUpSelfTicker := time.NewTicker(1 * time.Second)
	failures := 0
	tokenRefreshes := 0
	oldTTL := 0

	// Check for errors on error channel and query lookup for ttl changes
	for {
		select {
		case err = <-errChan:
			logger.Error(fmt.Sprint("Error from errChan ", err))
			failures++

		case <-lookUpSelfTicker.C:
			var response lookUpSelfResponse
			lookupData := makeHTTPCall(urlLookupSelf, "GET", "", authToken)

			if err := json.Unmarshal(lookupData, &response); err != nil {
				panic(err)
			}

			logger.Debug(fmt.Sprintf("Check lookup-self for token ttl: %v, period: %v", response.Data.TTL, response.Data.Period))

			// give a one second window to allow for token refresh time
			if response.Data.TTL < ((response.Data.Period / 2) - 1) {
				failures++
				logger.Debug(fmt.Sprintf("TTL fell below half of period ttl is %d, period is %d", response.Data.TTL, response.Data.Period))
			}

			if response.Data.TTL > oldTTL && oldTTL != 0 {
				tokenRefreshes++
			}

			oldTTL = response.Data.TTL

		case <-timesUpticker.C:
			logger.Debug("Time is up!")
			timesUpticker.Stop()
			lookUpSelfTicker.Stop()
			if failures > 0 {
				logger.Debug(fmt.Sprintf("Report: Token failed to refresh at least once, check the logs above for more details."))
			} else {
				logger.Debug(fmt.Sprintf("Report: Token refreshed as expected with a total time window of %s, and period of %s there were %v token refreshes.", totalTimeWindow.String(), tokenPeriod.String(), tokenRefreshes))
			}
			return
		}
	}
}

func makeHTTPCall(url string, httpMethod string, data string, token string) []byte {

	req, err := http.NewRequest(httpMethod, url, bytes.NewBuffer([]byte(data)))
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		panic(err)
	}

	return body
}

type auth struct {
	ClientToken   string `json:"client_token"`
	LeaseDuration int    `json:"lease_duration"`
	Renewable     bool   `json:"renewable"`
}

type creatTokenResponse struct {
	Auth auth `json:"auth"`
}

type lookUpSelfResponse struct {
	Data lookUpSelfData `json:"data"`
}

type lookUpSelfData struct {
	TTL    int `json:"ttl"`
	Period int `json:"period"`
}

func (obj creatTokenResponse) String() string {
	val, _ := json.Marshal(obj)
	return string(val)
}
