# Testing Vault Token Refresh

## Running the test

The docker-compose file is very simple and only contains one server 'vault'.  

1. Run `docker-compose up -d` to start a local unsealed vault container running in dev mod.  
2. Check vaults docker logs with `docker logs <vault image id>` near the top you will see a section that has the unseal key and root token.  Copy the root token to use in the next step.
3. Run the test golang file `go run main.go -token=<token-copied-from-step-2> -window=12 -period=6 -host=localhost`

The tests should output log messages indicating the progress.  

Below is an example of what the output should look like for a passing test (I removed some extra logging info for brevity)

```txt
... msg="Created new client token: s.ZhWVveQFxHs1btla6J1VpCVa"
... msg="Check lookup-self for token ttl: 5, period: 6"
... msg="Check lookup-self for token ttl: 4, period: 6"
... msg="Check lookup-self for token ttl: 3, period: 6"
... msg="successfully renewed token s.ZhWVveQFxHs1btla6J1VpCVa"
...
... msg="Time is up!"
... msg="Report: Token refreshed as expected with a total time window of 12s, and period of 6s there were 3 token refreshes."
```
