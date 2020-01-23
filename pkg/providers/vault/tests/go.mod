module test-vault-integration

go 1.12

// Remove this replace when these changes get merged to the edgex repo
replace github.com/edgexfoundry/go-mod-secrets => ../../../../

require (
	github.com/edgexfoundry/go-mod-core-contracts v0.1.42
	github.com/edgexfoundry/go-mod-secrets v0.0.0-00010101000000-000000000000
)
