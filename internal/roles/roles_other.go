//go:build !windows

package roles

// Non-Windows build stubs. SAFE's collector only ever runs on Windows; these
// keep `go build ./...` green on a non-Windows dev host and always report the
// role as absent.

func IsDomainController() bool    { return false }
func IsExchangeServer() bool      { return false }
func IsIISServer() bool           { return false }
func ExchangeInstallPath() string { return "" }
