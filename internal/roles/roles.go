// Package roles detects Windows server roles (Domain Controller, Exchange,
// etc.) so collection can specialize per target. Detection is read-only registry
// presence probing — it interprets nothing and collects nothing. It exists so a
// role-specific collection module (e.g. ad_collection) can cleanly skip on a
// host that does not have its role, and so the preflight can tell the analyst
// what the target actually is.
package roles

// Role identifies a Windows server role SAFE can detect and specialize
// collection for.
type Role string

const (
	RoleDomainController Role = "Domain Controller"
	RoleExchange         Role = "Exchange Server"
	RoleIIS              Role = "IIS Web Server"
)

// Detect returns the set of server roles present on the current host, in a
// stable order. An empty result means a plain workstation or member server with
// no specialized role SAFE collects for. Detection relies only on live host
// state (the registry), never on a shadow copy, so it is safe to call during
// collection planning before any VSS shadow exists.
func Detect() []Role {
	var found []Role
	if IsDomainController() {
		found = append(found, RoleDomainController)
	}
	if IsExchangeServer() {
		found = append(found, RoleExchange)
	}
	if IsIISServer() {
		found = append(found, RoleIIS)
	}
	return found
}
