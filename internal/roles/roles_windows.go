//go:build windows

package roles

import "golang.org/x/sys/windows/registry"

// keyExists reports whether a registry key can be opened for reading. A role is
// considered present when the marker key that only exists once that role is
// installed is present.
func keyExists(root registry.Key, path string) bool {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

// IsDomainController reports whether this host is an Active Directory domain
// controller. The NTDS service parameters key only exists once a server has
// been promoted (dcpromo / Install-ADDSForest), so its presence is a reliable
// DC marker. Validated against the lab DC (DC01) — this is the same key the
// preflight uses.
func IsDomainController() bool {
	return keyExists(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\NTDS\Parameters`)
}

// IsExchangeServer reports whether Microsoft Exchange (2013+) is installed,
// detected by the ExchangeServer\v15 product key.
func IsExchangeServer() bool {
	return keyExists(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\ExchangeServer\v15`)
}

// ExchangeInstallPath returns the Exchange installation root recorded in the
// Setup key (MsiInstallPath), e.g. "C:\Program Files\Microsoft\Exchange
// Server\V15", or "" if Exchange is not installed or the value is absent. The
// exchange_collection module uses this for discovery-first path resolution so it
// collects from a relocated install rather than assuming the default root.
func ExchangeInstallPath() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\ExchangeServer\v15\Setup`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue("MsiInstallPath")
	if err != nil {
		return ""
	}
	return v
}

// IsIISServer reports whether Internet Information Services is installed. The
// InetStp key is written once the IIS role/feature is present and holds the
// install path and version, so its presence is a reliable IIS marker. Note that
// Exchange installs IIS as a dependency — a box can therefore be both an
// Exchange server and an IIS server, which is expected and correct.
func IsIISServer() bool {
	return keyExists(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\InetStp`)
}
