package module

import "time"

type NetworkSnapshot struct{}

func (m *NetworkSnapshot) Name() string              { return "network_snapshot" }
func (m *NetworkSnapshot) Priority() Priority        { return PriorityCritical }
func (m *NetworkSnapshot) TimeBudget() time.Duration { return 60 * time.Second }
func (m *NetworkSnapshot) RequiresVSS() bool         { return false }

// RequiresLiveHost is true: active network connections are volatile live-host
// state with no equivalent in a disk image.
func (m *NetworkSnapshot) RequiresLiveHost() bool { return true }

func (m *NetworkSnapshot) Run(ctx *Context) Result {
	started := time.Now().UTC()
	result := Result{
		ModuleName: m.Name(),
		StartedAt:  started,
		Artifacts:  []Artifact{},
		Findings:   []Finding{},
		Errors:     []string{},
	}

	if !prepareOutputDir(&result, ctx.OutputDir, started) {
		return result
	}

	commands := []Command{
		{
			Filename: "netstat_abno.txt",
			Name:     "netstat",
			Args:     []string{"-abno"},
			Check:    &ContentCheck{MustContain: []string{"Proto"}, MustNotContain: commonErrorSignatures},
		},
		{
			Filename: "netstat_ano.txt",
			Name:     "netstat",
			Args:     []string{"-ano"},
			Check:    &ContentCheck{MustContain: []string{"Proto"}, MustNotContain: commonErrorSignatures},
		},
		{
			Filename: "netstat_rn.txt",
			Name:     "netstat",
			Args:     []string{"-rn"},
			Check:    &ContentCheck{MustContain: []string{"Interface List"}, MustNotContain: commonErrorSignatures},
		},
		{
			Filename: "arp_a.txt",
			Name:     "arp",
			Args:     []string{"-a"},
			Check:    &ContentCheck{MustContain: []string{"Interface"}, MustNotContain: commonErrorSignatures},
		},
		{
			Filename: "route_print.txt",
			Name:     "route",
			Args:     []string{"print"},
			Check:    &ContentCheck{MustContain: []string{"Interface List"}, MustNotContain: commonErrorSignatures},
		},
		{Filename: "dns_cache.txt", Name: "ipconfig", Args: []string{"/displaydns"}, SkipChecks: true},
		{
			Filename: "tcp_connections_powershell.txt",
			Name:     "powershell",
			Args: []string{
				"-NoProfile",
				"-Command",
				"Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,CreationTime | Format-List",
			},
			Check: &ContentCheck{MustContain: []string{"LocalAddress"}, MustNotContain: commonErrorSignatures},
		},
		{
			Filename: "udp_endpoints_powershell.txt",
			Name:     "powershell",
			Args: []string{
				"-NoProfile",
				"-Command",
				"Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess,CreationTime | Format-List",
			},
			Check: &ContentCheck{MustContain: []string{"LocalAddress"}, MustNotContain: commonErrorSignatures},
		},
		{
			Filename: "firewall_rules_enabled.txt",
			Name:     "powershell",
			Args: []string{
				"-NoProfile",
				"-Command",
				"Get-NetFirewallRule -Enabled True | Select-Object DisplayName,Direction,Action,Profile,Enabled | Format-List",
			},
			Check: &ContentCheck{MustContain: []string{"DisplayName"}, MustNotContain: commonErrorSignatures},
		},
		{
			Filename: "firewall_profiles.txt",
			Name:     "powershell",
			Args:     []string{"-NoProfile", "-Command", "Get-NetFirewallProfile | Format-List"},
			Check:    &ContentCheck{MustContain: []string{"Enabled"}, MustNotContain: commonErrorSignatures},
		},
		{
			Filename: "network_adapters.txt",
			Name:     "powershell",
			Args: []string{
				"-NoProfile",
				"-Command",
				"Get-NetAdapter | Format-List; Get-NetIPAddress | Format-List",
			},
			Check: &ContentCheck{MustContain: []string{"InterfaceAlias"}, MustNotContain: commonErrorSignatures},
		},
	}
	runCommands(ctx.Ctx, ctx.OutputDir, commands, &result)

	finalize(&result, started, ctx.Ctx)
	return result
}
