package module

import "time"

type NetworkSnapshot struct{}

func (m *NetworkSnapshot) Name() string              { return "network_snapshot" }
func (m *NetworkSnapshot) Priority() Priority        { return PriorityCritical }
func (m *NetworkSnapshot) TimeBudget() time.Duration { return 60 * time.Second }

func (m *NetworkSnapshot) Run(ctx *Context) Result {
	started := time.Now().UTC()
	result := Result{
		ModuleName: m.Name(),
		StartedAt:  started,
		Artifacts:  []Artifact{},
		Warnings:   []string{},
		Errors:     []string{},
	}

	if !prepareOutputDir(&result, ctx.OutputDir, started) {
		return result
	}

	commands := []Command{
		{Filename: "netstat_abno.txt", Name: "netstat", Args: []string{"-abno"}},
		{Filename: "netstat_ano.txt", Name: "netstat", Args: []string{"-ano"}},
		{Filename: "netstat_rn.txt", Name: "netstat", Args: []string{"-rn"}},
		{Filename: "arp_a.txt", Name: "arp", Args: []string{"-a"}},
		{Filename: "route_print.txt", Name: "route", Args: []string{"print"}},
		{Filename: "dns_cache.txt", Name: "ipconfig", Args: []string{"/displaydns"}},
		{
			Filename: "tcp_connections_powershell.txt",
			Name:     "powershell",
			Args: []string{
				"-NoProfile",
				"-Command",
				"Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,CreationTime | Format-List",
			},
		},
		{
			Filename: "udp_endpoints_powershell.txt",
			Name:     "powershell",
			Args: []string{
				"-NoProfile",
				"-Command",
				"Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess,CreationTime | Format-List",
			},
		},
		{
			Filename: "firewall_rules_enabled.txt",
			Name:     "powershell",
			Args: []string{
				"-NoProfile",
				"-Command",
				"Get-NetFirewallRule -Enabled True | Select-Object DisplayName,Direction,Action,Profile,Enabled | Format-List",
			},
		},
		{
			Filename: "firewall_profiles.txt",
			Name:     "powershell",
			Args:     []string{"-NoProfile", "-Command", "Get-NetFirewallProfile | Format-List"},
		},
		{
			Filename: "network_adapters.txt",
			Name:     "powershell",
			Args: []string{
				"-NoProfile",
				"-Command",
				"Get-NetAdapter | Format-List; Get-NetIPAddress | Format-List",
			},
		},
	}
	runCommands(ctx.Ctx, ctx.OutputDir, commands, &result)

	finalize(&result, started, ctx.Ctx)
	return result
}
