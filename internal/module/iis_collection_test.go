package module

import (
	"os"
	"testing"
)

// TestParseAppHostSites covers the discovery parse: web-root extraction from the
// root application's root virtual directory, per-site logFile override, and
// inheritance of the siteDefaults log directory when a site has no override. The
// real applicationHost.config was validated against this same function
// during development (two sites resolving to wwwroot and the Exchange
// ClientAccess root); this keeps that behavior locked in without shipping the
// full vendor config as a fixture.
func TestParseAppHostSites(t *testing.T) {
	cfg := []byte(`<configuration>
  <system.applicationHost>
    <log><centralW3CLogFile enabled="true" directory="C:\central" /></log>
    <sites>
      <siteDefaults><logFile directory="C:\inetpub\logs\LogFiles" /></siteDefaults>
      <site name="Default Web Site" id="1">
        <application path="/"><virtualDirectory path="/" physicalPath="C:\inetpub\wwwroot" /></application>
      </site>
      <site name="Custom" id="7">
        <application path="/"><virtualDirectory path="/" physicalPath="D:\sites\custom" /></application>
        <logFile directory="E:\customlogs" />
      </site>
    </sites>
  </system.applicationHost>
</configuration>`)

	sites, ok := parseAppHostSites(cfg, true)
	if !ok {
		t.Fatal("parseAppHostSites returned ok=false")
	}
	if len(sites) != 2 {
		t.Fatalf("expected 2 sites, got %d", len(sites))
	}

	byID := map[string]discoveredSite{}
	for _, s := range sites {
		byID[s.ID] = s
	}

	// Site 1 inherits the siteDefaults log directory.
	if s := byID["1"]; s.WebRootLive != `C:\inetpub\wwwroot` {
		t.Errorf("site 1 web root: got %q", s.WebRootLive)
	}
	if s := byID["1"]; s.LogDirLive != `C:\inetpub\logs\LogFiles` {
		t.Errorf("site 1 log dir (should inherit siteDefaults): got %q", s.LogDirLive)
	}

	// Site 7 overrides the log directory per-site.
	if s := byID["7"]; s.WebRootLive != `D:\sites\custom` {
		t.Errorf("site 7 web root: got %q", s.WebRootLive)
	}
	if s := byID["7"]; s.LogDirLive != `E:\customlogs` {
		t.Errorf("site 7 log dir (per-site override): got %q", s.LogDirLive)
	}
}

// TestExpandWinVarsImageModeIndependentOfHost proves that dead-image expansion
// resolves %VAR% tokens from the fixed image table, NOT the analyst's own
// environment, while live expansion still uses the host environment. This is the
// bug: an image config's paths were previously expanded against the collector's
// machine, which is a different host than the image.
func TestExpandWinVarsImageModeIndependentOfHost(t *testing.T) {
	// Make the host environment deliberately non-standard.
	os.Setenv("SystemDrive", "Z:")
	t.Cleanup(func() { os.Unsetenv("SystemDrive") })

	// Image mode ignores the host env and uses the standard placeholder drive
	// (which mapToRoot later strips before rejoining under the image root).
	if got := expandWinVars(`%SystemDrive%\inetpub\logs`, false); got != `C:\inetpub\logs` {
		t.Errorf("image mode: got %q, want C:\\inetpub\\logs (independent of host SystemDrive=Z:)", got)
	}
	// Live mode uses the host environment.
	if got := expandWinVars(`%SystemDrive%\inetpub\logs`, true); got != `Z:\inetpub\logs` {
		t.Errorf("live mode: got %q, want Z:\\inetpub\\logs (host SystemDrive)", got)
	}
	// Well-known non-drive var resolves in image mode.
	if got := expandWinVars(`%SystemRoot%\System32\inetsrv`, false); got != `C:\Windows\System32\inetsrv` {
		t.Errorf("image %%SystemRoot%%: got %q", got)
	}
	// Unknown tokens are left intact in both modes.
	if got := expandWinVars(`%NoSuchVar%\x`, false); got != `%NoSuchVar%\x` {
		t.Errorf("unknown token should stay intact, got %q", got)
	}
}
