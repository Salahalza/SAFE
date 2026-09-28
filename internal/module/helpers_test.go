package module

import "testing"

// TestRootRelativePath locks the shadow-mount → volume-relative conversion used to
// read live web-root payloads off the VSS shadow's raw NTFS. Getting this wrong
// would send go-ntfs a bad path and silently drop back to an (AV-exposed) OS read.
func TestRootRelativePath(t *testing.T) {
	cases := []struct {
		name string
		src  string
		root string
		want string
	}{
		{
			name: "file under shadow mount",
			src:  `C:\safe_shadow_1\inetpub\wwwroot\shell.aspx`,
			root: `C:\safe_shadow_1`,
			want: `\inetpub\wwwroot\shell.aspx`,
		},
		{
			name: "nested path",
			src:  `C:\safe_shadow_1\inetpub\wwwroot\a\b\c.aspx`,
			root: `C:\safe_shadow_1`,
			want: `\inetpub\wwwroot\a\b\c.aspx`,
		},
		{
			name: "immediate child",
			src:  `C:\safe_shadow_1\file.aspx`,
			root: `C:\safe_shadow_1`,
			want: `\file.aspx`,
		},
		{
			name: "root itself is not a file",
			src:  `C:\safe_shadow_1`,
			root: `C:\safe_shadow_1`,
			want: "",
		},
		{
			name: "src outside root",
			src:  `C:\elsewhere\shell.aspx`,
			root: `C:\safe_shadow_1`,
			want: "",
		},
		{
			name: "empty root",
			src:  `C:\safe_shadow_1\x.aspx`,
			root: "",
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rootRelativePath(tc.src, tc.root); got != tc.want {
				t.Errorf("rootRelativePath(%q, %q) = %q, want %q", tc.src, tc.root, got, tc.want)
			}
		})
	}
}
