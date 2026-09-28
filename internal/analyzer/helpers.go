package analyzer

import "time"

// filetimeToTime converts a Windows FILETIME (100-nanosecond ticks since
// 1601-01-01 00:00:00 UTC) to a Go time.Time in UTC.
//
// This is the single authoritative implementation for the package; all parsers
// that need FILETIME conversion should call this function rather than defining
// their own. The previous bam_dam.go variant (filetimeToUTC) has been removed
// in favour of this one.
func filetimeToTime(ft uint64) time.Time {
	const filetimeEpochToUnix = 11644473600 // seconds between 1601-01-01 and 1970-01-01
	seconds := int64(ft/10_000_000) - filetimeEpochToUnix
	nanos := int64((ft % 10_000_000) * 100)
	return time.Unix(seconds, nanos).UTC()
}

// suspiciousExecPaths are lower-cased path fragments that are unusual homes for
// an executed program and common for dropped malware — a single shared list so
// the scheduled-task and BAM/DAM triage stay in sync (they previously kept
// byte-identical copies that could drift apart).
var suspiciousExecPaths = []string{
	`\temp\`, `\appdata\`, `\programdata\`, `\users\public\`, `\windows\temp\`,
	`%temp%`, `%appdata%`, `\downloads\`,
}

// wellKnownShellGUIDs maps Windows shell namespace GUID strings (upper-case,
// dashed, no braces) to human-readable folder names. Used by the ShellBags
// parser to decode root-folder shell items.
//
// Sources: Microsoft documentation, Windows SDK shell32.dll, and DFIR community
// research (Velociraptor, EZ Tools, Forensic Artifacts repositories).
var wellKnownShellGUIDs = map[string]string{
	// ---- Classic / Windows XP–Vista known folders ----
	"20D04FE0-3AEA-1069-A2D8-08002B30309D": "My Computer",
	"450D8FBA-AD25-11D0-98A8-0800361B1103": "My Documents",
	"208D2C60-3AEA-1069-A2D7-08002B30309D": "My Network Places",
	"871C2480-42A0-1069-A2EB-08002B30309D": "Internet Explorer",
	"F02C1A0D-BE21-4350-88B0-7367FC96EF3C": "Network",
	"645FF040-5081-101B-9F08-00AA002F954E": "Recycle Bin",
	"21EC2020-3AEA-1069-A2DD-08002B30309D": "Control Panel",
	"031E4825-7B94-4DC3-B131-E506E649151C": "Libraries",

	// ---- Windows Vista+ user shell folders (KNOWNFOLDERID) ----
	"374DE290-123F-4565-9164-39C4925E467B": "Downloads",
	"B4BFCC3A-DB2C-424C-B029-7FE99A87C641": "Desktop",
	"FDD39AD0-238F-46AF-ADB4-6C85480369C7": "Documents",
	"33E28130-4E1E-4676-835A-98395C3BC3BB": "Pictures",
	"4BD8D571-6D19-48D3-BE97-422220080E43": "Music",
	"18989B1D-99B5-455B-841C-AB7C74E4DDFC": "Videos",
	"1777F761-68AD-4D8A-87BD-30B759FA33DD": "Favorites",
	"BFB9D5E0-C6A9-404C-B2B2-AE6DB6AF4968": "Links",
	"4C5C32FF-BB9D-43B0-B5B4-2D72E54EAAA4": "Saved Games",
	"56784854-C6CB-462B-8169-88E350ACB882": "Contacts",
	"7D1D3A04-DEBB-4115-95CF-2F29DA2920DA": "Searches",
	"A3916023-D3B7-4825-B5B5-3DF80FD5A0B0": "OneDrive",
	"A52BBA46-E9E1-435F-B3D9-28DAA648C0F6": "OneDrive",

	// ---- Control Panel / System virtual folders ----
	"26EE0668-A00A-44D7-9371-BEB064C98683": "Control Panel (All Items)",
	"ED7BA470-8E54-465E-825C-99712043E01C": "Control Panel (All Tasks)",
	"D20EA4E1-3957-11D2-A40B-0C5020524153": "Administrative Tools",
	"7007ACC7-3202-11D1-AAD2-00805FC1270E": "Network Connections",
	"6DFD7C5C-2451-11D3-A299-00C04F8EF6AF": "Local Disk (Folder Options)",
	"00C6D95F-329C-409A-81D7-C46C66EA7F33": "Default Location",
	"9C60DE1E-E5FC-40F4-A487-460851A8D915": "AutoPlay",

	// ---- Windows 10 / 11 modern shell folders ----
	"088E3905-0323-4B02-9826-5D99428E115F": "Downloads (IE/Legacy)",
	"2B0F765D-C0E9-4171-908E-08A611B84FF6": "Cookies (IE/Legacy)",
	"F3CE0F7C-4901-4ACC-8648-D5D44B04EF8F": "Users Files Folder",
	"59031A47-3F72-44A7-89C5-5595FE6B30EE": "Public Desktop",
	"ED4824AF-DCE4-45A8-81E2-FC7965083634": "Public Documents",
	"3D644C9B-1FB8-4F30-9B45-F670235F79C0": "Public Downloads",
	"4DA689C0-4D6D-4A92-A086-5EA2DA9C67A0": "Common Places FS Folder",
}
