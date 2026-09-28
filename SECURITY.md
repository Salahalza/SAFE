# Security Policy

SAFE is a defensive forensic tool. The integrity of the collected evidence, the resilience of the parsers, and the chain of custody are paramount. 

## Supported Versions
Only the latest release (`main` branch and the most recent Git tag) receives security updates.

## Reporting a Vulnerability

If you discover a vulnerability in SAFE, please do **NOT** open a public issue. Publicly disclosing a vulnerability may allow attackers to exploit forensic examiners before a patch is released.

Instead, please send an email directly to the repository owner or use the GitHub Security Advisory feature to report the issue privately.

### Scope of Vulnerabilities
Because SAFE is run by Incident Response analysts (often on already-compromised machines), we treat the following as critical security vulnerabilities:
- **Parser crashes/exploits:** If a maliciously crafted artifact (e.g., a poisoned EVTX file or MFT record) can cause the `safe-analyze` parser to crash or execute code on the analyst's machine.
- **Evidence destruction:** Bugs that cause `safe-collect` to accidentally corrupt target evidence.
- **AV Evasion Failure:** Bugs that result in the `web_payloads.zip` container failing to encrypt, exposing the analyst to their own local AV quarantines.

Please provide a detailed summary of the vulnerability, including steps to reproduce the issue and (if applicable) a sample of the poisoned artifact that triggers it. We will acknowledge your report within 48 hours.
