# Contributing to SAFE

Thank you for your interest in improving SAFE! As a defensive tool, we prioritize reliability, forensic soundness, and performance.

## Submitting Pull Requests

1. **Fork the repository** and create your branch from `main`.
2. **If you've added code that should be tested, add tests.** Because SAFE interacts heavily with Windows internals (VSS, raw disk access), we test primarily in a live VM environment rather than using mock unit tests. 
3. **Ensure the test suite passes.** Run `go build ./...` and `go vet ./...` locally.
4. **Follow the formatting guidelines.** Ensure your code is formatted with `gofmt`.

## Developing New Features

### Adding a New Detection Rule
You do not need to write Go code to add new behavior detections!
1. Add your new rule to `examples/rules/` in YAML format.
2. Refer to `docs/DETECTION_RULES.md` for the syntax, logic, and field mappings.

### Adding a New Parser
If you want to parse a new Windows artifact:
1. Implement the `Parser` interface defined in `internal/analyzer/`.
2. Ensure you use native Go libraries whenever possible. **SAFE's primary architectural rule is that we do not wrap external executables** (e.g., do not call out to `cmd.exe` or `python`). 
3. Prioritize performance: SAFE is designed to be fast and memory-efficient. Avoid loading massive artifacts entirely into memory; stream them instead.

## Code of Conduct
Please be professional and respectful in all interactions on issues and pull requests.
