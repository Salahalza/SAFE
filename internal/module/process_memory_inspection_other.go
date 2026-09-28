//go:build !windows

package module

// runMemoryCollection is a stub for non-Windows build hosts (the macOS dev
// machine). process_memory_inspection relies on Windows-only syscalls
// (OpenProcess / VirtualQueryEx / ReadProcessMemory), so there is nothing to do
// here. It exists only so `go build ./...` stays green during development. The
// module is never run in production on a non-Windows host — SAFE is Windows-only.
func runMemoryCollection(ctx *Context, result *Result) {
	result.Errors = append(result.Errors,
		"process_memory_inspection is only supported on Windows")
}
