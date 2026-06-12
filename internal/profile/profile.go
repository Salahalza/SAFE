package profile

import (
	"fmt"
	"time"

	"safe/internal/module"
)

// Profile is a named, versioned collection plan.
// It defines which modules run, in what order, with what total time budget.
type Profile struct {
	// Name is the unique identifier (e.g. "rapid_triage").
	Name string

	// Description is human-readable, shown in UIs.
	Description string

	// Version of the profile definition. Bump when modules or order change.
	Version string

	// Modules in execution order.
	Modules []module.Module

	// TotalBudget is a hard ceiling for the entire profile.
	// The engine should abort the profile if elapsed time exceeds this,
	// regardless of which module is currently running.
	TotalBudget time.Duration
}

// Registry holds all known profiles, keyed by name.
type Registry struct {
	profiles map[string]*Profile
}

// NewRegistry creates an empty profile registry.
func NewRegistry() *Registry {
	return &Registry{
		profiles: make(map[string]*Profile),
	}
}

// Register adds a profile to the registry.
// Returns an error if a profile with the same name already exists.
func (r *Registry) Register(p *Profile) error {
	if _, exists := r.profiles[p.Name]; exists {
		return fmt.Errorf("profile %q already registered", p.Name)
	}
	r.profiles[p.Name] = p
	return nil
}

// Get returns the profile with the given name, or an error if not found.
func (r *Registry) Get(name string) (*Profile, error) {
	p, ok := r.profiles[name]
	if !ok {
		return nil, fmt.Errorf("profile %q not found", name)
	}
	return p, nil
}

// Names returns all registered profile names, sorted alphabetically.
func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.profiles))
	for name := range r.profiles {
		names = append(names, name)
	}
	// Sort so output is deterministic across runs.
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j-1] > names[j]; j-- {
			names[j-1], names[j] = names[j], names[j-1]
		}
	}
	return names
}
