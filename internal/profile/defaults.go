package profile

// RegisterDefaults adds all built-in profiles to a registry.
// Call this once at startup to populate the registry with everything
// Acquira ships with by default.
func RegisterDefaults(r *Registry) error {
	defaults := []*Profile{
		RapidTriage(),
		EndpointDeep(),
		// More profiles get added here as they're written:
		// VolatileCapture(),
		// ServerInfra(),
	}
	for _, p := range defaults {
		if err := r.Register(p); err != nil {
			return err
		}
	}
	return nil
}
