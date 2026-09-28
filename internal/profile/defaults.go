package profile

// RegisterDefaults adds all built-in profiles to a registry.
// Call this once at startup to populate the registry with everything
// SAFE ships with by default.
func RegisterDefaults(r *Registry) error {
	defaults := []*Profile{
		RapidTriage(),
		EndpointDeep(),
		MemoryTriage(),
		ServerInfra(),
		DiskImage(),
	}
	for _, p := range defaults {
		if err := r.Register(p); err != nil {
			return err
		}
	}
	return nil
}
