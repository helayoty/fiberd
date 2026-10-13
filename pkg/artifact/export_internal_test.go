package artifact

// SetHostInfo replaces what Build and Host detect about this host and
// returns what puts the real detection back. A platform's own facts
// still win, as they do over the real detection.
func SetHostInfo(f func() (arch, kernel, libc string)) (restore func()) {
	old := detect
	detect = func(p Platform) Platform {
		arch, kernel, libc := f()
		if p.Arch == "" {
			p.Arch = arch
		}
		if p.Kernel == "" {
			p.Kernel = kernel
		}
		if p.Libc == "" {
			p.Libc = libc
		}
		return p
	}
	return func() { detect = old }
}
