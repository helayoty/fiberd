package artifact

// SetHostInfo replaces what Build and Host record about this host and
// returns what puts the real detection back.
func SetHostInfo(f func() (arch, kernel, libc string)) (restore func()) {
	old := hostInfo
	hostInfo = f
	return func() { hostInfo = old }
}
