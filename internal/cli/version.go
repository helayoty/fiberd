package cli

import "runtime/debug"

// Version is what a binary's -version prints. stamped is the binary's
// main.version, which a release sets at link time with
// -ldflags "-X main.version=v0.1.0". An unstamped build reports the
// module version Go recorded, as go install does, and otherwise "dev".
func Version(stamped string) string {
	info, _ := debug.ReadBuildInfo()
	return version(stamped, info)
}

func version(stamped string, info *debug.BuildInfo) string {
	switch {
	case stamped != "":
		return stamped
	case info != nil && info.Main.Version != "" && info.Main.Version != "(devel)":
		return info.Main.Version
	}
	return "dev"
}
