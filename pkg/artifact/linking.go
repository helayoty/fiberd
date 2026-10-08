package artifact

import (
	"debug/elf"
)

// How the zygote executable is linked. A home whose backend runs the
// template inside a root filesystem of its own (gVisor, runc) cannot load
// a dynamically linked executable unless that filesystem holds the libc
// it was built against, which the home cannot tell. A static executable
// needs nothing from it. Build records the fact so the home can refuse
// at warm, with a clear error, instead of failing inside the sandbox.
const (
	// LinkStatic is an ELF executable with no program interpreter.
	LinkStatic = "static"
	// LinkDynamic is anything else: an ELF with an interpreter, or a
	// script, which needs its interpreter from the root filesystem.
	LinkDynamic = "dynamic"
)

// Linking reports how the executable at path is linked. Anything that is
// not a static ELF, including a file that cannot be read, is dynamic:
// the conservative answer, since a home refuses what it cannot vouch for.
func Linking(path string) string {
	f, err := elf.Open(path)
	if err != nil {
		return LinkDynamic
	}
	defer func() { _ = f.Close() }()
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			return LinkDynamic
		}
	}
	return LinkStatic
}
