//go:build linux

package cgroup

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// GPUGuard is one cgroup device program (BPF_PROG_TYPE_CGROUP_DEVICE)
// attached to a cgroup directory. It refuses every open and mknod of an
// NVIDIA character device, by major, for every process in that cgroup
// and below, whatever mount or device node the process sees. Everything
// else is allowed, so it adds no rule beyond the GPU.
//
// The kernel keeps an attached program alive by the cgroup's own
// reference, so closing the program descriptor does not detach it.
// Detaching a program attached with BPF_F_ALLOW_MULTI needs that
// descriptor back, which is why the guard holds it until Close.
type GPUGuard struct {
	dir    string
	progFD int
	id     uint32
}

// AttachGPUGuard loads the device program and attaches it to the cgroup
// directory at dir with BPF_CGROUP_DEVICE and BPF_F_ALLOW_MULTI, so the
// programs an ancestor holds (runc's or systemd's device allow list)
// keep running beside it and a descendant can still attach its own.
//
// Every error names its step and errno. The attach is refused with
// EPERM when the nearest ancestor with a device program attached it
// without BPF_F_ALLOW_MULTI, or with exactly one program and no
// BPF_F_ALLOW_OVERRIDE, and when dir itself already holds a program
// attached under other flags. That is the attach failing by name the
// warm reports.
//
// Capabilities, on the 6.17 kernels fiberd targets. The load needs
// bpf_capable, CAP_BPF or CAP_SYS_ADMIN in the initial user namespace,
// and so does every bpf command while kernel.unprivileged_bpf_disabled
// is set, which distributions default to. The attach itself asks for
// nothing beyond a cgroup directory the caller can open. Covered uses
// BPF_PROG_QUERY, which needs CAP_NET_ADMIN or CAP_SYS_ADMIN. caps.Proc
// keeps CAP_SYS_ADMIN and CAP_NET_ADMIN, so nothing new is needed. A
// fiberd in a child user namespace cannot load the program at all.
func AttachGPUGuard(dir string) (*GPUGuard, error) {
	majors, err := nvidiaMajors()
	if err != nil {
		return nil, err
	}
	progFD, err := loadDeviceProgram(deviceProgram(majors))
	if err != nil {
		return nil, err
	}
	id, err := progID(progFD)
	if err != nil {
		_ = unix.Close(progFD)
		return nil, err
	}
	target, err := os.OpenFile(dir, os.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		_ = unix.Close(progFD)
		return nil, fmt.Errorf("cgroup: gpu guard: open %s: %w", dir, err)
	}
	defer func() { _ = target.Close() }()
	attr := progAttachAttr{
		targetFD:    uint32(target.Fd()),
		attachBPFFD: uint32(progFD),
		attachType:  unix.BPF_CGROUP_DEVICE,
		attachFlags: unix.BPF_F_ALLOW_MULTI,
	}
	if errno := bpf(unix.BPF_PROG_ATTACH, unsafe.Pointer(&attr), unsafe.Sizeof(attr)); errno != 0 {
		_ = unix.Close(progFD)
		if errno == unix.EPERM {
			return nil, fmt.Errorf("cgroup: gpu guard: attach to %s: %w (an ancestor's device program was attached without BPF_F_ALLOW_MULTI, or %s already holds one under other flags)", dir, errno, dir)
		}
		return nil, fmt.Errorf("cgroup: gpu guard: attach to %s: %w", dir, errno)
	}
	return &GPUGuard{dir: dir, progFD: progFD, id: id}, nil
}

// Dir is the cgroup directory the guard is attached to.
func (g *GPUGuard) Dir() string { return g.dir }

// Close detaches the program from its cgroup and closes its descriptor.
// Fibers already in the cgroup lose the guard at once. Safe to call
// more than once.
func (g *GPUGuard) Close() error {
	if g.progFD < 0 {
		return nil
	}
	fd := g.progFD
	g.progFD = -1
	defer func() { _ = unix.Close(fd) }()
	target, err := os.OpenFile(g.dir, os.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		// The cgroup is gone, and its programs with it.
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("cgroup: gpu guard: open %s: %w", g.dir, err)
	}
	defer func() { _ = target.Close() }()
	attr := progAttachAttr{
		targetFD:    uint32(target.Fd()),
		attachBPFFD: uint32(fd),
		attachType:  unix.BPF_CGROUP_DEVICE,
	}
	if errno := bpf(unix.BPF_PROG_DETACH, unsafe.Pointer(&attr), unsafe.Sizeof(attr)); errno != 0 && errno != unix.ENOENT {
		return fmt.Errorf("cgroup: gpu guard: detach from %s: %w", g.dir, errno)
	}
	return nil
}

// Release closes the program's descriptor and leaves the program
// attached. The cgroup keeps it until the cgroup itself is removed, so
// every process still in it stays guarded. Safe to call more than once.
func (g *GPUGuard) Release() error {
	if g.progFD < 0 {
		return nil
	}
	fd := g.progFD
	g.progFD = -1
	return unix.Close(fd)
}

// Covered reports whether this guard's program runs for the processes
// of leaf, a cgroup directory at or below the guard's own. It asks the
// kernel for the device programs in effect there (BPF_PROG_QUERY with
// BPF_F_QUERY_EFFECTIVE) and looks for the guard's program id. A
// descendant that attached its own program without BPF_F_ALLOW_MULTI
// shadows every ancestor's, and the leaf is then not covered.
func (g *GPUGuard) Covered(leaf string) (bool, error) {
	if g.progFD < 0 {
		return false, errors.New("cgroup: gpu guard: closed")
	}
	target, err := os.OpenFile(leaf, os.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return false, fmt.Errorf("cgroup: gpu guard: open %s: %w", leaf, err)
	}
	defer func() { _ = target.Close() }()
	ids := make([]uint32, 16)
	for {
		attr := progQueryAttr{
			targetFD:   uint32(target.Fd()),
			attachType: unix.BPF_CGROUP_DEVICE,
			queryFlags: unix.BPF_F_QUERY_EFFECTIVE,
			progIDs:    pointerTo(unsafe.Pointer(&ids[0])),
			progCnt:    uint32(len(ids)),
		}
		errno := bpf(unix.BPF_PROG_QUERY, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
		runtime.KeepAlive(ids)
		switch {
		case errno == unix.ENOSPC:
			// More programs than room. The kernel still says how many.
			ids = make([]uint32, int(attr.progCnt)+16)
			continue
		case errno != 0:
			return false, fmt.Errorf("cgroup: gpu guard: query %s: %w", leaf, errno)
		}
		for _, id := range ids[:min(int(attr.progCnt), len(ids))] {
			if id == g.id {
				return true, nil
			}
		}
		return false, nil
	}
}

// nvidiaMajor is the fixed character major of nvidia0..N, nvidiactl and
// nvidia-modeset. nvidia-uvm, nvidia-caps and the driver's other nodes
// take dynamic majors, read from /proc/devices.
const nvidiaMajor = 195

// nvidiaMajors is every character major the NVIDIA driver holds on this
// host, 195 first. A host without the driver, or whose /proc/devices
// cannot be read, gives 195 alone, so the program is the same on a host
// that loads the driver later and on the fake-driver runs.
func nvidiaMajors() ([]uint32, error) {
	text, err := os.ReadFile("/proc/devices")
	if err != nil {
		return []uint32{nvidiaMajor}, nil
	}
	return nvidiaMajorsOf(string(text)), nil
}

// NVIDIAPresent reports whether the NVIDIA driver holds a character
// major on this host, as /proc/devices lists it. A host whose
// /proc/devices cannot be read is taken to have none, like one that
// never loaded the driver.
func NVIDIAPresent() bool {
	text, err := os.ReadFile("/proc/devices")
	if err != nil {
		return false
	}
	return nvidiaNamed(string(text))
}

// nvidiaNamed reports whether text, a /proc/devices listing, names a
// character device of the NVIDIA driver.
func nvidiaNamed(text string) bool {
	chars := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		switch line {
		case "Character devices:":
			chars = true
			continue
		case "Block devices:":
			chars = false
			continue
		}
		if fields := strings.Fields(line); chars && len(fields) == 2 && strings.HasPrefix(fields[1], "nvidia") {
			return true
		}
	}
	return false
}

// nvidiaMajorsOf parses the "Character devices:" section of a
// /proc/devices text for every major whose name starts with "nvidia",
// in the order found, with 195 first and no repeats. The block section
// is skipped, since the program checks character devices alone.
func nvidiaMajorsOf(text string) []uint32 {
	majors := []uint32{nvidiaMajor}
	chars := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "Character devices:":
			chars = true
			continue
		case line == "Block devices:":
			chars = false
			continue
		case !chars:
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || !strings.HasPrefix(fields[1], "nvidia") {
			continue
		}
		n, err := strconv.ParseUint(fields[0], 10, 32)
		if err != nil || n == nvidiaMajor {
			continue
		}
		dup := false
		for _, m := range majors {
			if m == uint32(n) {
				dup = true
			}
		}
		if !dup {
			majors = append(majors, uint32(n))
		}
	}
	return majors
}

// insn is one eBPF instruction (struct bpf_insn): the opcode, the
// destination register in the low nibble and the source in the high
// one, a signed jump offset in instructions, and an immediate.
type insn struct {
	code uint8
	regs uint8
	off  int16
	imm  int32
}

// The eBPF registers the program uses. r1 holds the context on entry
// and r0 the verdict on exit.
const (
	r0 = 0
	r1 = 1
	r2 = 2
)

// The context of a device program, struct bpf_cgroup_dev_ctx: three
// u32s, access_type (the device type in the low 16 bits, the access
// asked in the high 16), major and minor. The verifier takes 4-byte
// loads from it alone. BPF_DEVCG_DEV_CHAR is a character device
// (linux/bpf.h).
const (
	ctxAccessType = 0
	ctxMajor      = 4
	devcgDevChar  = 2
)

// deviceProgram is the guard for the given character majors. It allows
// every access to a block device and to a character device of another
// major, and refuses the rest. One jeq per major, no map and no
// helper call, so the verifier takes it as a constant-time program.
//
//	r2 = *(u32 *)(r1 + 0)       ; access_type
//	r2 &= 0xffff                ; the device type
//	if r2 != DEV_CHAR goto allow
//	r2 = *(u32 *)(r1 + 4)       ; major
//	if r2 == 195 goto deny
//	if r2 == <dynamic> goto deny ; one per major from /proc/devices
//	allow: r0 = 1; exit
//	deny:  r0 = 0; exit
func deviceProgram(majors []uint32) []insn {
	n := int16(len(majors))
	p := []insn{
		{code: unix.BPF_LDX | unix.BPF_MEM | unix.BPF_W, regs: r2 | r1<<4, off: ctxAccessType},
		{code: unix.BPF_ALU64 | unix.BPF_AND | unix.BPF_K, regs: r2, imm: 0xffff},
		{code: unix.BPF_JMP | unix.BPF_JNE | unix.BPF_K, regs: r2, off: n + 1, imm: devcgDevChar},
		{code: unix.BPF_LDX | unix.BPF_MEM | unix.BPF_W, regs: r2 | r1<<4, off: ctxMajor},
	}
	for i, m := range majors {
		// The deny label is n + 1 - i instructions past this one.
		p = append(p, insn{code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, regs: r2, off: n + 1 - int16(i), imm: int32(m)})
	}
	return append(p,
		insn{code: unix.BPF_ALU64 | unix.BPF_MOV | unix.BPF_K, regs: r0, imm: 1},
		insn{code: unix.BPF_JMP | unix.BPF_EXIT},
		insn{code: unix.BPF_ALU64 | unix.BPF_MOV | unix.BPF_K, regs: r0, imm: 0},
		insn{code: unix.BPF_JMP | unix.BPF_EXIT},
	)
}

// progName is what bpftool shows for the program, at most 15 bytes.
const progName = "fiberd_gpuguard"

// loadDeviceProgram loads p under the GPL license, which the kernel
// asks for nothing here but records, and returns its descriptor. On a
// refusal the verifier's log, when it wrote one, follows the errno.
func loadDeviceProgram(p []insn) (int, error) {
	license := []byte("GPL\x00")
	log := make([]byte, 4096)
	attr := progLoadAttr{
		progType: unix.BPF_PROG_TYPE_CGROUP_DEVICE,
		insnCnt:  uint32(len(p)),
		insns:    pointerTo(unsafe.Pointer(&p[0])),
		license:  pointerTo(unsafe.Pointer(&license[0])),
		logLevel: 1,
		logSize:  uint32(len(log)),
		logBuf:   pointerTo(unsafe.Pointer(&log[0])),
	}
	copy(attr.progName[:], progName)
	fd, errno := bpfFD(unix.BPF_PROG_LOAD, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	runtime.KeepAlive(p)
	runtime.KeepAlive(license)
	runtime.KeepAlive(log)
	if errno != 0 {
		if why := strings.TrimSpace(string(log[:cStringLen(log)])); why != "" {
			return -1, fmt.Errorf("cgroup: gpu guard: load: %w (verifier: %s)", errno, why)
		}
		return -1, fmt.Errorf("cgroup: gpu guard: load: %w", errno)
	}
	return fd, nil
}

// progID is the kernel's id for the loaded program at fd, what
// BPF_PROG_QUERY lists.
func progID(fd int) (uint32, error) {
	var info struct {
		typ uint32
		id  uint32
		tag [8]byte
	}
	attr := objGetInfoAttr{
		bpfFD:   uint32(fd),
		infoLen: uint32(unsafe.Sizeof(info)),
		info:    pointerTo(unsafe.Pointer(&info)),
	}
	errno := bpf(unix.BPF_OBJ_GET_INFO_BY_FD, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	runtime.KeepAlive(&info)
	if errno != 0 {
		return 0, fmt.Errorf("cgroup: gpu guard: program id: %w", errno)
	}
	return info.id, nil
}

// cStringLen is the length of b up to its first NUL.
func cStringLen(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return len(b)
}

// pointer is a user address inside a bpf_attr, an __aligned_u64 in the
// kernel's union. Holding it as an unsafe.Pointer keeps what it points
// to traced for as long as the attr is, and a stack never moves during
// the system call. It is 8 bytes on amd64 and arm64, the Linux targets
// fiberd builds, which the array below pins at compile time.
type pointer struct{ ptr unsafe.Pointer }

var _ [8]byte = [unsafe.Sizeof(pointer{})]byte{}

func pointerTo(p unsafe.Pointer) pointer { return pointer{ptr: p} }

// The members of union bpf_attr the guard uses, each laid out as
// linux/bpf.h has it, cut after the last field set. The kernel takes a
// shorter attr and reads the rest as zero.

// progLoadAttr is the BPF_PROG_LOAD member, through expected_attach_type.
type progLoadAttr struct {
	progType           uint32
	insnCnt            uint32
	insns              pointer
	license            pointer
	logLevel           uint32
	logSize            uint32
	logBuf             pointer
	kernVersion        uint32
	progFlags          uint32
	progName           [16]byte
	progIfindex        uint32
	expectedAttachType uint32
}

// progAttachAttr is the BPF_PROG_ATTACH and BPF_PROG_DETACH member,
// through replace_bpf_fd.
type progAttachAttr struct {
	targetFD     uint32
	attachBPFFD  uint32
	attachType   uint32
	attachFlags  uint32
	replaceBPFFD uint32
}

// progQueryAttr is the BPF_PROG_QUERY member, through prog_cnt and its
// padding. The kernel writes attach_flags and prog_cnt back.
type progQueryAttr struct {
	targetFD    uint32
	attachType  uint32
	queryFlags  uint32
	attachFlags uint32
	progIDs     pointer
	progCnt     uint32
	_           uint32
}

// objGetInfoAttr is the BPF_OBJ_GET_INFO_BY_FD member.
type objGetInfoAttr struct {
	bpfFD   uint32
	infoLen uint32
	info    pointer
}

// bpf runs one bpf(2) command and returns its errno, 0 on success.
func bpf(cmd int, attr unsafe.Pointer, size uintptr) unix.Errno {
	_, _, errno := unix.Syscall(unix.SYS_BPF, uintptr(cmd), uintptr(attr), size)
	return errno
}

// bpfFD is bpf for a command that returns a descriptor.
func bpfFD(cmd int, attr unsafe.Pointer, size uintptr) (int, unix.Errno) {
	r, _, errno := unix.Syscall(unix.SYS_BPF, uintptr(cmd), uintptr(attr), size)
	if errno != 0 {
		return -1, errno
	}
	return int(r), 0
}
