package runc

import (
	"bufio"
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"strconv"
	"strings"
	"sync"
)

// SlotIDs is how many host ids one grant's user namespace maps. The
// container's root is the first of them and the rest serve the uids and
// gids a rootfs may hold.
const SlotIDs = 65536

// DefaultPool is the -userns-pool default. It starts at 2^30, above every
// id a host hands out by convention (useradd's /etc/subuid ranges end at
// SUB_UID_MAX, 600100000, and LXC and kubelet pod ranges sit lower still),
// stays below 2^31 so no tool ever reads an id as negative, and reaches
// the top of the 32-bit id space, so two grants rarely hash to one slot.
const DefaultPool = "1073741824:49151"

// DefaultSubIDFiles are the files CheckSubIDs reads when none are given.
var DefaultSubIDFiles = []string{"/etc/subuid", "/etc/subgid"}

// IDPool is the host id space grants' user namespaces are carved from.
// Slot i maps container ids [0, SlotIDs) to host ids
// [Start+i*SlotIDs, Start+(i+1)*SlotIDs).
type IDPool struct {
	Start uint32
	Slots uint32
}

// IDRange is one grant's map.
type IDRange struct {
	Start uint32 // the host id of the grant's root
	Count uint32 // SlotIDs
}

// ParsePool reads "START:SLOTS". The pool must fit the 32-bit id space
// below the overflow ids (nobody is 65534 and the kernel's overflow id
// 4294967294).
func ParsePool(s string) (IDPool, error) {
	a, b, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok {
		return IDPool{}, fmt.Errorf("userns pool %q: want START:SLOTS", s)
	}
	start, err := strconv.ParseUint(a, 10, 32)
	if err != nil {
		return IDPool{}, fmt.Errorf("userns pool %q: start: %w", s, err)
	}
	slots, err := strconv.ParseUint(b, 10, 32)
	if err != nil {
		return IDPool{}, fmt.Errorf("userns pool %q: slots: %w", s, err)
	}
	p := IDPool{Start: uint32(start), Slots: uint32(slots)}
	if err := p.Validate(); err != nil {
		return IDPool{}, fmt.Errorf("userns pool %q: %w", s, err)
	}
	return p, nil
}

// Validate checks that every slot is a usable host id range.
func (p IDPool) Validate() error {
	if p.Slots == 0 {
		return errors.New("want at least one slot")
	}
	if p.Start < SlotIDs {
		return fmt.Errorf("start %d overlaps the host's own ids (want at least %d)", p.Start, SlotIDs)
	}
	if p.end() > 1<<32-2 {
		return fmt.Errorf("%d slots from %d reach id %d, past the 32-bit id space", p.Slots, p.Start, p.end()-1)
	}
	return nil
}

// end is the first id past the pool.
func (p IDPool) end() uint64 { return uint64(p.Start) + uint64(p.Slots)*SlotIDs }

// CheckSubIDs refuses a pool that overlaps a range the host has handed
// out in /etc/subuid or /etc/subgid (files, or DefaultSubIDFiles when
// none are given). Such a range is some user's to map into namespaces of
// their own, and sharing host ids with it would make that user's
// containers and fiberd's grants one identity. A file that does not
// exist has nothing to overlap. A line that does not parse is an error
// too, since a range it hides cannot be checked.
func (p IDPool) CheckSubIDs(files ...string) error {
	if len(files) == 0 {
		files = DefaultSubIDFiles
	}
	for _, path := range files {
		f, err := os.Open(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("userns pool: %w", err)
		}
		err = p.checkSubIDFile(path, f)
		_ = f.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func (p IDPool) checkSubIDFile(path string, f *os.File) error {
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) != 3 {
			return fmt.Errorf("userns pool: %s line %d: want name:start:count, got %q", path, n, line)
		}
		start, err1 := strconv.ParseUint(fields[1], 10, 32)
		count, err2 := strconv.ParseUint(fields[2], 10, 32)
		if err1 != nil || err2 != nil {
			return fmt.Errorf("userns pool: %s line %d: want name:start:count, got %q", path, n, line)
		}
		if start < p.end() && start+count > uint64(p.Start) {
			return fmt.Errorf("userns pool %d:%d (host ids %d-%d) overlaps %s entry %q (ids %d-%d); move the pool or that entry",
				p.Start, p.Slots, p.Start, p.end()-1, path, line, start, start+count-1)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("userns pool: read %s: %w", path, err)
	}
	return nil
}

// Range is the grant's map. It depends on the grant uid and the pool
// alone, so every home configured with the same pool gives the grant the
// same host ids and a checkpoint restores on any of them.
func (p IDPool) Range(grantUID string) IDRange {
	return IDRange{Start: p.Start + p.slot(grantUID)*SlotIDs, Count: SlotIDs}
}

// slot hashes the grant uid into the pool.
func (p IDPool) slot(grantUID string) uint32 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(grantUID))
	return uint32(h.Sum64() % uint64(p.Slots))
}

// ErrRangeCollision: another grant admitted on this home holds the
// slot the grant hashes to. The grant can run on a home that does not
// hold the other one.
var ErrRangeCollision = errors.New("runc: user namespace id range is held by another grant on this home")

// claims records which grant holds each slot and who of the grant uses
// it on this home. A slot is held for as long as anything of the grant
// maps the range here: its warm zygote, and every fiber criu restored on
// this home, since a restored tree is a pid namespace of its own and
// outlives the zygote. Nothing else of the grant may map the range, so a
// fiber the zygote forked is covered by the zygote's hold (it dies with
// its init).
type claims struct {
	mu   sync.Mutex
	pool IDPool
	held map[uint32]*holder // slot -> who holds it
}

type holder struct {
	grant  string
	warm   bool // the zygote is up, or on its way up
	fibers int  // trees restored here and still running
}

// busy: someone still uses the range.
func (h *holder) busy() bool { return h.warm || h.fibers > 0 }

func newClaims(p IDPool) *claims { return &claims{pool: p, held: map[uint32]*holder{}} }

// check is acquire without taking the slot. It fails the same way.
func (c *claims) check(grantUID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.find(grantUID)
	return err
}

// acquire takes the grant's slot for one user: its warm zygote (warm,
// which may be acquired again while held and counts once) or one
// restored fiber (counted). A grant may hold its slot as both.
func (c *claims) acquire(grantUID string, warm bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	h, err := c.find(grantUID)
	if err != nil {
		return err
	}
	if h == nil {
		h = &holder{grant: grantUID}
		c.held[c.pool.slot(grantUID)] = h
	}
	if warm {
		h.warm = true
	} else {
		h.fibers++
	}
	return nil
}

// find is the grant's holder, nil when the slot is free, or the
// collision when another grant holds it.
func (c *claims) find(grantUID string) (*holder, error) {
	slot := c.pool.slot(grantUID)
	h, ok := c.held[slot]
	if !ok {
		return nil, nil
	}
	if h.grant != grantUID {
		return nil, fmt.Errorf("%w: grant %s and grant %s both hash to slot %d of %d (host ids from %d); a larger -userns-pool makes collisions rarer",
			ErrRangeCollision, grantUID, h.grant, slot, c.pool.Slots, c.pool.Range(grantUID).Start)
	}
	return h, nil
}

// release gives one user's hold back and reports whether the grant's
// slot is now free, so the caller can remove what the grant left on this
// home. A release by a grant that does not hold the slot, or of a user
// it does not have, changes nothing.
func (c *claims) release(grantUID string, warm bool) (free bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	slot := c.pool.slot(grantUID)
	h, ok := c.held[slot]
	if !ok || h.grant != grantUID {
		return false
	}
	switch {
	case warm:
		h.warm = false
	case h.fibers > 0:
		h.fibers--
	}
	if h.busy() {
		return false
	}
	delete(c.held, slot)
	return true
}
