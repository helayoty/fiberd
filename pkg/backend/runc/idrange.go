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
// SUB_UID_MAX, 600100000, and LXC and kubelet pod ranges sit lower still).
// It holds the most slots that end below the kernel's overflow id
// 4294967294, so two grants rarely hash to one slot.
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

// IDRange is one range key's map.
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

// Range is the map of a range key, the grant's session domain or, for a
// grant without a tenant, its uid. A session moves between homes that
// each hold their own grant for it, and the domain is what those grants
// share. The range depends on the key and the pool alone, so every home
// configured with the same pool gives the session the same host ids and
// its checkpoint, which keeps the map it was dumped with, restores on
// any of them.
func (p IDPool) Range(key string) IDRange {
	return IDRange{Start: p.Start + p.slot(key)*SlotIDs, Count: SlotIDs}
}

// slot hashes the range key into the pool.
func (p IDPool) slot(key string) uint32 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(key))
	return uint32(h.Sum64() % uint64(p.Slots))
}

// ErrRangeCollision means a grant of another range key admitted on this
// home holds the slot the key hashes to. The grant can run on a home
// that does not hold the other one.
var ErrRangeCollision = errors.New("runc: user namespace id range is held by another grant on this home")

// claims records which range key holds each slot, the grants of that key
// that map it on this home, and which of each grant's users do. The
// users are the warm zygote and every fiber criu restored here, since a
// restored tree is a pid namespace of its own and outlives the zygote. A
// fiber the zygote forked dies with its init, so the zygote's hold
// covers it.
type claims struct {
	mu   sync.Mutex
	pool IDPool
	held map[uint32]*claim // slot -> who holds it
}

// claim is one held slot. Every grant in it has the key the slot was
// claimed for, and the slot is free once the last of them lets go.
type claim struct {
	key    string
	grants map[string]*holder // grant uid -> its users of the slot
}

type holder struct {
	warm   bool // the zygote is up, or on its way up
	fibers int  // trees restored here and still running
}

// busy reports whether someone still uses the range.
func (h *holder) busy() bool { return h.warm || h.fibers > 0 }

func newClaims(p IDPool) *claims { return &claims{pool: p, held: map[uint32]*claim{}} }

// check is acquire without taking the slot. It fails the same way.
func (c *claims) check(key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.find(key)
	return err
}

// acquire takes the key's slot for one user of the grant. The warm
// zygote (warm) may be acquired again while held and counts once. Each
// restored fiber counts. A grant may hold its slot as both, and grants
// of one key share the slot.
func (c *claims) acquire(key, grantUID string, warm bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	cl, err := c.find(key)
	if err != nil {
		return err
	}
	if cl == nil {
		cl = &claim{key: key, grants: map[string]*holder{}}
		c.held[c.pool.slot(key)] = cl
	}
	h, ok := cl.grants[grantUID]
	if !ok {
		h = &holder{}
		cl.grants[grantUID] = h
	}
	if warm {
		h.warm = true
	} else {
		h.fibers++
	}
	return nil
}

// find is the key's claim, nil when the slot is free, or the collision
// when another key holds it.
func (c *claims) find(key string) (*claim, error) {
	slot := c.pool.slot(key)
	cl, ok := c.held[slot]
	if !ok {
		return nil, nil
	}
	if cl.key != key {
		return nil, fmt.Errorf("%w: range keys %q and %q both hash to slot %d of %d (host ids from %d); a larger -userns-pool makes collisions rarer",
			ErrRangeCollision, key, cl.key, slot, c.pool.Slots, c.pool.Range(key).Start)
	}
	return cl, nil
}

// release gives one user's hold of the grant back and reports whether
// the grant no longer uses the slot, so the caller can remove what the
// grant left on this home. The slot is freed with its last grant. A
// release by a grant that does not hold the slot under key, or of a user
// it does not have, changes nothing.
func (c *claims) release(key, grantUID string, warm bool) (free bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	slot := c.pool.slot(key)
	cl, ok := c.held[slot]
	if !ok || cl.key != key {
		return false
	}
	h, ok := cl.grants[grantUID]
	if !ok {
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
	delete(cl.grants, grantUID)
	if len(cl.grants) == 0 {
		delete(c.held, slot)
	}
	return true
}
