//go:build linux

package host

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/sys/cgroup"
)

// pooled is a sandbox restored ahead of its fiber in <grant>/pool/p-<n>.
// The fiber keeps the leaf, since cgroup v2 cannot rename one.
type pooled struct {
	id  string // the backend's handle
	pid int
	cg  cgroup.Dir
	// spent is set once Bind was asked: a failure after that killed the
	// sandbox, a failure before gives it back to the pool.
	spent bool
}

// poolDir is the name of the grant cgroup's child the pool leaves live in.
const poolDir = "pool"

func (r *Runtime) pooler() backend.Pooler {
	pb, _ := r.be.(backend.Pooler)
	return pb
}

// Fill restores one sandbox ahead of its fiber. It answers
// core.ErrNoPool, ErrNotPrepared, core.ErrPressure when the grant has
// no room for another fiber, or core.ErrYielded when a clone's restore
// took its place.
func (r *Runtime) Fill(ctx context.Context, g core.Grant, deadline time.Duration) error {
	pb := r.pooler()
	if pb == nil {
		return fmt.Errorf("%w: the %s backend", core.ErrNoPool, r.cfg.Backend.Name())
	}
	r.mu.Lock()
	z := r.warms[g.UID]
	noPool := z != nil && z.noPool
	r.mu.Unlock()
	if z == nil {
		return fmt.Errorf("%w: %s", ErrNotPrepared, g.UID)
	}
	if noPool {
		return fmt.Errorf("%w: %s", core.ErrNoPool, g.UID)
	}
	if err := r.poolRoom(z); err != nil {
		return err
	}
	pcg := z.cg.Child(poolDir)
	if err := pcg.Ensure("memory", "pids"); err != nil {
		return err
	}
	r.mu.Lock()
	r.poolSeq++
	n := r.poolSeq
	r.mu.Unlock()
	leaf, err := r.leaf(pcg, g, fmt.Sprintf("p-%d", n))
	if err != nil {
		return err
	}
	lfd, err := leaf.Open()
	if err != nil {
		_ = leaf.Remove()
		return err
	}
	defer func() { _ = lfd.Close() }()
	p, err := pb.Pool(ctx, z.id, backend.PoolSpec{CgroupFD: int(lfd.Fd()), Deadline: deadline})
	if err != nil {
		if errors.Is(err, backend.ErrNoPool) {
			r.mu.Lock()
			z.noPool = true
			r.mu.Unlock()
			err = fmt.Errorf("%w: %w", core.ErrNoPool, err)
		} else if errors.Is(err, backend.ErrYielded) {
			err = fmt.Errorf("%w: %w", core.ErrYielded, err)
		}
		_ = leaf.Kill()
		removeDead(leaf)
		return err
	}
	r.mu.Lock()
	if r.warms[g.UID] != z {
		// The template went while the restore ran.
		r.mu.Unlock()
		r.discard([]*pooled{{id: p.ID, pid: p.PID, cg: leaf}})
		return fmt.Errorf("%w: %s", ErrNotPrepared, g.UID)
	}
	z.pool = append(z.pool, &pooled{id: p.ID, pid: p.PID, cg: leaf})
	r.mu.Unlock()
	log.Printf("host: pooled %s for grant %s pid=%d leaf=%s", p.ID, g.UID, p.PID, leaf.Name())
	return nil
}

// poolRoom refuses a fill the grant's ceiling has no room for, so a pool
// never provokes the reclaim the pressure ladder reads.
func (r *Runtime) poolRoom(z *warm) error {
	high := limitOf(z.cg, "memory.high")
	if high == 0 {
		return nil
	}
	cur, err := z.cg.MemoryCurrent()
	if err != nil {
		return nil
	}
	if cur+z.total > high {
		return fmt.Errorf("%w: grant %s holds %d of %d bytes, no room for a pooled sandbox of %d", core.ErrPressure, z.grantUID, cur, high, z.total)
	}
	return nil
}

// limitOf reads one limit of d itself, 0 for "max" or no file.
func limitOf(d cgroup.Dir, name string) uint64 {
	b, err := os.ReadFile(filepath.Join(d.Path, name))
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return n
}

// Drain discards up to n pooled sandboxes of the grant, oldest first,
// every one when n < 0, and returns how many went.
func (r *Runtime) Drain(grantUID string, n int) int {
	r.mu.Lock()
	var ps []*pooled
	if z := r.warms[grantUID]; z != nil {
		if n < 0 || n > len(z.pool) {
			n = len(z.pool)
		}
		ps, z.pool = z.pool[:n], z.pool[n:]
	}
	r.mu.Unlock()
	r.discard(ps)
	return len(ps)
}

// PooledExits names the grant each time a pooled sandbox dies before
// its hand-out, so the core backs its refill off.
func (r *Runtime) PooledExits() <-chan string { return r.poolExits }

// Pooled is how many sandboxes wait in the grant's pool.
func (r *Runtime) Pooled(grantUID string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if z := r.warms[grantUID]; z != nil {
		return len(z.pool)
	}
	return 0
}

// takePooled takes the oldest pooled sandbox of z, nil when none waits.
func (r *Runtime) takePooled(z *warm) *pooled {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(z.pool) == 0 {
		return nil
	}
	p := z.pool[0]
	z.pool = z.pool[1:]
	return p
}

// returnPooled puts back a sandbox a birth gave up before asking for it.
func (r *Runtime) returnPooled(z *warm, p *pooled) {
	r.mu.Lock()
	kept := r.warms[z.grantUID] == z
	if kept {
		z.pool = append([]*pooled{p}, z.pool...)
	}
	r.mu.Unlock()
	if !kept {
		r.discard([]*pooled{p}) // the template went meanwhile
	}
}

// drainAll takes every pooled sandbox of z, under r.mu.
func (z *warm) drainAll() []*pooled {
	ps := z.pool
	z.pool = nil
	return ps
}

// discard kills pooled sandboxes and removes their leaves. Their exits
// arrive later under ids the host no longer holds, and are ignored.
func (r *Runtime) discard(ps []*pooled) {
	pb := r.pooler()
	for _, p := range ps {
		if pb != nil {
			pb.Discard(p.id)
		}
		_ = p.cg.Kill()
	}
	for _, p := range ps {
		waitEmpty(p.cg, 5*time.Second)
		_ = removeSoon(p.cg)
	}
}

// pooledGone forgets a pooled sandbox that died and removes its leaf.
// An id the host no longer holds is ignored.
func (r *Runtime) pooledGone(id, status string) {
	r.mu.Lock()
	var p *pooled
	grant := ""
	for _, z := range r.warms {
		for i, q := range z.pool {
			if q.id == id {
				p, grant = q, z.grantUID
				z.pool = append(z.pool[:i], z.pool[i+1:]...)
				break
			}
		}
	}
	r.mu.Unlock()
	if p == nil {
		return
	}
	_ = removeSoon(p.cg)
	log.Printf("host: pooled %s of grant %s died before hand-out: %s", id, grant, status)
	select {
	case r.poolExits <- grant:
	default: // the core's next tick sees the count anyway
	}
}

// sweepPools kills and removes the pool leaves a previous life left,
// which nothing else would end.
func (r *Runtime) sweepPools() {
	grants, err := r.root.Children("")
	if err != nil {
		return
	}
	for _, g := range grants {
		pcg := g.Child(poolDir)
		leaves, err := pcg.Children("")
		if err != nil {
			continue // no pool
		}
		for _, l := range leaves {
			_ = l.Kill()
		}
		for _, l := range leaves {
			waitEmpty(l, 5*time.Second)
			_ = removeSoon(l)
		}
		_ = removeSoon(pcg)
		if len(leaves) > 0 {
			log.Printf("host: swept %d pooled sandboxes of grant %s", len(leaves), g.Name())
		}
	}
}

// waitEmpty waits up to timeout for a killed leaf's tasks to leave.
func waitEmpty(d cgroup.Dir, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for {
		pids, err := d.Procs()
		if err != nil || len(pids) == 0 || time.Now().After(deadline) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// removeDead removes a killed leaf in the background once it is empty.
func removeDead(d cgroup.Dir) {
	go func() {
		waitEmpty(d, 5*time.Second)
		_ = removeSoon(d)
	}()
}
