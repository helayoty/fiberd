package main

import (
	"fmt"
	"io"
	"math"
	"os"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// The steps run shows, one per fiber call.
const (
	eventClone  = "clone"
	eventAsk    = "ask"
	eventPark   = "park"
	eventResume = "resume"
)

// step is one call run made for a fiber.
type step struct {
	fiber, event, session string
	// took is how long fiberd took, 0 for an ask, which only reads.
	took time.Duration
	// says is what the fiber sent on the connection, nil for a park.
	says []byte
}

// refusal is a clone fiberd refused past the grant's fibers.max.
type refusal struct {
	clone, max int
	err        error
}

// summary is what run did, once the fibers are released.
type summary struct {
	fibers, refused, max, parked int
	// took is each clone's time, in clone order. The first also warmed
	// the template.
	took []time.Duration
}

// view is how run shows what happened.
type view interface {
	start(template string, n int)
	step(s step)
	refused(r refusal)
	end(s summary)
}

// newView is the view -o names. auto is a table when stdout is a
// terminal and raw otherwise, so a pipe gets only the fibers' bytes.
func newView(mode string, stdout, stderr io.Writer, park, timed bool) (view, error) {
	switch mode {
	case "auto":
		if terminal(stdout) {
			return &tableView{w: stdout, park: park, timed: timed}, nil
		}
		return &rawView{out: stdout, notes: stderr, timed: timed}, nil
	case "table":
		return &tableView{w: stdout, park: park, timed: timed}, nil
	case "raw":
		return &rawView{out: stdout, notes: stderr, timed: timed}, nil
	}
	return nil, fmt.Errorf("run: -o %q unknown, want auto, table or raw", mode)
}

// terminal reports whether w is a character device other than the null
// device, which is as near a terminal as the standard library tells.
func terminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	if err != nil || st.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	null, err := os.Stat(os.DevNull)
	return err != nil || !os.SameFile(st, null)
}

// tableView shows every step as a row, with what fiberd did and what the
// fiber said side by side.
type tableView struct {
	w io.Writer
	// park adds the SESSION column. timed adds the clones' p50 and p99.
	park, timed bool
}

func (t *tableView) start(template string, n int) {
	_, _ = fmt.Fprintf(t.w, "fiberd is up. Cloning %s from %s.\n\n", count(n, "fiber"), template)
	t.row("FIBER", "EVENT", "SESSION", "TIME", "SAYS")
}

func (t *tableView) step(s step) {
	took := ""
	if s.took > 0 {
		took = ms(s.took)
	}
	t.row(s.fiber, s.event, s.session, took, says(s.says))
}

func (t *tableView) refused(r refusal) {
	t.row("-", "refused", "", "", fmt.Sprintf("clone %d, %v", r.clone, r.err))
}

func (t *tableView) end(s summary) {
	line := fmt.Sprintf("\n%s from one template, released.", count(s.fibers, "fiber"))
	if s.refused > 0 {
		line += fmt.Sprintf(" %s refused, the grant holds %d.", count(s.refused, "clone"), s.max)
	}
	if s.parked > 0 {
		line += fmt.Sprintf(" %s parked and resumed.", count(s.parked, "session"))
	}
	_, _ = fmt.Fprintln(t.w, line)
	if len(s.took) == 0 {
		return
	}
	_, _ = fmt.Fprintln(t.w, "The first clone's time includes warming the template.")
	switch rest := s.took[1:]; {
	case !t.timed || len(rest) == 0:
	case len(rest) == 1:
		_, _ = fmt.Fprintf(t.w, "The other clone took %s.\n", ms(rest[0]))
	default:
		_, _ = fmt.Fprintf(t.w, "The other %d clones took p50 %s, p99 %s.\n", len(rest), ms(percentile(rest, 0.50)), ms(percentile(rest, 0.99)))
	}
}

// row writes one row, without the SESSION column unless a park is shown.
func (t *tableView) row(fiber, event, session, took, says string) {
	s := fmt.Sprintf("  %-12s %-8s", fiber, event)
	if t.park {
		s += fmt.Sprintf(" %-8s", session)
	}
	s += fmt.Sprintf(" %-9s %s", took, says)
	_, _ = fmt.Fprintln(t.w, strings.TrimRight(s, " "))
}

// says is a fiber's answer on one line. Its lines are joined with " / ",
// a tab is a space, and any other character that does not print, such
// as a carriage return or an escape that would drive the terminal, is
// shown as U+FFFD. An answer that is not text is shown by its size.
func says(b []byte) string {
	if !utf8.Valid(b) {
		return fmt.Sprintf("(%d bytes)", len(b))
	}
	line := strings.Join(strings.Split(strings.TrimRight(string(b), "\n"), "\n"), " / ")
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t':
			return ' '
		case !unicode.IsPrint(r):
			return utf8.RuneError
		}
		return r
	}, line)
}

// count is n things, as "1 fiber" or "3 fibers".
func count(n int, thing string) string {
	if n == 1 {
		return "1 " + thing
	}
	return fmt.Sprintf("%d %ss", n, thing)
}

// rawView passes the fibers' bytes to out as they are, and says what
// run did on notes, so a script reads only what the fibers sent.
type rawView struct {
	out, notes io.Writer
	timed      bool
	// parked is the park a resume reports with.
	parked step
}

func (r *rawView) start(string, int) {}

func (r *rawView) step(s step) {
	switch s.event {
	case eventPark:
		r.parked = s
		return
	case eventResume:
		if r.timed {
			_, _ = fmt.Fprintf(r.notes, "fiberd run: session %s parked as %s in %s, resumed as %s in %s\n",
				s.session, r.parked.fiber, ms(r.parked.took), s.fiber, ms(s.took))
		} else {
			_, _ = fmt.Fprintf(r.notes, "fiberd run: session %s parked as %s, resumed as %s\n", s.session, r.parked.fiber, s.fiber)
		}
	}
	_, _ = r.out.Write(s.says)
}

func (r *rawView) refused(f refusal) {
	_, _ = fmt.Fprintf(r.notes, "fiberd run: clone %d refused, the grant holds %d: %v\n", f.clone, f.max, f.err)
}

func (r *rawView) end(s summary) {
	if r.timed {
		report(r.notes, s.took)
	}
}

// report tells how long the clones took. The first one also started
// the template and waited for it to warm, so it is shown apart.
func report(notes io.Writer, took []time.Duration) {
	if len(took) == 0 {
		return
	}
	_, _ = fmt.Fprintf(notes, "fiberd run: first clone %s, with the template's warm-up\n", ms(took[0]))
	if rest := took[1:]; len(rest) > 0 {
		_, _ = fmt.Fprintf(notes, "fiberd run: %d more from the warm template, p50 %s, p99 %s\n",
			len(rest), ms(percentile(rest, 0.50)), ms(percentile(rest, 0.99)))
	}
}

// percentile is the q'th of ds by nearest rank, q in (0, 1]. ds is not
// changed.
func percentile(ds []time.Duration, q float64) time.Duration {
	s := slices.Clone(ds)
	slices.Sort(s)
	i := int(math.Ceil(q*float64(len(s)))) - 1
	return s[max(i, 0)]
}

// ms is d in milliseconds with one decimal.
func ms(d time.Duration) string {
	return fmt.Sprintf("%.1fms", float64(d.Microseconds())/1000)
}
