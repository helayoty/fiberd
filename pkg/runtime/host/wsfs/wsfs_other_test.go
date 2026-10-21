//go:build !linux

package wsfs

import (
	"errors"
	"testing"
)

func TestOpenUnsupported(t *testing.T) {
	cases := []struct {
		name string
		opts Options
	}{
		{name: "with a budget", opts: Options{Budget: NewCounter(Limits{Bytes: 1})}},
		{name: "without", opts: Options{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ws, err := Open(t.TempDir(), tc.opts)
			if ws != nil || !errors.Is(err, ErrUnsupported) {
				t.Fatalf("Open = %v, %v", ws, err)
			}
		})
	}
}
