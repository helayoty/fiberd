//go:build !linux

package criu

import (
	"context"
	"errors"
)

// Restore needs clone3-into-cgroup, which only Linux has.
func (o Options) Restore(context.Context, string, int) (*Restored, error) {
	return nil, errors.New("criu: restore is Linux-only")
}
