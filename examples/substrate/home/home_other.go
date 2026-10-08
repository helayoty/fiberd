//go:build !linux

package home

import "errors"

func remountRW(string) error { return errors.New("remount: not supported on this platform") }
