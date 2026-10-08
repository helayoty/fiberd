//go:build !linux

package home

func writableMounts(string) error { return nil }
