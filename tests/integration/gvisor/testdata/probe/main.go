// Command probe is run inside a test sandbox with runsc exec to report
// what a fiber can see and do there. It is built static (CGO_ENABLED=0)
// into the test rootfs, since the rootfs has no shell.
//
//	probe ls <dir>        the entries of a directory, space-separated
//	probe write <path>    try to create or overwrite a file
//	probe cat <path>      a file's content
//	probe remount <path>  try to remount a mount read-write
//
// Every answer is one line: the result, or "error: <errno text>".
package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("error: usage probe ls|write|cat|remount <path>")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "ls":
		var entries []os.DirEntry
		if entries, err = os.ReadDir(os.Args[2]); err == nil {
			names := make([]string, 0, len(entries))
			for _, e := range entries {
				names = append(names, e.Name())
			}
			fmt.Println(strings.Join(names, " "))
			return
		}
	case "write":
		if err = os.WriteFile(os.Args[2], []byte("x"), 0o644); err == nil {
			fmt.Println("ok")
			return
		}
	case "cat":
		var data []byte
		if data, err = os.ReadFile(os.Args[2]); err == nil {
			fmt.Println(strings.TrimSpace(string(data)))
			return
		}
	case "remount":
		if err = syscall.Mount("", os.Args[2], "", syscall.MS_REMOUNT|syscall.MS_BIND, ""); err == nil {
			fmt.Println("ok")
			return
		}
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	fmt.Printf("error: %v\n", err)
}
