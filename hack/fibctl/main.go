// Command fibctl sends one line to a fiber's endpoint and prints the
// reply: the shell's way to talk to a reference-zygote fiber.
//
//	fibctl unix:///run/fiberd/g/1-1.sock incr
//	fibctl tcp://10.0.0.7:30012 get
package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/helayoty/fiberd/pkg/endpoint"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: fibctl <endpoint> <line>")
		os.Exit(2)
	}
	reply, err := say(os.Args[1], strings.Join(os.Args[2:], " "))
	if err != nil {
		fmt.Fprintln(os.Stderr, "fibctl:", err)
		os.Exit(1)
	}
	fmt.Print(reply)
}

func say(ep, line string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := endpoint.Dial(ctx, ep)
	if err != nil {
		return "", err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintln(c, line); err != nil {
		return "", err
	}
	return bufio.NewReader(c).ReadString('\n')
}
