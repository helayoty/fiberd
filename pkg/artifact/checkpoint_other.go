//go:build !linux

package artifact

import (
	"context"
	"errors"
)

func checkpointZygote(context.Context, BuildOptions, string) error {
	return errors.New("artifact: checkpointing a zygote needs Linux and criu (use -skip-images here)")
}
