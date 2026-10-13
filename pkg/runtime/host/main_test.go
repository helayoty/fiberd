package host_test

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain fails the package when a test leaves a goroutine behind, such
// as the W executioner or a relay outliving Close.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
