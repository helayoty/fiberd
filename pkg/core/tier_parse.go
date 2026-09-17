package core

import (
	"fmt"
	"strings"
)

// ParseTier accepts the proto enum names (FIBER_WARM) and short forms
// (warm), case-insensitively.
func ParseTier(s string) (Tier, error) {
	switch strings.ToUpper(strings.TrimPrefix(strings.ToUpper(s), "FIBER_")) {
	case "BASIC":
		return TierBasic, nil
	case "WARM":
		return TierWarm, nil
	case "CHECKPOINT":
		return TierCheckpoint, nil
	case "SNAPSHOT":
		return TierSnapshot, nil
	case "FABRIC":
		return TierFabric, nil
	case "", "TIER_UNSPECIFIED", "UNSPECIFIED":
		return TierUnspecified, nil
	}
	return TierUnspecified, fmt.Errorf("unknown tier %q", s)
}
