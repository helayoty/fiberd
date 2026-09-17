package grant

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/protobuf/encoding/protojson"

	grantv1 "github.com/helayoty/fiberd/api/grant/v1"
	"github.com/helayoty/fiberd/pkg/core"
)

// InsecureJSONVerifier accepts a CapacityGrant encoded as protobuf JSON in
// place of a signed JWT. It performs NO signature check and exists only
// for local development and for exercising the ledger before an issuer is
// configured. fiberd refuses to start with it unless told explicitly.
type InsecureJSONVerifier struct{}

var ErrEmptyGrant = errors.New("grant: grant_uid is empty")

func (InsecureJSONVerifier) Verify(_ context.Context, token []byte) (core.Grant, error) {
	var p grantv1.CapacityGrant
	if err := protojson.Unmarshal(token, &p); err != nil {
		return core.Grant{}, fmt.Errorf("grant: decode json grant: %w", err)
	}
	g := FromProto(&p)
	if g.UID == "" {
		return core.Grant{}, ErrEmptyGrant
	}
	return g, nil
}
