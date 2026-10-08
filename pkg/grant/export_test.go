package grant

import "github.com/go-jose/go-jose/v4"

// Header is a token's header, read before any verification.
type Header struct {
	KeyID     string
	Algorithm jose.SignatureAlgorithm
}

// Parse reads the header of token without verifying it.
func Parse(token string) (Header, error) {
	tok, err := parse(token)
	if err != nil {
		return Header{}, err
	}
	h := tok.Headers[0]
	if h.KeyID == "" {
		return Header{}, ErrNoKID
	}
	return Header{KeyID: h.KeyID, Algorithm: jose.SignatureAlgorithm(h.Algorithm)}, nil
}
