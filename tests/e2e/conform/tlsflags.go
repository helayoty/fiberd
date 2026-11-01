//go:build integration

package main

import (
	"crypto/tls"
	"errors"

	"github.com/helayoty/fiberd/pkg/tlsconf"
)

// callerTLS turns the harness's TLS flags into the config it dials with and
// the thumbprint to bind every minted grant to. With no files it returns a
// nil config, which dials plaintext, and an empty thumbprint. A server name
// needs the files, because it only matters to a TLS dial.
func callerTLS(caFile, certFile, keyFile, serverName string) (cfg *tls.Config, thumbprint string, err error) {
	cfg, err = tlsconf.Client(caFile, certFile, keyFile)
	if err != nil {
		return nil, "", err
	}
	if cfg == nil {
		if serverName != "" {
			return nil, "", errors.New("-tls-server-name needs -tls-ca, -tls-cert and -tls-key")
		}
		return nil, "", nil
	}
	if serverName != "" {
		cfg.ServerName = serverName
	}
	if certFile != "" {
		if thumbprint, err = tlsconf.ThumbprintFile(certFile); err != nil {
			return nil, "", err
		}
	}
	return cfg, thumbprint, nil
}
