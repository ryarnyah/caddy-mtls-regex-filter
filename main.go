package mtls_regex_filter

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"regexp"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"

	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(MTLSRegexFilter{})
}

type MTLSRegexFilter struct {
	TrustedRegexpOIDs [][]map[string]string `json:"trusted_regexp_oids,omitempty"`

	patterns [][]map[string]*regexp.Regexp
	logger   *zap.Logger
}

func (m *MTLSRegexFilter) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	for _, groupPattern := range m.TrustedRegexpOIDs {
		p := make([]map[string]*regexp.Regexp, 0)
		for _, pattern := range groupPattern {
			r := make(map[string]*regexp.Regexp)
			for oid, regex := range pattern {
				compiled, err := regexp.Compile(regex)
				if err != nil {
					return err
				}
				r[oid] = compiled
			}
			p = append(p, r)
		}
		m.patterns = append(m.patterns, p)
	}
	return nil
}

func (g MTLSRegexFilter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.NextArg() {
		return d.ArgErr()
	}
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		for d.Next() {
			if !d.NextArg() {
				return d.ArgErr()
			}
			key := d.Val()
			if key != "trusted_regexp_oids" {
				return d.ArgErr()
			}
			p := make([]map[string]string, 0)
			for nestingArg := d.Nesting(); d.NextBlock(nestingArg); {
				for d.Next() {
					if !d.NextArg() {
						return d.ArgErr()
					}
					keyArg := d.Val()
					if keyArg != "regexp_oids" {
						return d.ArgErr()
					}
					r := make(map[string]string)
					for nestingOids := d.Nesting(); d.NextBlock(nestingOids); {
						for d.Next() {
							if !d.NextArg() {
								return d.ArgErr()
							}
							oidPattern := d.RemainingArgs()
							if len(oidPattern) != 2 {
								return d.ArgErr()
							}
							r[oidPattern[0]] = oidPattern[1]
						}
					}
					p = append(p, r)
				}
			}
			g.TrustedRegexpOIDs = append(g.TrustedRegexpOIDs, p)
		}
	}
	return nil
}

func (MTLSRegexFilter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "tls.client_auth.regexp_filter",
		New: func() caddy.Module {
			return &MTLSRegexFilter{
				TrustedRegexpOIDs: make([][]map[string]string, 0),
				patterns:          make([][]map[string]*regexp.Regexp, 0),
			}
		},
	}
}

func (m *MTLSRegexFilter) VerifyClientCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("no client certificate provided")
	}

	remoteLeafCert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("can't parse the given certificate: %s", err.Error())
	}
	for _, groupPattern := range m.patterns {
		// Check DN
		if m.anyDNPatternMatch(groupPattern, remoteLeafCert.Subject.Names) {
			return nil
		}
		// Check DNS
		if m.anyDNSPatternMatch(groupPattern, remoteLeafCert.DNSNames) {
			return nil
		}
	}

	return fmt.Errorf("client leaf certificate failed validation")
}

func (m *MTLSRegexFilter) anyDNSPatternMatch(groupPattern []map[string]*regexp.Regexp, dnss []string) bool {
	for _, pattern := range groupPattern {
		for _, dns := range dnss {
			if _, ok := pattern["dns"]; !ok {
				return false
			}
			if !pattern["dns"].Match([]byte(dns)) {
				return false
			}
		}
	}
	return true
}

func (m *MTLSRegexFilter) anyDNPatternMatch(groupPattern []map[string]*regexp.Regexp, names []pkix.AttributeTypeAndValue) bool {
	for _, pattern := range groupPattern {
		for _, oid := range names {
			oidName := oid.Type.String()
			if _, ok := pattern[oidName]; !ok {
				return false
			}
			if !pattern[oidName].Match([]byte(oid.Value.(string))) {
				return false
			}
		}
	}
	return true
}

var (
	_ caddy.Provisioner                  = (*MTLSRegexFilter)(nil)
	_ caddytls.ClientCertificateVerifier = (*MTLSRegexFilter)(nil)
	_ caddyfile.Unmarshaler              = (*MTLSRegexFilter)(nil)
)
