/*
 * Copyright (C) 2025 by John J. Rushford jrushford@apache.org
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package config

import (
	"strings"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	cfgList, err := LoadConfig("test_files/tnas-loadconfig.ini")
	if err != nil {
		t.Fatalf("loading the test config failed: %v", err)
	}
	if len(cfgList) != 3 {
		t.Fatalf("expected 3 config sections, got %d", len(cfgList))
	}

	tests := []struct {
		section string
		host    string
	}{
		{"deploy_default", "nas01.mydomain.com"},
		{"nas02", "nas02.mydomain.com"},
		{"nas03", "nas03.mydomain.com"},
	}
	for _, tt := range tests {
		t.Run(tt.section, func(t *testing.T) {
			cfg, ok := cfgList[tt.section]
			if !ok {
				t.Fatalf("section %q not found", tt.section)
			}
			if cfg.ConnectHost != tt.host {
				t.Errorf("ConnectHost: got %q, want %q", cfg.ConnectHost, tt.host)
			}
		})
	}
}

func TestReadConfigs(t *testing.T) {
	t.Run("error on non-existent file", func(t *testing.T) {
		_, err := LoadConfig("non_existent_file")
		if err == nil {
			t.Error("expected an error loading a non-existent file")
		}
	})

	cfgList, err := LoadConfig("test_files/tnas-cert.ini")
	if err != nil {
		t.Fatalf("loading the test config failed: %v", err)
	}

	t.Run("deploy_default", func(t *testing.T) {
		cfg, ok := cfgList["deploy_default"]
		if !ok {
			t.Fatal("section 'deploy_default' not found")
		}
		tests := []struct {
			name string
			got  any
			want any
		}{
			{"ConnectHost", cfg.ConnectHost, "nas01.mydomain.com"},
			{"PrivateKeyPath", cfg.PrivateKeyPath, "test_files/privkey.pem"},
			{"FullChainPath", cfg.FullChainPath, "test_files/fullchain.pem"},
			{"Protocol", cfg.Protocol, "wss"},
			{"TlsSkipVerify", cfg.TlsSkipVerify, false},
			{"DeleteOldCerts", cfg.DeleteOldCerts, true},
			{"AddAsUiCertificate", cfg.AddAsUiCertificate, true},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if tt.got != tt.want {
					t.Errorf("got %v, want %v", tt.got, tt.want)
				}
			})
		}
	})

	t.Run("nas02", func(t *testing.T) {
		cfg, ok := cfgList["nas02"]
		if !ok {
			t.Fatal("section 'nas02' not found")
		}
		if cfg.ConnectHost != "nas02.mydomain.com" {
			t.Errorf("ConnectHost: got %q, want %q", cfg.ConnectHost, "nas02.mydomain.com")
		}
		wantURL := "wss://nas02.mydomain.com:443/api/current"
		if got := cfg.ServerURL() + "/api/current"; got != wantURL {
			t.Errorf("ServerURL: got %q, want %q", got, wantURL)
		}
		if !strings.HasPrefix(cfg.CertName(), "letsencrypt-") {
			t.Errorf("CertName: got %q, want prefix %q", cfg.CertName(), "letsencrypt-")
		}
	})

	t.Run("nas03", func(t *testing.T) {
		cfg, ok := cfgList["nas03"]
		if !ok {
			t.Fatal("section 'nas03' not found")
		}
		if cfg.ConnectHost != "nas03.mydomain.com" {
			t.Errorf("ConnectHost: got %q, want %q", cfg.ConnectHost, "nas03.mydomain.com")
		}
	})

	defaultTests := []struct {
		section string
		check   func(t *testing.T, cfg *Config)
	}{
		{
			"no_cert_basename",
			func(t *testing.T, cfg *Config) {
				if cfg.CertBasename != Default_base_cert_name {
					t.Errorf("CertBasename: got %q, want %q", cfg.CertBasename, Default_base_cert_name)
				}
			},
		},
		{
			"no_protocol",
			func(t *testing.T, cfg *Config) {
				if cfg.Protocol != Default_protocol {
					t.Errorf("Protocol: got %q, want %q", cfg.Protocol, Default_protocol)
				}
			},
		},
		{
			"no_timeout_seconds",
			func(t *testing.T, cfg *Config) {
				if cfg.TimeoutSeconds != Default_timeout_seconds {
					t.Errorf("TimeoutSeconds: got %d, want %d", cfg.TimeoutSeconds, Default_timeout_seconds)
				}
			},
		},
	}
	for _, tt := range defaultTests {
		t.Run(tt.section, func(t *testing.T) {
			cfg, ok := cfgList[tt.section]
			if !ok {
				t.Fatalf("section %q not found", tt.section)
			}
			tt.check(t, cfg)
		})
	}
}

func TestReadConfigsFromEnvironment(t *testing.T) {
	t.Setenv("DOMAIN_NAME", "mydomain.com")
	t.Setenv("API_KEY", "testapikey")
	t.Setenv("CERT_BASENAME", "letsencrypt")
	t.Setenv("CLIENT_API", "wsapi")
	t.Setenv("PRIVATE_KEY_PATH", "test_files/privkey.pem")
	t.Setenv("FULL_CHAIN_PATH", "test_files/fullchain.pem")
	t.Setenv("PROTOCOL", "wss")
	t.Setenv("TLS_SKIP_VERIFY", "false")
	t.Setenv("CONNECT_HOST", "nas01")
	t.Setenv("CONNECT_PORT", "443")
	t.Setenv("TIMEOUT_SECONDS", "5")
	t.Setenv("DELETE_OLD_CERTIFICATES", "true")
	t.Setenv("ADD_AS_UI_CERTIFICATE", "true")
	t.Setenv("ADD_AS_FTP_CERTIFICATE", "true")
	t.Setenv("ADD_AS_APP_CERTIFICATE", "true")
	t.Setenv("APP_LIST", "frigate")
	t.Setenv("DEBUG", "true")

	cfgList, err := LoadConfig("test_files/environment.ini")
	if err != nil {
		t.Fatalf("loading the test config failed: %v", err)
	}
	cfg, ok := cfgList["deploy_default"]
	if !ok {
		t.Fatalf("section 'deploy_default' not found")
	}

	tests := []struct {
		name string
		got  any
		want any
	}{
		{"ConnectHost", cfg.ConnectHost, "nas01.mydomain.com"},
		{"CertBasename", cfg.CertBasename, "letsencrypt"},
		{"ClientApi", cfg.ClientApi, "wsapi"},
		{"PrivateKeyPath", cfg.PrivateKeyPath, "test_files/privkey.pem"},
		{"FullChainPath", cfg.FullChainPath, "test_files/fullchain.pem"},
		{"Protocol", cfg.Protocol, "wss"},
		{"TlsSkipVerify", cfg.TlsSkipVerify, false},
		{"Port", cfg.Port, uint64(443)},
		{"TimeoutSeconds", cfg.TimeoutSeconds, int64(5)},
		{"DeleteOldCerts", cfg.DeleteOldCerts, true},
		{"AddAsFTPCertificate", cfg.AddAsFTPCertificate, true},
		{"AddAsAppCertificate", cfg.AddAsAppCertificate, true},
		{"AddAsUiCertificate", cfg.AddAsUiCertificate, true},
		{"AppList", cfg.AppList, "frigate"},
		{"Debug", cfg.Debug, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %v, want %v", tt.got, tt.want)
			}
		})
	}
}
