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

// Package testhelpers provides shared test fixtures and helpers for client packages.
// It is only imported by _test.go files and is therefore never compiled into
// a production binary — no build tag is needed to enforce this.
package testhelpers

import (
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/ramcguire/tnascert-deploy/v2/config"
)

// dir returns the absolute path of the directory containing this source file.
// Using runtime.Caller makes this robust regardless of the working directory
// of the test that calls it.
func dir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Dir(filename)
}

// SharedIniPath returns the absolute path to the shared base ini fixture in
// testdata/. Use this for packages that don't have their own ini file.
func SharedIniPath() string {
	return filepath.Join(dir(), "testdata", "tnas-cert.ini")
}

// LoadConfig loads the deploy_default section from iniFile and replaces
// FullChainPath and PrivateKeyPath with the shared PEM fixtures in testdata/.
// iniFile is resolved relative to the calling test's working directory (i.e.
// the package directory), so package-specific ini files can be passed as
// relative paths such as "test_files/tnas-cert.ini".
func LoadConfig(iniFile string) (*config.Config, error) {
	cfgList, err := config.LoadConfig(iniFile)
	if err != nil {
		return nil, fmt.Errorf("error loading config file %q: %w", iniFile, err)
	}
	cfg, ok := cfgList[config.Default_section]
	if !ok {
		return nil, fmt.Errorf("section %q not found in %q", config.Default_section, iniFile)
	}
	cfg.FullChainPath = filepath.Join(dir(), "testdata", "fullchain.pem")
	cfg.PrivateKeyPath = filepath.Join(dir(), "testdata", "privkey.pem")
	return cfg, nil
}
