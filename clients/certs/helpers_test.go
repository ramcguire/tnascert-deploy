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

package certs

import (
	"testing"

	"github.com/ramcguire/tnascert-deploy/v2/clients/testhelpers"
	"github.com/ramcguire/tnascert-deploy/v2/config"
)

func getConfig() (*config.Config, error) {
	return testhelpers.LoadConfig(testhelpers.SharedIniPath())
}

func TestVerifyCertificate(t *testing.T) {
	cfg, err := getConfig()
	if err != nil {
		t.Errorf("error loading config file: %v", err)
	}

	err = VerifyCertificateKeyPair(cfg.FullChainPath, cfg.PrivateKeyPath)
	if err != nil {
		t.Errorf("VerifyCertificateKeyPair() test failed: %v", err)
	}
}
