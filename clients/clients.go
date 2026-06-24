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

package clients

import (
	"fmt"
	"log"

	"github.com/ramcguire/tnascert-deploy/v2/clients/restapi"
	"github.com/ramcguire/tnascert-deploy/v2/clients/wsapi"
	"github.com/ramcguire/tnascert-deploy/v2/config"
)

/*
 * clients must implement this constructor
 * NewClient(cfg config.Config) (clients.Client, error)
 */

// clients must implement this interface.
type Client interface {
	Close() error
	Login() error
	Install() error
	PreInstall() error
	PostInstall() error
}

func New(cfg *config.Config) (Client, error) {
	switch cfg.ClientApi {
	case "restapi":
		if cfg.Debug {
			log.Printf("using a restapi client")
		}
		return restapi.NewClient(cfg)
	case "wsapi":
		if cfg.Debug {
			log.Printf("using a wsapi client")
		}
		return wsapi.NewClient(cfg)
	}
	return nil, fmt.Errorf("empty or undefined client api in the config for %s", cfg.ConnectHost)
}
