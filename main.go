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

package main

import (
	"fmt"
	"log"
	"os"
	"runtime/debug"

	"github.com/ramcguire/tnascert-deploy/v2/clients"

	"github.com/ramcguire/tnascert-deploy/v2/config"

	"github.com/pborman/getopt/v2"
)

// application release
const release = "2.2"

func processSection(arg string, cfg *config.Config) error {
	client, err := clients.New(cfg)
	if err != nil {
		return fmt.Errorf("error creating client for '%s': %w", arg, err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			log.Printf("error closing the client connection: %v", err)
		}
	}()

	if err := client.Login(); err != nil {
		return fmt.Errorf("login error: %w", err)
	}
	if err := client.PreInstall(); err != nil {
		return fmt.Errorf("preinstall tasks error: %w", err)
	}
	if err := client.Install(); err != nil {
		return fmt.Errorf("installation tasks error: %w", err)
	}
	if err := client.PostInstall(); err != nil {
		return fmt.Errorf("post installation tasks error: %w", err)
	}
	return nil
}

func main() {
	help := getopt.BoolLong("help", 'h', "print usage information and exit")
	version := getopt.BoolLong("version", 'v', "print version information and exit")
	configFile := getopt.StringLong("config", 'c', config.Config_file, "full path to the configuration file")
	getopt.SetParameters("config_section ... config_section")

	getopt.Parse()
	if *help {
		getopt.PrintUsage(os.Stdout)
		os.Exit(0)
	}
	if *version {
		if info, ok := debug.ReadBuildInfo(); ok {
			for _, setting := range info.Settings {
				if setting.Key == "vcs.revision" {
					fmt.Printf("\nrelease: %s\ngit revision: %s\n\n", release, setting.Value)
					os.Exit(0)
				}
			}
		}
	}
	args := getopt.Args()
	if len(args) == 0 {
		args = append(args, config.Default_section)
	}

	cfgList, err := config.LoadConfig(*configFile)
	if err != nil {
		getopt.PrintUsage(os.Stdout)
		log.Fatalln("error loading the config,", err)
	}
	for _, arg := range args {
		fmt.Printf("\n")
		log.Printf("processing certificate installation for '%s'\n", arg)
		cfg, ok := cfgList[arg]
		if !ok {
			log.Fatalf("configuration %s was not found", arg)
		}
		if err := processSection(arg, cfg); err != nil {
			log.Printf("%v", err)
			os.Exit(1)
		}
	}
}
