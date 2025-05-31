package main

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"time"

	ast "github.com/autobrr/autoscan/targets/autoscan"
	"github.com/autobrr/autoscan/targets/emby"
	"github.com/autobrr/autoscan/targets/jellyfin"
	"github.com/autobrr/autoscan/targets/plex"
	"github.com/autobrr/autoscan/triggers/a_train"
	"github.com/autobrr/autoscan/triggers/bernard"
	"github.com/autobrr/autoscan/triggers/inotify"
	"github.com/autobrr/autoscan/triggers/lidarr"
	"github.com/autobrr/autoscan/triggers/manual"
	"github.com/autobrr/autoscan/triggers/radarr"
	"github.com/autobrr/autoscan/triggers/readarr"
	"github.com/autobrr/autoscan/triggers/sonarr"
)

type Triggers struct {
	Manual  manual.Config    `yaml:"manual"`
	ATrain  a_train.Config   `yaml:"a-train"`
	Bernard []bernard.Config `yaml:"bernard"`
	Inotify []inotify.Config `yaml:"inotify"`
	Lidarr  []lidarr.Config  `yaml:"lidarr"`
	Radarr  []radarr.Config  `yaml:"radarr"`
	Readarr []readarr.Config `yaml:"readarr"`
	Sonarr  []sonarr.Config  `yaml:"sonarr"`
}

type Targets struct {
	Autoscan []ast.Config      `yaml:"autoscan"`
	Emby     []emby.Config     `yaml:"emby"`
	Jellyfin []jellyfin.Config `yaml:"jellyfin"`
	Plex     []plex.Config     `yaml:"plex"`
}

type HttpAuth struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type config struct {
	// General configuration
	Host       []string      `yaml:"host"`
	Port       int           `yaml:"port"`
	MinimumAge time.Duration `yaml:"minimum-age"`
	ScanDelay  time.Duration `yaml:"scan-delay"`
	ScanStats  time.Duration `yaml:"scan-stats"`
	Anchors    []string      `yaml:"anchors"`

	// Authentication for autoscan.HTTPTrigger
	Auth HttpAuth `yaml:"authentication"`

	// autoscan.HTTPTrigger
	Triggers Triggers `yaml:"triggers"`

	// autoscan.Target
	Targets Targets `yaml:"targets"`
}

func NewConfig(filePath string) (*config, error) {
	// set default values
	c := config{
		MinimumAge: 10 * time.Minute,
		ScanDelay:  5 * time.Second,
		ScanStats:  1 * time.Hour,
		Host:       []string{""},
		Port:       3030,
	}

	if filePath != "" {
		// config
		file, err := os.Open(filePath)
		if err != nil {
			//log.Fatal().
			//	Err(err).
			//	Msg("Failed opening config")
			return nil, err
		}
		defer file.Close()

		decoder := yaml.NewDecoder(file)
		//decoder.SetStrict(true)
		err = decoder.Decode(&c)
		if err != nil {
			return nil, err
			//log.Fatal().
			//	Err(err).
			//	Msg("Failed decoding config")
		}
	}

	return &c, nil
}

func defaultConfigDirectory(app string, filename string) string {
	// binary path
	bcd := getBinaryPath()
	if _, err := os.Stat(filepath.Join(bcd, filename)); err == nil {
		// there is a config file in the binary path
		// so use this directory as the default
		return bcd
	}

	// config dir
	ucd, err := os.UserConfigDir()
	if err != nil {
		panic(fmt.Sprintf("userconfigdir: %v", err))
	}

	acd := filepath.Join(ucd, app)
	if _, err := os.Stat(acd); os.IsNotExist(err) {
		if err := os.MkdirAll(acd, os.ModePerm); err != nil {
			panic(fmt.Sprintf("mkdirall: %v", err))
		}
	}

	return acd
}

func getBinaryPath() string {
	// get current binary path
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		// get current working dir
		if dir, err = os.Getwd(); err != nil {
			panic(fmt.Sprintf("getwd: %v", err))
		}
	}

	return dir
}
