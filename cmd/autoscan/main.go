package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/natefinch/lumberjack"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/autobrr/autoscan"
	"github.com/autobrr/autoscan/datastore"
	"github.com/autobrr/autoscan/processor"
	ast "github.com/autobrr/autoscan/targets/autoscan"
	"github.com/autobrr/autoscan/targets/emby"
	"github.com/autobrr/autoscan/targets/jellyfin"
	"github.com/autobrr/autoscan/targets/plex"
	"github.com/autobrr/autoscan/triggers/inotify"

	// sqlite3 driver
	_ "modernc.org/sqlite"
)

var (
	// release variables
	Version   string
	Timestamp string
	GitCommit string

	// CLI
	cli struct {
		globals

		// flags
		Config    string `type:"path" default:"${config_file}" env:"AUTOSCAN_CONFIG" help:"Config file path"`
		Database  string `type:"path" default:"${database_file}" env:"AUTOSCAN_DATABASE" help:"Database file path"`
		Log       string `type:"path" default:"${log_file}" env:"AUTOSCAN_LOG" help:"Log file path"`
		Verbosity int    `type:"counter" default:"0" short:"v" env:"AUTOSCAN_VERBOSITY" help:"Log level verbosity"`
	}
)

type globals struct {
	Version versionFlag `name:"version" help:"Print version information and quit"`
}

type versionFlag string

func (v versionFlag) Decode(ctx *kong.DecodeContext) error { return nil }
func (v versionFlag) IsBool() bool                         { return true }
func (v versionFlag) BeforeApply(app *kong.Kong, vars kong.Vars) error {
	fmt.Println(vars["version"])
	app.Exit(0)
	return nil
}

func main() {
	// parse cli
	ctx := kong.Parse(&cli,
		kong.Name("autoscan"),
		kong.Description("Scan media into target media servers"),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{
			Summary: true,
			Compact: true,
		}),
		kong.Vars{
			"version":       fmt.Sprintf("%s (%s@%s)", Version, GitCommit, Timestamp),
			"config_file":   filepath.Join(defaultConfigDirectory("autoscan", "config.yml"), "config.yml"),
			"log_file":      filepath.Join(defaultConfigDirectory("autoscan", "config.yml"), "activity.log"),
			"database_file": filepath.Join(defaultConfigDirectory("autoscan", "config.yml"), "autoscan.db"),
		},
	)

	if err := ctx.Validate(); err != nil {
		fmt.Println("Failed parsing cli:", err)
		os.Exit(1)
	}

	logWriters := []io.Writer{zerolog.ConsoleWriter{TimeFormat: time.Stamp, Out: os.Stderr}}
	if cli.Log != "" {
		logWriters = append(logWriters, zerolog.ConsoleWriter{TimeFormat: time.Stamp, NoColor: true, Out: &lumberjack.Logger{
			Filename:   cli.Log,
			MaxSize:    5,
			MaxAge:     14,
			MaxBackups: 5,
		}})
	}

	// logger
	logger := log.Output(io.MultiWriter(logWriters...))

	switch {
	case cli.Verbosity == 1:
		log.Logger = logger.Level(zerolog.DebugLevel)
	case cli.Verbosity > 1:
		log.Logger = logger.Level(zerolog.TraceLevel)
	default:
		log.Logger = logger.Level(zerolog.InfoLevel)
	}

	// config
	c, err := NewConfig(cli.Config)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed opening config")
	}

	// datastore
	store, err := datastore.NewDatastore(cli.Database)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed initialising datastore")
	}
	defer store.Close()

	// targets
	targets := initTargets(c)

	// processor
	proc, err := processor.New(processor.Config{
		Targets:    targets,
		Anchors:    c.Anchors,
		MinimumAge: c.MinimumAge,
		ScanDelay:  c.ScanDelay,
		Datastore:  store,
	})

	if err != nil {
		log.Fatal().
			Err(err).
			Msg("Failed initialising processor")
	}

	log.Info().
		Stringer("min_age", c.MinimumAge).
		Strs("anchors", c.Anchors).
		Msg("Initialised processor")

	// Check authentication. If no auth -> warn user.
	if c.Auth.Username == "" || c.Auth.Password == "" {
		log.Warn().Msg("Webhooks running without authentication")
	}

	// daemon triggers
	//for _, t := range c.Triggers.Bernard {
	//	trigger, err := bernard.New(t, db)
	//	if err != nil {
	//		log.Fatal().
	//			Err(err).
	//			Str("trigger", "bernard").
	//			Msg("Failed initialising trigger")
	//	}
	//
	//	go trigger(proc.Add)
	//}

	for _, t := range c.Triggers.Inotify {
		trigger, err := inotify.New(t)
		if err != nil {
			log.Fatal().
				Err(err).
				Str("trigger", "inotify").
				Msg("Failed initialising trigger")
		}

		go trigger(proc.Add)
	}

	// http triggers
	router := getRouter(c, proc)

	log.Info().
		Int("manual", 1).
		Int("bernard", len(c.Triggers.Bernard)).
		Int("inotify", len(c.Triggers.Inotify)).
		Int("lidarr", len(c.Triggers.Lidarr)).
		Int("radarr", len(c.Triggers.Radarr)).
		Int("readarr", len(c.Triggers.Readarr)).
		Int("sonarr", len(c.Triggers.Sonarr)).
		Msg("Initialised triggers")

	// scan stats
	if c.ScanStats.Seconds() > 0 {
		go scanStats(proc, c.ScanStats)
	}

	// display initialized banner
	log.Info().
		Str("version", fmt.Sprintf("%s (%s@%s)", Version, GitCommit, Timestamp)).
		Msg("Initialized")

	errorChannel := make(chan error)
	for _, h := range c.Host {
		go func(host string) {
			addr := host
			if !strings.Contains(addr, ":") {
				addr = fmt.Sprintf("%s:%d", host, c.Port)
			}

			log.Info().Msgf("Starting server on %s", addr)
			if err := http.ListenAndServe(addr, router); err != nil {
				if err != nil {
					if !errors.Is(err, http.ErrServerClosed) {
						log.Error().Err(err).Str("addr", addr).Msg("Failed starting web server")
						errorChannel <- err
					}
				}
			}
		}(h)
	}

	go func() {
		err := proc.Run()
		if err != nil {
			errorChannel <- err
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Info().Msgf("recieved signal %q, shutting down autoscan..", sig.String())

		if err := store.Close(); err != nil {
			log.Error().Err(err).Msg("Failed closing datastore")
		}

	case err := <-errorChannel:
		log.Error().Err(err).Msg("got unexpected error")
	}

}

func initTargets(c *config) []autoscan.Target {
	log.Info().Msg("Initialising targets..")

	targets := make([]autoscan.Target, 0)

	for _, t := range c.Targets.Autoscan {
		tp, err := ast.New(t)
		if err != nil {
			log.Warn().Err(err).Str("target", "autoscan").Str("target_url", t.URL).Msg("Failed initialising target")
		}

		targets = append(targets, tp)
	}

	for _, t := range c.Targets.Plex {
		tp, err := plex.New(t)
		if err != nil {
			log.Warn().Err(err).Str("target", "plex").Str("target_url", t.URL).Msg("Failed initialising target")
		}

		targets = append(targets, tp)
	}

	for _, t := range c.Targets.Emby {
		tp, err := emby.New(t)
		if err != nil {
			log.Warn().Err(err).Str("target", "emby").Str("target_url", t.URL).Msg("Failed initialising target")
		}

		targets = append(targets, tp)
	}

	for _, t := range c.Targets.Jellyfin {
		tp, err := jellyfin.New(t)
		if err != nil {
			log.Warn().Err(err).Str("target", "jellyfin").Str("target_url", t.URL).Msg("Failed initialising target")
		}

		targets = append(targets, tp)
	}

	log.Info().Int("autoscan", len(c.Targets.Autoscan)).Int("plex", len(c.Targets.Plex)).Int("emby", len(c.Targets.Emby)).Int("jellyfin", len(c.Targets.Jellyfin)).Msg("Initialised targets")
	return targets
}
