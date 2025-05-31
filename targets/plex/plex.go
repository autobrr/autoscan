package plex

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/autobrr/autoscan"
)

type Config struct {
	URL       string             `yaml:"url"`
	Token     string             `yaml:"token"`
	Rewrite   []autoscan.Rewrite `yaml:"rewrite"`
	Verbosity string             `yaml:"verbosity"`
}

type Target struct {
	id        string
	url       string
	token     string
	libraries []library

	log     zerolog.Logger
	rewrite autoscan.Rewriter
	api     *apiClient

	healthy bool
}

func (t *Target) ID() string {
	return t.id
}

func New(c Config) (*Target, error) {
	l := autoscan.GetLogger(c.Verbosity).With().
		Str("target", "plex").
		Str("url", c.URL).Logger()

	rewriter, err := autoscan.NewRewriter(c.Rewrite)
	if err != nil {
		return nil, err
	}

	api := newAPIClient(c.URL, c.Token, l)

	t := &Target{
		id:        autoscan.CreateMd5Hash(c.URL + c.Token),
		url:       c.URL,
		token:     c.Token,
		libraries: make([]library, 0),

		log:     l,
		rewrite: rewriter,
		api:     api,
		healthy: false,
	}

	ctx := context.Background()
	version, err := api.Version(ctx)
	if err != nil {
		t.healthy = false
		l.Warn().
			Err(err).
			Msg("Plex not available")
		return t, autoscan.ErrTargetUnavailable
	}

	t.healthy = true
	l.Debug().Msgf("Plex version: %s", version)
	if !isSupportedVersion(version) {
		return nil, fmt.Errorf("plex running unsupported version %s: %w", version, autoscan.ErrFatal)
	}

	libraries, err := t.api.Libraries(ctx)
	if err != nil {
		return nil, err
	}
	t.libraries = libraries

	l.Debug().
		Interface("libraries", libraries).
		Msg("Retrieved libraries")

	return t, nil
}

// startLibraryFetcher starts a background goroutine that periodically fetches libraries
func (t *Target) startLibraryFetcher(ctx context.Context, fetchInterval time.Duration) {
	t.log.Debug().Msgf("Starting library fetcher with interval: %v", fetchInterval)

	ticker := time.NewTicker(fetchInterval)

	go func() {
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				t.log.Debug().Msg("Fetching libraries")
				libraries, err := t.api.Libraries(ctx)
				if err != nil {
					t.log.Error().Err(err).Msg("Failed to fetch libraries")
					continue
				}

				t.libraries = libraries
				t.log.Debug().
					Interface("libraries", libraries).
					Msg("Libraries refreshed")
			case <-ctx.Done():
				t.log.Debug().Msg("Library fetcher stopped")
				return
			}
		}
	}()
}

func (t *Target) IsHealthy(ctx context.Context) (bool, error) {
	_, err := t.api.Version(ctx)
	if err != nil {
		t.healthy = false
		return false, err
	}
	t.healthy = true
	return t.healthy, nil
}

func (t *Target) Available(ctx context.Context) error {
	if _, err := t.api.Version(ctx); err != nil {
		return err
	}

	if len(t.libraries) == 0 {
		libraries, err := t.api.Libraries(ctx)
		if err != nil {
			return err
		}
		t.libraries = libraries

		t.log.Debug().
			Interface("libraries", libraries).
			Msg("Retrieved libraries")
	}

	return nil
}

func (t *Target) Scan(ctx context.Context, scan autoscan.Scan) error {
	// determine a library for this scan
	scanFolder := t.rewrite(scan.Folder)

	libs, err := t.getScanLibrary(scanFolder)
	if err != nil {
		t.log.Warn().
			Err(err).
			Msg("No Target libraries found")

		return nil
	}

	// send scan request
	for _, lib := range libs {
		l := t.log.With().
			Str("path", scanFolder).
			Str("library", lib.Name).
			Logger()

		l.Trace().Msg("Sending scan request")

		if err := t.api.Scan(ctx, scanFolder, lib.ID); err != nil {
			return err
		}

		l.Info().Msg("Scan moved to target")
	}

	return nil
}

func (t *Target) getScanLibrary(folder string) ([]library, error) {
	libraries := make([]library, 0)

	for _, l := range t.libraries {
		if strings.HasPrefix(folder, l.Path) {
			libraries = append(libraries, l)
		}
	}

	if len(libraries) == 0 {
		return nil, fmt.Errorf("%v: failed determining libraries", folder)
	}

	return libraries, nil
}

func isSupportedVersion(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return false
	}

	major, _ := strconv.Atoi(parts[0])
	minor, _ := strconv.Atoi(parts[1])

	if major >= 2 || (major == 1 && minor >= 20) {
		return true
	}

	return false
}
