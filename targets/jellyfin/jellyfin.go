package jellyfin

import (
	"context"
	"fmt"
	"strings"

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
}

func (t *Target) ID() string {
	return t.id
}

func New(c Config) (*Target, error) {
	l := autoscan.GetLogger(c.Verbosity).With().
		Str("target", "jellyfin").
		Str("url", c.URL).
		Logger()

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
	}

	ctx := context.Background()
	if err := api.Available(ctx); err != nil {
		l.Warn().Err(err).Msg("Jellyfin not available")
		return t, autoscan.ErrTargetUnavailable
	}

	libraries, err := api.Libraries(ctx)
	if err != nil {
		return nil, err
	}
	t.libraries = libraries

	l.Debug().
		Interface("libraries", libraries).
		Msg("Retrieved libraries")

	return t, nil
}

func (t *Target) Available(ctx context.Context) error {
	if err := t.api.Available(ctx); err != nil {
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

	lib, err := t.getScanLibrary(scanFolder)
	if err != nil {
		t.log.Warn().
			Err(err).
			Msg("No target libraries found")

		return nil
	}

	l := t.log.With().
		Str("path", scanFolder).
		Str("library", lib.Name).
		Logger()

	// send scan request
	l.Trace().Msg("Sending scan request")

	if err := t.api.Scan(ctx, scanFolder); err != nil {
		return err
	}

	l.Info().Msg("Scan moved to target")
	return nil
}

func (t *Target) getScanLibrary(folder string) (*library, error) {
	for _, l := range t.libraries {
		if strings.HasPrefix(folder, l.Path) {
			return &l, nil
		}
	}

	return nil, fmt.Errorf("%v: failed determining library", folder)
}
