package processor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/autobrr/autoscan"
	"github.com/autobrr/autoscan/datastore"

	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"
)

type Config struct {
	Targets    []autoscan.Target
	Anchors    []string
	MinimumAge time.Duration
	ScanDelay  time.Duration

	Datastore *datastore.Datastore
}

func New(c Config) (*Processor, error) {
	proc := &Processor{
		targets:    c.Targets,
		anchors:    c.Anchors,
		minimumAge: c.MinimumAge,
		scanDelay:  c.ScanDelay,
		store:      c.Datastore,
	}
	return proc, nil
}

type Processor struct {
	targets    []autoscan.Target
	anchors    []string
	minimumAge time.Duration
	scanDelay  time.Duration
	store      *datastore.Datastore
	processed  int64
}

// Add adds a scan to the queue. One scan per target
// The scan will be processed by the processor.
func (p *Processor) Add(scans ...autoscan.Scan) error {
	toScan := make([]autoscan.Scan, 0)
	for _, scan := range scans {
		for _, target := range p.targets {
			scan.Target = target.ID()
			toScan = append(toScan, scan)
		}
	}
	return p.store.Upsert(toScan)
}

// ScansRemaining returns the number of scans remaining
func (p *Processor) ScansRemaining() (int, error) {
	return p.store.GetScansRemaining()
}

// ScansProcessed returns the number of scans processed
func (p *Processor) ScansProcessed() int64 {
	return atomic.LoadInt64(&p.processed)
}

// CheckAvailability checks whether all targets are available.
// If one target is not available, the error will return.
func (p *Processor) CheckAvailability(ctx context.Context, targets []autoscan.Target) error {
	g := new(errgroup.Group)

	for _, target := range targets {
		g.Go(func() error {
			return target.Available(ctx)
		})
	}

	return g.Wait()
}

// GetAvailableTargets checks for all available targets.
// If no target is available, it returns autoscan.ErrAllTargetsUnavailable.
func (p *Processor) GetAvailableTargets(ctx context.Context) ([]autoscan.Target, error) {
	targets := make([]autoscan.Target, 0)
	wg := new(sync.WaitGroup)

	for _, target := range p.targets {
		wg.Add(1)
		go func(target autoscan.Target) {
			defer wg.Done()
			if err := target.Available(ctx); err != nil {
				log.Warn().Err(err).Msgf("Target %s is unavailable", target.ID())
				return
			}
			targets = append(targets, target)
		}(target)
	}

	wg.Wait()

	if len(targets) == 0 {
		return targets, autoscan.ErrAllTargetsUnavailable
	}

	return targets, nil
}

func (p *Processor) Process(ctx context.Context) error {
	// Check whether all anchors are present
	for _, anchor := range p.anchors {
		if !fileExists(anchor) {
			return fmt.Errorf("%s: %w", anchor, autoscan.ErrAnchorUnavailable)
		}
	}

	targets, err := p.GetAvailableTargets(ctx)
	if err != nil {
		return err
	}

	g := new(errgroup.Group)

	for _, target := range targets {
		g.Go(func() error {
			targetID := target.ID()
			scan, err := p.store.GetAvailableScanWithTarget(p.minimumAge, targetID)
			if err != nil {
				return err
			}

			if err := target.Scan(ctx, scan); err != nil {
				return err
			}

			if err := p.store.Delete(scan); err != nil {
				return err
			}

			atomic.AddInt64(&p.processed, 1)
			return nil
		})
	}

	return g.Wait()
}

func (p *Processor) Run() error {
	// processor
	log.Info().Msg("Processor starting..")

	targetsSize := len(p.targets)
	for {
		// sleep indefinitely when no targets setup
		if targetsSize == 0 {
			log.Warn().Msg("No targets initialised, processor stopped, triggers will continue...")
			select {}
		}

		procCtx := context.Background()

		// process scans
		err := p.Process(procCtx)
		switch {
		case err == nil:
			// Sleep scan-delay between successful requests to reduce the load on targets.
			time.Sleep(p.scanDelay)

		case errors.Is(err, autoscan.ErrNoScans):
			// No scans currently available, let's wait a couple of seconds
			log.Trace().
				Msg("No scans are available, retrying in 15 seconds...")

			time.Sleep(15 * time.Second)

		case errors.Is(err, autoscan.ErrAnchorUnavailable):
			log.Error().
				Err(err).
				Msg("Not all anchor files are available, retrying in 15 seconds...")

			time.Sleep(15 * time.Second)

		case errors.Is(err, autoscan.ErrAllTargetsUnavailable):
			log.Error().
				Err(err).
				Msg("All targets are unavailable, retrying in 30 seconds...")

			time.Sleep(30 * time.Second)

		case errors.Is(err, autoscan.ErrTargetUnavailable):
			log.Error().
				Err(err).
				Msg("Not all targets are available, retrying in 15 seconds...")

			time.Sleep(15 * time.Second)

		case errors.Is(err, autoscan.ErrFatal):
			// fatal error occurred, processor must stop (however, triggers must not)
			log.Error().
				Err(err).
				Msg("Fatal error occurred while processing targets, processor stopped, triggers will continue...")

			// sleep indefinitely
			select {}

		default:
			// unexpected error
			log.Fatal().
				Err(err).
				Msg("Failed processing targets")
		}
	}
}

var fileExists = func(fileName string) bool {
	info, err := os.Stat(fileName)
	if err != nil {
		return false
	}

	return !info.IsDir()
}
