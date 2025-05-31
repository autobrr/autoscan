package datastore

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"time"

	"github.com/autobrr/autoscan"
	"github.com/autobrr/autoscan/migrate"

	"github.com/rs/zerolog/log"
	// sqlite3 driver
	_ "modernc.org/sqlite"
)

type Datastore struct {
	db *sql.DB
	mg *migrate.Migrator
}

var (
	//go:embed migrations
	migrations embed.FS
)

func NewDatastore(path string) (*Datastore, error) {
	store := &Datastore{}

	// datastore
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("could not open SQLite database: %s: %w", path, err)
	}
	store.db = db

	// migrator
	mg, err := migrate.New(db, "migrations")
	if err != nil {
		log.Fatal().
			Err(err).
			Msg("Failed initialising migrator")
	}
	store.mg = mg

	for _, option := range sqliteOptions {
		if _, err := store.db.Exec(option); err != nil {
			return nil, fmt.Errorf("could not set SQLite PRAGMA: %s: %w", err, autoscan.ErrFatal)
		}
	}

	// migrations
	if err := store.mg.Migrate(&migrations, "processor"); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return store, nil
}

var sqliteOptions = []string{
	// Set busy-timeout
	`PRAGMA busy_timeout = 5000;`,

	// Enable WAL. SQLite performs better with the WAL  because it allows
	// multiple readers to operate while data is being written.
	`PRAGMA journal_mode = wal;`,

	// SQLite has a query planner that uses lifecycle stats to fund optimizations.
	// This restricts the SQLite query planner optimizer to only run if sufficient
	// information has been gathered over the lifecycle of the connection.
	// The SQLite documentation is inconsistent in this regard,
	// suggestions of 400 and 1000 are both "recommended", so lets use the lower bound.
	`PRAGMA analysis_limit = 400;`,

	// When the application does not cleanly shut down, the WAL will still be present and not committed.
	// This is a no-op if the WAL is empty, and a commit when the WAL is not to start fresh.
	// When commits hit 1000, PRAGMA wal_checkpoint(PASSIVE); is invoked which tries its best
	// to commit from the WAL (and can fail to commit all pending operations).
	// Forcing a PRAGMA wal_checkpoint(RESTART); in the future on a "quiet period" could be
	// considered.
	`PRAGMA wal_checkpoint(TRUNCATE);`,
}

func (store *Datastore) Close() error {
	return store.db.Close()
}

const sqlUpsert = `
INSERT INTO scan (folder, priority, target_id, time)
VALUES (?, ?, ?, ?)
ON CONFLICT (folder, target_id) DO UPDATE SET
	priority = MAX(excluded.priority, scan.priority),
	time = excluded.time
`

func (store *Datastore) upsert(tx *sql.Tx, scan autoscan.Scan) error {
	_, err := tx.Exec(sqlUpsert, scan.Folder, scan.Priority, scan.Target, scan.Time)
	return err
}

func (store *Datastore) Upsert(scans []autoscan.Scan) error {
	tx, err := store.db.Begin()
	if err != nil {
		return err
	}

	for _, scan := range scans {
		if err = store.upsert(tx, scan); err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				panic(rollbackErr)
			}

			return err
		}
	}

	return tx.Commit()
}

const sqlGetScansRemaining = `SELECT COUNT(folder) FROM scan`

func (store *Datastore) GetScansRemaining() (int, error) {
	row := store.db.QueryRow(sqlGetScansRemaining)

	remaining := 0
	err := row.Scan(&remaining)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return remaining, nil
	case err != nil:
		return remaining, fmt.Errorf("get remaining scans: %v: %w", err, autoscan.ErrFatal)
	}

	return remaining, nil
}

const sqlGetAvailableScan = `
SELECT folder, priority, time FROM scan
WHERE time < ?
ORDER BY priority DESC, time ASC
LIMIT 1
`

func (store *Datastore) GetAvailableScan(minAge time.Duration) (autoscan.Scan, error) {
	row := store.db.QueryRow(sqlGetAvailableScan, now().Add(-1*minAge))

	scan := autoscan.Scan{}
	err := row.Scan(&scan.Folder, &scan.Priority, &scan.Time)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return scan, autoscan.ErrNoScans
	case err != nil:
		return scan, fmt.Errorf("get matching: %s: %w", err, autoscan.ErrFatal)
	}

	return scan, nil
}

const sqlGetAvailableScanWithTarget = `
SELECT folder, priority, target_id, time FROM scan
WHERE time < ? AND target_id = ?
ORDER BY priority DESC, time ASC
LIMIT 1
`

func (store *Datastore) GetAvailableScanWithTarget(minAge time.Duration, targetID string) (autoscan.Scan, error) {
	row := store.db.QueryRow(sqlGetAvailableScanWithTarget, now().Add(-1*minAge), targetID)

	scan := autoscan.Scan{}
	err := row.Scan(&scan.Folder, &scan.Priority, &scan.Target, &scan.Time)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return scan, autoscan.ErrNoScans
	case err != nil:
		return scan, fmt.Errorf("get matching: %s: %w", err, autoscan.ErrFatal)
	}

	return scan, nil
}

const sqlGetAll = `
SELECT folder, priority, target_id, time FROM scan
`

func (store *Datastore) GetAll() (scans []autoscan.Scan, err error) {
	rows, err := store.db.Query(sqlGetAll)
	if err != nil {
		return scans, err
	}

	defer rows.Close()
	for rows.Next() {
		scan := autoscan.Scan{}
		err = rows.Scan(&scan.Folder, &scan.Priority, &scan.Target, &scan.Time)
		if err != nil {
			return scans, err
		}

		scans = append(scans, scan)
	}

	return scans, rows.Err()
}

const sqlDelete = `
DELETE FROM scan WHERE folder=? AND target_id=?
`

func (store *Datastore) Delete(scan autoscan.Scan) error {
	_, err := store.db.Exec(sqlDelete, scan.Folder, scan.Target)
	if err != nil {
		return fmt.Errorf("delete: %s: %w", err, autoscan.ErrFatal)
	}

	return nil
}

var now = time.Now
