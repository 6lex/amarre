// Package collector interroge périodiquement les hôtes et tient l'état.
//
// La veille porte sur l'ABSENCE de sauvegarde, pas sur l'échec. Un plan qui
// cesse d'exister n'émet aucune erreur : c'est très exactement ainsi qu'une
// sauvegarde peut s'arrêter des mois sans que personne ne le remarque.
package collector

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/6lex/amarre/internal/config"
	"github.com/6lex/amarre/internal/fleet"
	"github.com/6lex/amarre/internal/store"
)

type Collector struct {
	cfg   *config.Config
	fl    *fleet.Client
	st    *store.Store
	log   *slog.Logger
	limit chan struct{}
}

func New(cfg *config.Config, fl *fleet.Client, st *store.Store, log *slog.Logger) *Collector {
	return &Collector{cfg: cfg, fl: fl, st: st, log: log, limit: make(chan struct{}, 4)}
}

// Run boucle jusqu'à annulation du contexte.
func (c *Collector) Run(ctx context.Context) {
	c.CollectAll(ctx)
	t := time.NewTicker(c.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.CollectAll(ctx)
			_ = c.st.PurgeExpiredSessions()
		}
	}
}

func (c *Collector) CollectAll(ctx context.Context) {
	var wg sync.WaitGroup
	for _, h := range c.cfg.Hosts {
		if h.Disabled {
			continue
		}
		wg.Add(1)
		go func(h config.HostConfig) {
			defer wg.Done()
			c.limit <- struct{}{}
			defer func() { <-c.limit }()
			c.collectOne(ctx, h)
		}(h)
	}
	wg.Wait()
}

func (c *Collector) collectOne(ctx context.Context, h config.HostConfig) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	chk := store.Check{Host: h.Name, CollectedAt: time.Now()}
	st, err := c.fl.Status(ctx, h.Addr, h.User, h.Port)
	if err != nil {
		chk.Reachable = false
		chk.Err = err.Error()
		c.log.Warn("collecte en échec", "hôte", h.Name, "erreur", err)
	} else {
		chk.Reachable = true
		chk.SnapshotID = st.SnapshotID
		chk.SnapshotAt = st.Time
		chk.SizeBytes = st.SizeBytes
	}
	if err := c.st.RecordCheck(chk); err != nil {
		c.log.Error("enregistrement du relevé impossible", "hôte", h.Name, "erreur", err)
	}
}

// ─── État présenté ──────────────────────────────────────────────────────

type State string

const (
	StateOK       State = "ok"       // sauvegarde fraîche
	StateOverdue  State = "overdue"  // échéance dépassée — le cas qui compte
	StateUnknown  State = "unknown"  // hôte injoignable
	StateNoBackup State = "nobackup" // aucun snapshot connu
)

type HostView struct {
	Name        string
	State       State
	Age         time.Duration
	SnapshotID  string
	SnapshotAt  time.Time
	SizeBytes   int64
	Err         string
	CollectedAt time.Time
	Expect      time.Duration
}

// Fleet compose la vue de parc à partir du dernier relevé de chaque hôte.
func (c *Collector) Fleet() ([]HostView, error) {
	checks, err := c.st.LatestChecks()
	if err != nil {
		return nil, err
	}
	byHost := map[string]store.Check{}
	for _, ch := range checks {
		byHost[ch.Host] = ch
	}
	now := time.Now()
	out := make([]HostView, 0, len(c.cfg.Hosts))
	for _, h := range c.cfg.Hosts {
		v := HostView{Name: h.Name, Expect: h.Expect}
		ch, seen := byHost[h.Name]
		switch {
		case !seen:
			v.State = StateUnknown
			v.Err = "jamais collecté"
		case !ch.Reachable:
			v.State = StateUnknown
			v.Err = ch.Err
			v.CollectedAt = ch.CollectedAt
		case ch.SnapshotAt.IsZero():
			v.State = StateNoBackup
			v.CollectedAt = ch.CollectedAt
		default:
			v.SnapshotID = ch.SnapshotID
			v.SnapshotAt = ch.SnapshotAt
			v.SizeBytes = ch.SizeBytes
			v.CollectedAt = ch.CollectedAt
			v.Age = now.Sub(ch.SnapshotAt)
			if v.Age > h.Expect {
				v.State = StateOverdue
			} else {
				v.State = StateOK
			}
		}
		out = append(out, v)
	}
	return out, nil
}
