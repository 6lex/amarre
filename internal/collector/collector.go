// Package collector interroge périodiquement les hôtes et tient l'état.
//
// La veille porte sur l'ABSENCE de sauvegarde, pas sur l'échec. Un plan qui
// cesse d'exister n'émet aucune erreur : c'est très exactement ainsi qu'une
// sauvegarde peut s'arrêter des mois sans que personne ne le remarque.
package collector

import (
	"context"
	"fmt"
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
	cache *cache
}

func New(cfg *config.Config, fl *fleet.Client, st *store.Store, log *slog.Logger) *Collector {
	return &Collector{cfg: cfg, fl: fl, st: st, log: log,
		limit: make(chan struct{}, 4), cache: newCache(90 * time.Second)}
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
		// L'occupation réelle du dépôt est un appel séparé : son échec ne
		// doit pas faire passer l'hôte pour injoignable alors que la
		// sauvegarde, elle, est bien là.
		if rs, serr := c.fl.Stats(ctx, h.Addr, h.User, h.Port); serr == nil {
			chk.RepoSize = rs.TotalSize
			chk.RepoRaw = rs.UncompressedSize
		}
	}
	c.cache.invalidate(h.Name)
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

// Totals agrège le parc pour les tuiles de synthèse.
type Totals struct {
	Hosts, Alerts   int
	Protected       int64
	RepoSize        int64
	Ratio           float64
}

type HostView struct {
	Name        string
	State       State
	Age         time.Duration
	SnapshotID  string
	SnapshotAt  time.Time
	SizeBytes   int64
	RepoSize    int64
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
			v.RepoSize = ch.RepoSize
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

// Totals compose la synthèse affichée en tête de la vue de parc.
func Sum(hosts []HostView) Totals {
	var t Totals
	t.Hosts = len(hosts)
	for _, h := range hosts {
		if h.State != StateOK {
			t.Alerts++
		}
		t.Protected += h.SizeBytes
		t.RepoSize += h.RepoSize
	}
	if t.RepoSize > 0 {
		t.Ratio = float64(t.Protected) / float64(t.RepoSize)
	}
	return t
}

// Detail rassemble ce qu'on affiche sur la fiche d'un hôte. Tout est demandé
// À LA VOLÉE à l'hôte : la console ne conserve pas d'arborescence ni de
// policy, elle ne fait que les relayer.
type Detail struct {
	Host      config.HostConfig
	View      HostView
	Snapshots []fleet.Snapshot
	Stats     *fleet.RepoStats
	Policy    []fleet.PolicyEntry
	Excludes  []string
	History   []store.Check
	Err       string
}

func (c *Collector) HostDetail(ctx context.Context, name string) (*Detail, error) {
	var hc *config.HostConfig
	for i := range c.cfg.Hosts {
		if c.cfg.Hosts[i].Name == name {
			hc = &c.cfg.Hosts[i]
			break
		}
	}
	if hc == nil {
		return nil, fmt.Errorf("hôte inconnu : %s", name)
	}
	d := &Detail{Host: *hc}

	if views, err := c.Fleet(); err == nil {
		for _, v := range views {
			if v.Name == name {
				d.View = v
			}
		}
	}
	d.History, _ = c.st.History(name, 30)

	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()

	// Les trois appels sont indépendants et coûtent ~2,5 s chacun parce que
	// restic rouvre le dépôt distant à chaque fois. En série la fiche mettait
	// 5 s à s'afficher ; en parallèle elle coûte le plus lent des trois.
	var wg sync.WaitGroup
	var snapErr error
	wg.Add(4)
	go func() {
		defer wg.Done()
		d.Snapshots, snapErr = c.snapshotsCached(ctx, *hc)
	}()
	go func() {
		defer wg.Done()
		d.Stats, _ = c.statsCached(ctx, *hc)
	}()
	go func() {
		defer wg.Done()
		d.Policy, _ = c.policyCached(ctx, *hc)
	}()
	go func() {
		defer wg.Done()
		d.Excludes, _ = c.excludesCached(ctx, *hc)
	}()
	wg.Wait()

	if snapErr != nil {
		d.Err = snapErr.Error()
	}
	return d, nil
}

func (c *Collector) snapshotsCached(ctx context.Context, h config.HostConfig) ([]fleet.Snapshot, error) {
	key := h.Name + "|snapshots"
	if v, ok := c.cache.get(key); ok {
		return v.([]fleet.Snapshot), nil
	}
	v, err := c.fl.Snapshots(ctx, h.Addr, h.User, h.Port)
	if err != nil {
		return nil, err
	}
	c.cache.put(key, v)
	return v, nil
}

func (c *Collector) statsCached(ctx context.Context, h config.HostConfig) (*fleet.RepoStats, error) {
	key := h.Name + "|stats"
	if v, ok := c.cache.get(key); ok {
		return v.(*fleet.RepoStats), nil
	}
	v, err := c.fl.Stats(ctx, h.Addr, h.User, h.Port)
	if err != nil {
		return nil, err
	}
	c.cache.put(key, v)
	return v, nil
}

func (c *Collector) excludesCached(ctx context.Context, h config.HostConfig) ([]string, error) {
	key := h.Name + "|excludes"
	if v, ok := c.cache.get(key); ok {
		return v.([]string), nil
	}
	v, err := c.fl.Excludes(ctx, h.Addr, h.User, h.Port)
	if err != nil {
		return nil, err
	}
	c.cache.put(key, v)
	return v, nil
}

func (c *Collector) policyCached(ctx context.Context, h config.HostConfig) ([]fleet.PolicyEntry, error) {
	key := h.Name + "|policy"
	if v, ok := c.cache.get(key); ok {
		return v.([]fleet.PolicyEntry), nil
	}
	v, err := c.fl.Policy(ctx, h.Addr, h.User, h.Port)
	if err != nil {
		return nil, err
	}
	c.cache.put(key, v)
	return v, nil
}

// Browse rend le contenu d'un répertoire d'un snapshot, servi par l'hôte.
// Rien n'est conservé : la console relaie, elle n'archive pas d'arborescence.
func (c *Collector) Browse(ctx context.Context, host, snapshot, path string) ([]fleet.Node, *config.HostConfig, error) {
	var hc *config.HostConfig
	for i := range c.cfg.Hosts {
		if c.cfg.Hosts[i].Name == host {
			hc = &c.cfg.Hosts[i]
			break
		}
	}
	if hc == nil {
		return nil, nil, fmt.Errorf("hôte inconnu : %s", host)
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	nodes, err := c.fl.List(ctx, hc.Addr, hc.User, hc.Port, snapshot, path)
	return nodes, hc, err
}

// SnapshotsOf liste les snapshots d'un hôte, pour le sélecteur de l'explorateur.
func (c *Collector) SnapshotsOf(ctx context.Context, host string) ([]fleet.Snapshot, error) {
	for i := range c.cfg.Hosts {
		if c.cfg.Hosts[i].Name == host {
			h := c.cfg.Hosts[i]
			ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
			defer cancel()
			return c.snapshotsCached(ctx, h)
		}
	}
	return nil, fmt.Errorf("hôte inconnu : %s", host)
}

// Hosts rend la liste configurée, pour les sélecteurs de l'interface.
func (c *Collector) Hosts() []config.HostConfig { return c.cfg.Hosts }

// PolicyOf rend la policy locale d'un hôte.
func (c *Collector) PolicyOf(ctx context.Context, host string) ([]fleet.PolicyEntry, error) {
	for i := range c.cfg.Hosts {
		if c.cfg.Hosts[i].Name == host {
			h := c.cfg.Hosts[i]
			ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			return c.policyCached(ctx, h)
		}
	}
	return nil, fmt.Errorf("hôte inconnu : %s", host)
}

// Action déclenche une opération sur un hôte. Elle est asynchrone : une
// vérification d'intégrité peut durer des minutes sur un gros dépôt, et la
// console ne doit pas retenir une requête HTTP pendant ce temps. Le résultat
// arrive dans le journal d'audit.
//
// L'hôte reste seul juge : si sa policy refuse, le shim sort en 77 et c'est
// ce refus qui est journalisé.
func (c *Collector) Action(host, verb, actor, ip string) error {
	var hc *config.HostConfig
	for i := range c.cfg.Hosts {
		if c.cfg.Hosts[i].Name == host {
			hc = &c.cfg.Hosts[i]
			break
		}
	}
	if hc == nil {
		return fmt.Errorf("hôte inconnu : %s", host)
	}
	switch verb {
	case "check", "backup", "unlock":
	default:
		return fmt.Errorf("opération non proposée : %s", verb)
	}
	c.st.Audit(actor, ip, verb, host, "demandé")

	go func(h config.HostConfig) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		var err error
		switch verb {
		case "check":
			err = c.fl.Check(ctx, h.Addr, h.User, h.Port)
		case "backup":
			err = c.fl.Backup(ctx, h.Addr, h.User, h.Port)
		case "unlock":
			err = c.fl.Unlock(ctx, h.Addr, h.User, h.Port)
		}
		if err != nil {
			c.log.Warn("opération en échec", "hôte", h.Name, "verbe", verb, "erreur", err)
			c.st.Audit(actor, ip, verb, h.Name, "échec : "+err.Error())
			return
		}
		c.st.Audit(actor, ip, verb, h.Name, "succès")
		c.cache.invalidate(h.Name)
		c.collectOne(context.Background(), h)
	}(*hc)
	return nil
}
