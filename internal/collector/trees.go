package collector

import (
	"context"
	"sync"
	"time"

	"github.com/6lex/amarre/internal/config"
	"github.com/6lex/amarre/internal/fleet"
)

// treeStore garde en MÉMOIRE les arborescences complètes déjà récupérées.
//
// Elles ne sont jamais écrites sur disque : même sans clé de dépôt, une base
// contenant tous les chemins de tous les serveurs serait une divulgation
// sérieuse. Elles disparaissent au redémarrage, et c'est voulu.
//
// La clé est (hôte, snapshot). Un snapshot étant immuable, une entrée n'est
// jamais périmée — elle est seulement évincée pour libérer de la mémoire.
type treeStore struct {
	mu      sync.Mutex
	trees   map[string]*fleet.Tree
	used    map[string]time.Time
	loading map[string]*sync.WaitGroup
	nodes   int
}

// maxNodes borne l'empreinte mémoire. ~100 octets par entrée : 800 000 nœuds
// tiennent dans ~80 Mo, largement de quoi couvrir plusieurs Moodle.
const maxNodes = 800_000

func newTreeStore() *treeStore {
	return &treeStore{
		trees:   map[string]*fleet.Tree{},
		used:    map[string]time.Time{},
		loading: map[string]*sync.WaitGroup{},
	}
}

func key(host, snap string) string { return host + "|" + snap }

// Tree rend l'arborescence d'un snapshot, en la récupérant au besoin.
// Deux demandes simultanées sur le même snapshot ne déclenchent qu'un appel.
func (c *Collector) Tree(ctx context.Context, host, snap string) (*fleet.Tree, error) {
	var hc *config.HostConfig
	for i := range c.cfg.Hosts {
		if c.cfg.Hosts[i].Name == host {
			hc = &c.cfg.Hosts[i]
			break
		}
	}
	if hc == nil {
		return nil, errUnknownHost(host)
	}
	k := key(host, snap)

	ts := c.trees
	ts.mu.Lock()
	if t, ok := ts.trees[k]; ok {
		ts.used[k] = time.Now()
		ts.mu.Unlock()
		return t, nil
	}
	// Une récupération est déjà en cours : on l'attend au lieu d'en lancer
	// une seconde, qui doublerait le coût et la charge sur l'hôte.
	if wg, ok := ts.loading[k]; ok {
		ts.mu.Unlock()
		wg.Wait()
		ts.mu.Lock()
		t, ok := ts.trees[k]
		ts.mu.Unlock()
		if ok {
			return t, nil
		}
		return nil, errTreeFailed(host)
	}
	wg := &sync.WaitGroup{}
	wg.Add(1)
	ts.loading[k] = wg
	ts.mu.Unlock()

	defer func() {
		ts.mu.Lock()
		delete(ts.loading, k)
		ts.mu.Unlock()
		wg.Done()
	}()

	fctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	t, err := c.fl.FetchTree(fctx, hc.Addr, hc.User, hc.Port, snap)
	if err != nil {
		return nil, err
	}

	ts.mu.Lock()
	ts.evictLocked(t.Count)
	ts.trees[k] = t
	ts.used[k] = time.Now()
	ts.nodes += t.Count
	ts.mu.Unlock()

	c.log.Info("arborescence en cache", "hôte", host, "snapshot", snap,
		"entrées", t.Count, "durée", time.Since(t.Built).Round(time.Millisecond))
	return t, nil
}

// evictLocked libère de la place en retirant les arborescences les moins
// récemment consultées.
func (ts *treeStore) evictLocked(incoming int) {
	for ts.nodes+incoming > maxNodes && len(ts.trees) > 0 {
		var oldest string
		var oldestAt time.Time
		for k, at := range ts.used {
			if oldest == "" || at.Before(oldestAt) {
				oldest, oldestAt = k, at
			}
		}
		if t, ok := ts.trees[oldest]; ok {
			ts.nodes -= t.Count
		}
		delete(ts.trees, oldest)
		delete(ts.used, oldest)
	}
}

// InvalidateTrees oublie les arborescences d'un hôte, après une sauvegarde.
func (c *Collector) InvalidateTrees(host string) {
	c.trees.mu.Lock()
	defer c.trees.mu.Unlock()
	for k, t := range c.trees.trees {
		if len(k) > len(host) && k[:len(host)+1] == host+"|" {
			c.trees.nodes -= t.Count
			delete(c.trees.trees, k)
			delete(c.trees.used, k)
		}
	}
}
