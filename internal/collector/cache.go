package collector

import (
	"sync"
	"time"
)

// cache mémorise brièvement les réponses coûteuses des hôtes.
//
// Un appel « snapshots » ou « stats » coûte ~2,5 s : restic rouvre le dépôt
// distant en SFTP, lit sa configuration puis son index. Trois appels
// séquentiels donnaient une fiche d'hôte à 5 s. Le cache n'est PAS persisté :
// il vit en mémoire et disparaît au redémarrage — la console ne doit pas
// accumuler de métadonnées d'hôte sur son disque.
type cache struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]entry
}

type entry struct {
	val any
	at  time.Time
}

func newCache(ttl time.Duration) *cache {
	return &cache{ttl: ttl, m: map[string]entry{}}
}

func (c *cache) get(key string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok || time.Since(e.at) > c.ttl {
		return nil, false
	}
	return e.val, true
}

func (c *cache) put(key string, v any) {
	c.mu.Lock()
	c.m[key] = entry{val: v, at: time.Now()}
	c.mu.Unlock()
}

// getLong lit une entrée avec un TTL propre, pour les données immuables.
func (c *cache) getLong(key string, ttl time.Duration) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok || time.Since(e.at) > ttl {
		return nil, false
	}
	return e.val, true
}

// Invalidate purge les entrées d'un hôte, après une action qui change son état.
func (c *cache) invalidate(host string) {
	c.mu.Lock()
	for k := range c.m {
		if len(k) > len(host) && k[:len(host)] == host {
			delete(c.m, k)
		}
	}
	c.mu.Unlock()
}
