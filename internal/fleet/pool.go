package fleet

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Le pool maintient UNE connexion SSH par hôte, réutilisée, sur laquelle
// plusieurs canaux sont ouverts.
//
// Pourquoi : les hôtes limitent le débit de connexions sur le port 22
// (`ufw limit 22/tcp` rejette au-delà de six connexions en trente secondes
// depuis la même source). Ouvrir une connexion par appel faisait échouer la
// fiche d'hôte — cinq appels simultanés — avec « Connection refused », de
// façon intermittente et donc déroutante.
//
// Une connexion réutilisée supprime le problème à la racine, et économise au
// passage la poignée de main SSH à chaque appel (~0,3 s).
type pool struct {
	mu    sync.Mutex
	conns map[string]*conn
}

type conn struct {
	client *ssh.Client
	sem    chan struct{} // borne les canaux simultanés
	last   time.Time
	dead   bool
}

// maxSessions reste sous le MaxSessions de sshd (10 par défaut) tout en
// laissant assez de parallélisme pour que la fiche d'hôte reste rapide.
const maxSessions = 4

// idleTTL ferme une connexion inutilisée : une console qui garde des
// connexions ouvertes indéfiniment vers tout un parc est une surface inutile.
const idleTTL = 10 * time.Minute

func newPool() *pool { return &pool{conns: map[string]*conn{}} }

func (p *pool) get(ctx context.Context, c *Client, addr, user string, port int) (*conn, error) {
	key := net.JoinHostPort(addr, strconv.Itoa(port)) + "|" + user

	p.mu.Lock()
	existing, ok := p.conns[key]
	if ok && !existing.dead {
		existing.last = time.Now()
		p.mu.Unlock()
		return existing, nil
	}
	p.mu.Unlock()

	// Établissement hors verrou global : un hôte lent ne doit pas bloquer
	// les connexions vers les autres.
	client, err := c.dial(ctx, addr, user, port)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	// Une autre goroutine a pu établir la connexion entre-temps.
	if cur, ok := p.conns[key]; ok && !cur.dead {
		_ = client.Close()
		cur.last = time.Now()
		return cur, nil
	}
	nc := &conn{client: client, sem: make(chan struct{}, maxSessions), last: time.Now()}
	p.conns[key] = nc

	// Marquer morte dès que la connexion tombe, pour rétablir au prochain appel.
	go func() {
		_ = client.Wait()
		p.mu.Lock()
		nc.dead = true
		p.mu.Unlock()
	}()
	return nc, nil
}

// drop force le rétablissement au prochain appel.
func (p *pool) drop(addr, user string, port int) {
	key := net.JoinHostPort(addr, strconv.Itoa(port)) + "|" + user
	p.mu.Lock()
	if c, ok := p.conns[key]; ok {
		c.dead = true
		_ = c.client.Close()
		delete(p.conns, key)
	}
	p.mu.Unlock()
}

// reap ferme les connexions inutilisées depuis idleTTL.
func (p *pool) reap() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, c := range p.conns {
		if c.dead || time.Since(c.last) > idleTTL {
			_ = c.client.Close()
			delete(p.conns, k)
		}
	}
}

// Close ferme tout le pool.
func (p *pool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, c := range p.conns {
		_ = c.client.Close()
		delete(p.conns, k)
	}
}

func (c *Client) dial(ctx context.Context, addr, user string, port int) (*ssh.Client, error) {
	// knownhosts attend « hôte:port » : c'est cette forme qui sert à
	// retrouver l'entrée, et il la normalise lui-même.
	hostport := net.JoinHostPort(addr, strconv.Itoa(port))
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(c.signer)},
		HostKeyCallback: c.hostKeys,
		Timeout:         c.dialTimeout,
	}
	d := net.Dialer{Timeout: c.dialTimeout}
	nc, err := d.DialContext(ctx, "tcp", hostport)
	if err != nil {
		return nil, fmt.Errorf("connexion : %w", err)
	}
	sc, chans, reqs, err := ssh.NewClientConn(nc, hostport, cfg)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("poignée de main SSH : %w", err)
	}
	cl := ssh.NewClient(sc, chans, reqs)
	// Sonde périodique : sans elle, une connexion coupée par un pare-feu
	// intermédiaire reste « vivante » côté client jusqu'au premier échec.
	go keepalive(cl)
	return cl, nil
}

func keepalive(cl *ssh.Client) {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for range t.C {
		if _, _, err := cl.SendRequest("keepalive@openssh.com", true, nil); err != nil {
			return
		}
	}
}
