// Package fleet parle aux hôtes sauvegardés à travers leur shim.
//
// La console n'exécute jamais restic elle-même et ne détient aucune clé de
// dépôt. Elle ouvre une session SSH dont la clé est bornée côté hôte par une
// directive command= : quoi qu'elle demande, l'hôte n'exécute que ce que sa
// policy locale autorise. La console demande, l'hôte décide.
package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
)

type Client struct {
	signer      ssh.Signer
	hostKeys    ssh.HostKeyCallback
	dialTimeout time.Duration
}

// NewClient charge la clé de parc. knownHosts est obligatoire : accepter
// n'importe quelle clé d'hôte exposerait chaque collecte à une interception,
// et la console ne transporte que des métadonnées mais s'authentifie avec un
// secret qui, lui, vaut beaucoup.
func NewClient(keyPath, knownHostsPath string) (*Client, error) {
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("lecture de la clé de parc : %w", err)
	}
	signer, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("clé de parc illisible : %w", err)
	}
	cb, err := knownHostsCallback(knownHostsPath)
	if err != nil {
		return nil, err
	}
	return &Client{signer: signer, hostKeys: cb, dialTimeout: 15 * time.Second}, nil
}

// Status est ce que la console apprend d'un hôte : des métadonnées, rien de plus.
type Status struct {
	SnapshotID string    `json:"snapshot_id"`
	Time       time.Time `json:"time"`
	SizeBytes  int64     `json:"size_bytes"`
	Hostname   string    `json:"hostname"`
	Paths      []string  `json:"paths"`
}

// resticSnapshot reflète la sortie de « restic snapshots --json ».
type resticSnapshot struct {
	ID       string    `json:"id"`
	ShortID  string    `json:"short_id"`
	Time     time.Time `json:"time"`
	Hostname string    `json:"hostname"`
	Paths    []string  `json:"paths"`
	Summary  struct {
		TotalBytesProcessed int64 `json:"total_bytes_processed"`
	} `json:"summary"`
}

// Status interroge un hôte. Le verbe « status » est le seul que la policy
// autorise systématiquement : il ne divulgue que des métadonnées.
func (c *Client) Status(ctx context.Context, addr, user string, port int) (*Status, error) {
	out, err := c.run(ctx, addr, user, port, "status")
	if err != nil {
		return nil, err
	}
	var snaps []resticSnapshot
	if err := json.Unmarshal(out, &snaps); err != nil {
		return nil, fmt.Errorf("réponse illisible de l'hôte : %w", err)
	}
	if len(snaps) == 0 {
		return nil, fmt.Errorf("aucun snapshot dans le dépôt")
	}
	s := snaps[len(snaps)-1]
	id := s.ShortID
	if id == "" && len(s.ID) >= 8 {
		id = s.ID[:8]
	}
	return &Status{
		SnapshotID: id,
		Time:       s.Time,
		SizeBytes:  s.Summary.TotalBytesProcessed,
		Hostname:   s.Hostname,
		Paths:      s.Paths,
	}, nil
}

// Check demande une vérification d'intégrité du dépôt.
func (c *Client) Check(ctx context.Context, addr, user string, port int) error {
	_, err := c.run(ctx, addr, user, port, "check")
	return err
}

// Backup déclenche une sauvegarde immédiate.
func (c *Client) Backup(ctx context.Context, addr, user string, port int) error {
	_, err := c.run(ctx, addr, user, port, "backup")
	return err
}

func (c *Client) run(ctx context.Context, addr, user string, port int, cmd string) ([]byte, error) {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(c.signer)},
		HostKeyCallback: c.hostKeys,
		Timeout:         c.dialTimeout,
	}
	// knownhosts attend l'adresse sous la forme « hôte:port » : c'est elle
	// qui sert à retrouver l'entrée correspondante, et il la normalise
	// lui-même (« hôte » pour le port 22, « [hôte]:port » sinon). Lui passer
	// le nom seul fait échouer toute vérification de clé d'hôte.
	hostport := net.JoinHostPort(addr, strconv.Itoa(port))
	d := net.Dialer{Timeout: c.dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", hostport)
	if err != nil {
		return nil, fmt.Errorf("connexion : %w", err)
	}
	sc, chans, reqs, err := ssh.NewClientConn(conn, hostport, cfg)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("poignée de main SSH : %w", err)
	}
	client := ssh.NewClient(sc, chans, reqs)
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("ouverture de session : %w", err)
	}
	defer sess.Close()

	// La commande est envoyée telle quelle ; côté hôte, la directive
	// command= la remplace par le shim, qui la reçoit dans
	// SSH_ORIGINAL_COMMAND et la confronte à sa policy.
	done := make(chan struct{})
	var out []byte
	var runErr error
	go func() {
		out, runErr = sess.Output(cmd)
		close(done)
	}()
	select {
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGKILL)
		return nil, ctx.Err()
	case <-done:
	}
	if runErr != nil {
		// Le shim sort en 77 quand la policy refuse : le distinguer d'une
		// panne évite de traiter un refus délibéré comme un incident.
		var ee *ssh.ExitError
		if ok := asExitError(runErr, &ee); ok && ee.ExitStatus() == 77 {
			return nil, fmt.Errorf("refusé par la policy locale de l'hôte")
		}
		return nil, fmt.Errorf("exécution distante : %w", runErr)
	}
	return out, nil
}
