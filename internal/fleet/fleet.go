// Package fleet parle aux hôtes sauvegardés à travers leur shim.
//
// La console n'exécute jamais restic elle-même et ne détient aucune clé de
// dépôt. Elle ouvre une session SSH dont la clé est bornée côté hôte par une
// directive command= : quoi qu'elle demande, l'hôte n'exécute que ce que sa
// policy locale autorise. La console demande, l'hôte décide.
package fleet

import (
	"bufio"
	"bytes"
	"sort"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type Client struct {
	signer      ssh.Signer
	hostKeys    ssh.HostKeyCallback
	dialTimeout time.Duration
	pool        *pool
}

// Close libère les connexions maintenues.
func (c *Client) Close() { c.pool.Close() }

// Reap ferme les connexions inutilisées. À appeler périodiquement.
func (c *Client) Reap() { c.pool.reap() }

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
	return &Client{signer: signer, hostKeys: cb, dialTimeout: 15 * time.Second, pool: newPool()}, nil
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
		TotalBytesProcessed int64     `json:"total_bytes_processed"`
		TotalFilesProcessed int64     `json:"total_files_processed"`
		DataAdded           int64     `json:"data_added"`
		DataAddedPacked     int64     `json:"data_added_packed"`
		FilesNew            int64     `json:"files_new"`
		FilesChanged        int64     `json:"files_changed"`
		BackupStart         time.Time `json:"backup_start"`
		BackupEnd           time.Time `json:"backup_end"`
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

// Unlock retire les verrous périmés du dépôt d'un hôte. Le shim n'expose
// jamais --remove-all : un verrou vivant n'est pas touché.
func (c *Client) Unlock(ctx context.Context, addr, user string, port int) error {
	_, err := c.run(ctx, addr, user, port, "unlock")
	return err
}

func (c *Client) run(ctx context.Context, addr, user string, port int, cmd string) ([]byte, error) {
	pc, err := c.pool.get(ctx, c, addr, user, port)
	if err != nil {
		return nil, err
	}

	// Borne les canaux simultanés sur cette connexion.
	select {
	case pc.sem <- struct{}{}:
		defer func() { <-pc.sem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	sess, err := pc.client.NewSession()
	if err != nil {
		// Connexion probablement tombée : on la jette et on réessaie une fois.
		c.pool.drop(addr, user, port)
		pc, derr := c.pool.get(ctx, c, addr, user, port)
		if derr != nil {
			return nil, derr
		}
		if sess, err = pc.client.NewSession(); err != nil {
			return nil, fmt.Errorf("ouverture de session : %w", err)
		}
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
		var ee *ssh.ExitError
		if ok := asExitError(runErr, &ee); ok {
			switch ee.ExitStatus() {
			case 77:
				return nil, fmt.Errorf("refusé par la policy locale de l'hôte")
			case 78:
				return nil, fmt.Errorf("policy absente sur l'hôte")
			case 10:
				return nil, fmt.Errorf("dépôt introuvable — ne pas réinitialiser sans vérifier")
			case 11:
				return nil, fmt.Errorf("dépôt verrouillé : un verrou périmé traîne, lancer « Déverrouiller »")
			case 12:
				return nil, fmt.Errorf("mot de passe de dépôt incorrect sur l'hôte")
			}
		}
		return nil, fmt.Errorf("exécution distante : %w", runErr)
	}
	return out, nil
}

// Snapshot est un instantané tel que l'hôte le décrit.
type Snapshot struct {
	ID       string
	Time     time.Time
	Paths    []string
	Size     int64
	Added    int64         // volume nouveau, avant compression
	Packed   int64         // ce que ce snapshot a réellement coûté au dépôt
	Files    int64
	Duration time.Duration // écart entre début et fin de sauvegarde
}

// Snapshots liste tous les instantanés du dépôt d'un hôte.
func (c *Client) Snapshots(ctx context.Context, addr, user string, port int) ([]Snapshot, error) {
	out, err := c.run(ctx, addr, user, port, "snapshots")
	if err != nil {
		return nil, err
	}
	var raw []resticSnapshot
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, fmt.Errorf("liste de snapshots illisible : %w", err)
	}
	res := make([]Snapshot, 0, len(raw))
	for i := len(raw) - 1; i >= 0; i-- {
		s := raw[i]
		id := s.ShortID
		if id == "" && len(s.ID) >= 8 {
			id = s.ID[:8]
		}
		var dur time.Duration
		if !s.Summary.BackupEnd.IsZero() && !s.Summary.BackupStart.IsZero() {
			dur = s.Summary.BackupEnd.Sub(s.Summary.BackupStart)
		}
		res = append(res, Snapshot{
			ID: id, Time: s.Time, Paths: s.Paths,
			Size:     s.Summary.TotalBytesProcessed,
			Added:    s.Summary.DataAdded,
			Packed:   s.Summary.DataAddedPacked,
			Files:    s.Summary.TotalFilesProcessed,
			Duration: dur,
		})
	}
	return res, nil
}

// RepoStats reflète « restic stats --mode raw-data --json ».
type RepoStats struct {
	TotalSize        int64   `json:"total_size"`
	UncompressedSize int64   `json:"total_uncompressed_size"`
	CompressionRatio float64 `json:"compression_ratio"`
	SnapshotsCount   int     `json:"snapshots_count"`
	BlobCount        int     `json:"total_blob_count"`
}

// Stats rend l'occupation réelle du dépôt, après compression et déduplication.
func (c *Client) Stats(ctx context.Context, addr, user string, port int) (*RepoStats, error) {
	out, err := c.run(ctx, addr, user, port, "stats")
	if err != nil {
		return nil, err
	}
	var st RepoStats
	if err := json.Unmarshal(out, &st); err != nil {
		return nil, fmt.Errorf("statistiques illisibles : %w", err)
	}
	return &st, nil
}

// PolicyEntry est une ligne de la policy locale d'un hôte.
type PolicyEntry struct {
	Key     string
	Value   string
	Allowed bool
}

// Policy rend la policy que l'hôte s'applique à lui-même. Elle n'est pas un
// secret : c'est au contraire ce qui doit être visible pour être vérifié.
func (c *Client) Policy(ctx context.Context, addr, user string, port int) ([]PolicyEntry, error) {
	out, err := c.run(ctx, addr, user, port, "policy")
	if err != nil {
		return nil, err
	}
	var res []PolicyEntry
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"`)
		res = append(res, PolicyEntry{Key: strings.TrimSpace(k), Value: v, Allowed: v == "yes"})
	}
	return res, nil
}

// Node est une entrée d'arborescence dans un snapshot.
type Node struct {
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	Path        string    `json:"path"`
	Size        int64     `json:"size"`
	Permissions string    `json:"permissions"`
	MTime       time.Time `json:"mtime"`
	StructType  string    `json:"struct_type"`
}

func (n Node) IsDir() bool { return n.Type == "dir" }

// List rend le contenu IMMÉDIAT d'un répertoire dans un snapshot.
//
// « restic ls » sans --recursive ne descend pas : un niveau à la fois, ce qui
// rend la navigation praticable même sur un moodledata de 300 000 fichiers.
// La sortie est du JSON par lignes : un objet « snapshot » d'abord, puis un
// objet « node » par entrée.
func (c *Client) List(ctx context.Context, addr, user string, port int, snapshot, path string) ([]Node, error) {
	if snapshot == "" {
		snapshot = "latest"
	}
	if path == "" {
		path = "/"
	}
	out, err := c.run(ctx, addr, user, port, fmt.Sprintf("ls %s %s", snapshot, path))
	if err != nil {
		return nil, err
	}
	var nodes []Node
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var n Node
		if err := json.Unmarshal(line, &n); err != nil {
			continue
		}
		if n.StructType != "node" {
			continue
		}
		nodes = append(nodes, n)
	}
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].IsDir() != nodes[j].IsDir() {
			return nodes[i].IsDir()
		}
		return nodes[i].Name < nodes[j].Name
	})
	return nodes, sc.Err()
}


// Excludes rend la liste des exclusions appliquées sur l'hôte. Savoir ce qui
// n'est PAS sauvegardé est aussi important que l'inverse — et c'est ce qu'on
// ne découvre d'ordinaire qu'au moment de restaurer.
func (c *Client) Excludes(ctx context.Context, addr, user string, port int) ([]string, error) {
	out, err := c.run(ctx, addr, user, port, "excludes")
	if err != nil {
		return nil, err
	}
	var res []string
	for _, l := range strings.Split(string(out), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		res = append(res, l)
	}
	return res, nil
}
