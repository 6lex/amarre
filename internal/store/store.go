// Package store persiste l'état de la console dans SQLite.
//
// Ce que cette base contient : des métadonnées de sauvegarde et des comptes
// d'accès. Ce qu'elle ne contient JAMAIS : un mot de passe de dépôt restic,
// un identifiant Storage Box, un contenu de fichier. La compromission de la
// console ne doit ouvrir aucune donnée sauvegardée.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct{ db *sql.DB }

const schema = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    totp_secret   TEXT,
    created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    remote_ip  TEXT NOT NULL
);

-- Un relevé par collecte et par hôte.
CREATE TABLE IF NOT EXISTS checks (
    id          INTEGER PRIMARY KEY,
    host        TEXT NOT NULL,
    collected_at INTEGER NOT NULL,
    reachable   INTEGER NOT NULL,
    err         TEXT,
    snapshot_id TEXT,
    snapshot_at INTEGER,
    size_bytes  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_checks_host_time ON checks(host, collected_at DESC);

-- Journal d'audit : toute action sensible, côté console.
-- Le shim tient le sien de son côté ; un attaquant qui prend la console ne
-- peut donc pas effacer la trace vue par l'hôte.
CREATE TABLE IF NOT EXISTS audit (
    id        INTEGER PRIMARY KEY,
    at        INTEGER NOT NULL,
    actor     TEXT NOT NULL,
    remote_ip TEXT NOT NULL,
    action    TEXT NOT NULL,
    target    TEXT,
    outcome   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit(at DESC);
`

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("ouverture de la base : %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("création du schéma : %w", err)
	}
	// CREATE TABLE IF NOT EXISTS n'ajoute jamais de colonne à une table
	// existante : les ajouts se font par ALTER, dont l'échec est ignoré
	// lorsque la colonne est déjà là.
	for _, alter := range []string{
		`ALTER TABLE checks ADD COLUMN repo_size INTEGER`,
		`ALTER TABLE checks ADD COLUMN repo_raw INTEGER`,
		`ALTER TABLE sessions ADD COLUMN csrf TEXT`,
	} {
		_, _ = db.Exec(alter)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// ─── Utilisateurs ───────────────────────────────────────────────────────

type User struct {
	ID         int64
	Username   string
	PassHash   string
	TOTPSecret string
}

var ErrNoUser = errors.New("utilisateur inconnu")

func (s *Store) CreateUser(username, hash, totp string) error {
	_, err := s.db.Exec(
		`INSERT INTO users (username, password_hash, totp_secret, created_at) VALUES (?,?,?,?)`,
		username, hash, totp, time.Now().Unix())
	return err
}

func (s *Store) UserByName(username string) (*User, error) {
	u := &User{}
	var totp sql.NullString
	err := s.db.QueryRow(
		`SELECT id, username, password_hash, totp_secret FROM users WHERE username = ?`,
		username).Scan(&u.ID, &u.Username, &u.PassHash, &totp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoUser
	}
	if err != nil {
		return nil, err
	}
	u.TOTPSecret = totp.String
	return u, nil
}

// TOTPSecret rend le secret d'un compte, pour réafficher son QR code.
func (s *Store) TOTPSecret(username string) (string, error) {
	var secret sql.NullString
	err := s.db.QueryRow(`SELECT totp_secret FROM users WHERE username = ?`, username).Scan(&secret)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNoUser
	}
	if err != nil {
		return "", err
	}
	return secret.String, nil
}

func (s *Store) CountUsers() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// ─── Sessions ───────────────────────────────────────────────────────────

// CreateSession lie un jeton CSRF à la session, pour toute sa durée.
//
// Le régénérer à chaque affichage invaliderait le formulaire d'un onglet dès
// qu'une autre page est chargée : deux onglets ouverts, et la première action
// échoue en 403 sans explication.
func (s *Store) CreateSession(token string, userID int64, ip, csrf string, ttl time.Duration) error {
	now := time.Now()
	_, err := s.db.Exec(
		`INSERT INTO sessions (token, user_id, created_at, expires_at, remote_ip, csrf)
		 VALUES (?,?,?,?,?,?)`,
		token, userID, now.Unix(), now.Add(ttl).Unix(), ip, csrf)
	return err
}

// SessionCSRF rend le jeton CSRF attaché à une session.
func (s *Store) SessionCSRF(token string) (string, error) {
	var c sql.NullString
	err := s.db.QueryRow(`SELECT csrf FROM sessions WHERE token = ?`, token).Scan(&c)
	if err != nil {
		return "", err
	}
	return c.String, nil
}

// SetSessionCSRF attache un jeton à une session qui n'en a pas.
// Nécessaire pour les sessions ouvertes avant que le jeton ne soit lié à la
// session : sans cela, leurs formulaires seraient refusés jusqu'à déconnexion.
func (s *Store) SetSessionCSRF(token, csrf string) error {
	_, err := s.db.Exec(`UPDATE sessions SET csrf = ? WHERE token = ?`, csrf, token)
	return err
}

// SessionUser résout une session valide. La session est liée à l'IP qui l'a
// ouverte : un cookie volé et rejoué depuis ailleurs ne vaut rien.
func (s *Store) SessionUser(token, ip string) (*User, error) {
	u := &User{}
	var totp sql.NullString
	err := s.db.QueryRow(`
		SELECT u.id, u.username, u.password_hash, u.totp_secret
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token = ? AND s.expires_at > ? AND s.remote_ip = ?`,
		token, time.Now().Unix(), ip).Scan(&u.ID, &u.Username, &u.PassHash, &totp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoUser
	}
	if err != nil {
		return nil, err
	}
	u.TOTPSecret = totp.String
	return u, nil
}

func (s *Store) DeleteSession(token string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token = ?`, token)
	return err
}

func (s *Store) PurgeExpiredSessions() error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at <= ?`, time.Now().Unix())
	return err
}

// ─── Relevés ────────────────────────────────────────────────────────────

type Check struct {
	Host        string
	CollectedAt time.Time
	Reachable   bool
	Err         string
	SnapshotID  string
	SnapshotAt  time.Time
	SizeBytes   int64
	RepoSize    int64
	RepoRaw     int64
}

func (s *Store) RecordCheck(c Check) error {
	var snapAt any
	if !c.SnapshotAt.IsZero() {
		snapAt = c.SnapshotAt.Unix()
	}
	_, err := s.db.Exec(`
		INSERT INTO checks (host, collected_at, reachable, err, snapshot_id, snapshot_at,
		                    size_bytes, repo_size, repo_raw)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		c.Host, c.CollectedAt.Unix(), c.Reachable, c.Err, c.SnapshotID, snapAt,
		c.SizeBytes, c.RepoSize, c.RepoRaw)
	return err
}

// LatestChecks rend le dernier relevé de chaque hôte.
func (s *Store) LatestChecks() ([]Check, error) {
	rows, err := s.db.Query(`
		SELECT host, collected_at, reachable, COALESCE(err,''), COALESCE(snapshot_id,''),
		       COALESCE(snapshot_at,0), COALESCE(size_bytes,0),
		       COALESCE(repo_size,0), COALESCE(repo_raw,0)
		FROM checks
		WHERE id IN (SELECT MAX(id) FROM checks GROUP BY host)
		ORDER BY host`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Check
	for rows.Next() {
		var c Check
		var collected, snapAt int64
		if err := rows.Scan(&c.Host, &collected, &c.Reachable, &c.Err,
			&c.SnapshotID, &snapAt, &c.SizeBytes, &c.RepoSize, &c.RepoRaw); err != nil {
			return nil, err
		}
		c.CollectedAt = time.Unix(collected, 0)
		if snapAt > 0 {
			c.SnapshotAt = time.Unix(snapAt, 0)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ─── Audit ──────────────────────────────────────────────────────────────

func (s *Store) Audit(actor, ip, action, target, outcome string) {
	_, _ = s.db.Exec(
		`INSERT INTO audit (at, actor, remote_ip, action, target, outcome) VALUES (?,?,?,?,?,?)`,
		time.Now().Unix(), actor, ip, action, target, outcome)
}

type AuditEntry struct {
	At       time.Time
	Actor    string
	RemoteIP string
	Action   string
	Target   string
	Outcome  string
}

func (s *Store) RecentAudit(limit int) ([]AuditEntry, error) {
	rows, err := s.db.Query(
		`SELECT at, actor, remote_ip, action, COALESCE(target,''), outcome
		 FROM audit ORDER BY at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var at int64
		if err := rows.Scan(&at, &e.Actor, &e.RemoteIP, &e.Action, &e.Target, &e.Outcome); err != nil {
			return nil, err
		}
		e.At = time.Unix(at, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

// History rend les n derniers relevés d'un hôte, du plus ancien au plus récent.
// Sert aux courbes de tendance : elles se lisent de gauche à droite.
func (s *Store) History(host string, n int) ([]Check, error) {
	rows, err := s.db.Query(`
		SELECT collected_at, reachable, COALESCE(size_bytes,0), COALESCE(repo_size,0)
		FROM checks WHERE host = ? ORDER BY id DESC LIMIT ?`, host, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Check
	for rows.Next() {
		var c Check
		var at int64
		if err := rows.Scan(&at, &c.Reachable, &c.SizeBytes, &c.RepoSize); err != nil {
			return nil, err
		}
		c.Host = host
		c.CollectedAt = time.Unix(at, 0)
		out = append(out, c)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, rows.Err()
}
