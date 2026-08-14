// Package auth regroupe l'authentification de la console.
//
// Trois barrières indépendantes protègent l'accès :
//  1. le filtrage IP (nftables, puis re-vérifié applicativement) ;
//  2. un mot de passe haché en Argon2id ;
//  3. un code TOTP à usage unique.
//
// Aucune ne suffit seule, et la défaillance de l'une n'ouvre pas la porte.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// ─── Mots de passe : Argon2id ───────────────────────────────────────────

// Paramètres RFC 9106, profil « second recommandé » : 64 Mio, 3 passes.
// Coûteux à vérifier (~50 ms), ce qui est précisément le but : cela rend le
// cassage hors ligne d'un hachage volé économiquement dissuasif.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
	saltLen      = 16
)

func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

var ErrBadHash = errors.New("hachage de mot de passe illisible")

func VerifyPassword(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, ErrBadHash
	}
	var version, mem, tim int
	var par int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, ErrBadHash
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &tim, &par); err != nil {
		return false, ErrBadHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, ErrBadHash
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, ErrBadHash
	}
	got := argon2.IDKey([]byte(password), salt, uint32(tim), uint32(mem), uint8(par), uint32(len(want)))
	// Comparaison à temps constant : une comparaison naïve fuirait le
	// préfixe correct par son temps d'exécution.
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// ─── TOTP (RFC 6238) ────────────────────────────────────────────────────
//
// Implémenté sur la bibliothèque standard plutôt qu'avec une dépendance :
// l'algorithme tient en trente lignes, il est intégralement spécifié, et
// il est couvert par les vecteurs de test de la RFC (voir auth_test.go).
// Une dépendance de moins dans un outil qui détient les accès d'un parc.

const totpPeriod = 30

func NewTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

func totpAt(secret string, counter uint64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).
		DecodeString(strings.ToUpper(strings.ReplaceAll(secret, " ", "")))
	if err != nil {
		return "", err
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	m := hmac.New(sha1.New, key)
	m.Write(buf[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1000000), nil
}

// VerifyTOTP accepte la fenêtre courante et une de part et d'autre, pour
// tolérer une horloge légèrement décalée sans élargir inutilement la cible.
func VerifyTOTP(secret, code string, now time.Time) bool {
	if secret == "" || len(code) != 6 {
		return false
	}
	counter := uint64(now.Unix()) / totpPeriod
	for _, d := range []int64{-1, 0, 1} {
		want, err := totpAt(secret, uint64(int64(counter)+d))
		if err != nil {
			return false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// ProvisioningURI rend l'URI otpauth:// à présenter en QR code.
func ProvisioningURI(issuer, account, secret string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=%d",
		issuer, account, secret, issuer, totpPeriod)
}

// ─── Jetons de session ──────────────────────────────────────────────────

func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ─── Limitation des tentatives ──────────────────────────────────────────
//
// Compteur par IP avec fenêtre glissante. Le filtrage IP rend déjà le
// bruteforce distant improbable, mais une IP autorisée peut être celle d'un
// réseau partagé — ou d'un poste compromis.

type Limiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	max      int
	window   time.Duration
}

func NewLimiter(max int, window time.Duration) *Limiter {
	return &Limiter{attempts: map[string][]time.Time{}, max: max, window: window}
}

// Allow enregistre une tentative et dit si elle est permise.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-l.window)
	kept := l.attempts[key][:0]
	for _, t := range l.attempts[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.max {
		l.attempts[key] = kept
		return false
	}
	l.attempts[key] = append(kept, now)
	return true
}

func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	delete(l.attempts, key)
	l.mu.Unlock()
}
