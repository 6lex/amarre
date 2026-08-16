package collector

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/6lex/amarre/internal/config"
)

// Probe est le résultat d'une sonde de disponibilité HTTP.
type Probe struct {
	URL       string        `json:"url"`
	Up        bool          `json:"up"`
	Status    int           `json:"status"`
	Latency   time.Duration `json:"latency_ns"`
	Attempts  int           `json:"attempts"`
	Err       string        `json:"err"`
	CheckedAt time.Time     `json:"checked_at"`
	// CertExpiry date l'expiration du certificat TLS. Un certificat qui
	// expire rend le site inaccessible aussi sûrement qu'une panne, et
	// personne ne le voit venir.
	CertExpiry time.Time `json:"cert_expiry"`
}

// probeAttempts et probeSpacing constituent la temporisation anti-faux-positif.
//
// Une requête isolée qui échoue ne prouve rien : un rechargement de service,
// une microcoupure réseau, un pic de charge. On ne déclare une indisponibilité
// qu'après plusieurs échecs espacés — et un seul succès suffit à conclure que
// le site répond.
const (
	probeAttempts = 3
	probeSpacing  = 8 * time.Second
	probeTimeout  = 12 * time.Second
)

// probeHTTP interroge une page du site depuis la console, c'est-à-dire du
// dehors. Un hôte qui s'interroge lui-même ne prouve pas qu'il est joignable.
func (c *Collector) probeHTTP(ctx context.Context, h config.HostConfig) *Probe {
	if h.HTTPCheck == "" {
		return nil
	}
	want := h.HTTPExpect
	if want == 0 {
		want = 200
	}
	p := &Probe{URL: h.HTTPCheck, CheckedAt: time.Now()}

	client := &http.Client{
		Timeout: probeTimeout,
		// On ne suit pas les redirections : une redirection EST une réponse
		// valable, et la suivre masquerait un site qui renvoie vers une page
		// d'erreur hébergée ailleurs.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
			DisableKeepAlives: true,
		},
	}

	for i := 1; i <= probeAttempts; i++ {
		p.Attempts = i
		start := time.Now()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.HTTPCheck, nil)
		if err != nil {
			p.Err = err.Error()
			return p
		}
		req.Header.Set("User-Agent", "amarre/health")
		resp, err := client.Do(req)
		p.Latency = time.Since(start)
		if err == nil {
			p.Status = resp.StatusCode
			if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
				p.CertExpiry = resp.TLS.PeerCertificates[0].NotAfter
			}
			_ = resp.Body.Close()
			// Toute réponse HTTP du serveur prouve qu'il répond. On ne juge
			// « en défaut » que si le code diffère de celui attendu.
			if resp.StatusCode == want || (want == 200 && resp.StatusCode < 400) {
				p.Up = true
				p.Err = ""
				return p
			}
			p.Err = fmt.Sprintf("code %d, attendu %d", resp.StatusCode, want)
		} else {
			p.Err = err.Error()
		}
		if i < probeAttempts {
			select {
			case <-ctx.Done():
				return p
			case <-time.After(probeSpacing):
			}
		}
	}
	return p
}
