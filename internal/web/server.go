// Package web sert la console.
//
// Modèle d'accès : filtrage IP, puis mot de passe Argon2id, puis TOTP. Le
// filtrage IP est appliqué AVANT toute autre chose — une requête d'une source
// non autorisée ne touche jamais le code d'authentification, et n'apprend
// même pas qu'il existe une console à cette adresse.
package web

import (
	"crypto/subtle"
	"embed"
	"errors"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/6lex/amarre/internal/auth"
	"github.com/6lex/amarre/internal/collector"
	"github.com/6lex/amarre/internal/config"
	"github.com/6lex/amarre/internal/store"
)

//go:embed templates/*.html
var templatesFS embed.FS

const (
	sessionCookie = "amarre_session"
	csrfCookie    = "amarre_csrf"
	sessionTTL    = 8 * time.Hour
)

type Server struct {
	cfg  *config.Config
	st   *store.Store
	col  *collector.Collector
	log  *slog.Logger
	tpl  *template.Template
	lim  *auth.Limiter
	mux  *http.ServeMux
}

func NewServer(cfg *config.Config, st *store.Store, col *collector.Collector, log *slog.Logger) (*Server, error) {
	tpl, err := template.New("").Funcs(funcs).ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg: cfg, st: st, col: col, log: log, tpl: tpl,
		lim: auth.NewLimiter(5, 15*time.Minute),
		mux: http.NewServeMux(),
	}
	s.routes()
	return s, nil
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET  /login", s.getLogin)
	s.mux.HandleFunc("POST /login", s.postLogin)
	s.mux.HandleFunc("POST /logout", s.requireAuth(s.postLogout))
	s.mux.HandleFunc("GET  /", s.requireAuth(s.getFleet))
	s.mux.HandleFunc("GET  /host/{name}", s.requireAuth(s.getHost))
	s.mux.HandleFunc("GET  /alerts", s.requireAuth(s.getAlerts))
	s.mux.HandleFunc("GET  /audit", s.requireAuth(s.getAudit))
}

// Handler enchaîne les protections, de la plus extérieure à la plus interne.
func (s *Server) Handler() http.Handler {
	return s.ipAllowlist(s.securityHeaders(s.mux))
}

// ─── Filtrage IP ────────────────────────────────────────────────────────

// ipAllowlist double la règle nftables. Deux barrières indépendantes : si
// l'une saute lors d'une manipulation du pare-feu, l'autre tient encore.
func (s *Server) ipAllowlist(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, err := remoteAddr(r)
		if err != nil || !s.cfg.IPAllowed(ip) {
			// 404 plutôt que 403 : ne pas confirmer qu'il y a quelque chose ici.
			s.log.Warn("source refusée", "ip", r.RemoteAddr, "chemin", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func remoteAddr(r *http.Request) (netip.Addr, error) {
	// Volontairement sans X-Forwarded-For : la console n'est pas censée
	// être derrière un proxy, et faire confiance à un en-tête client
	// contournerait tout le filtrage.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, err
	}
	return a.Unmap(), nil
}

// ─── En-têtes ───────────────────────────────────────────────────────────

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// Pas de script externe, pas de style externe, pas d'iframe.
		h.Set("Content-Security-Policy",
			"default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// ─── Authentification ───────────────────────────────────────────────────

type ctxUser struct{ *store.User }

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, _ := s.currentUser(r)
		if u == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func (s *Server) currentUser(r *http.Request) (*store.User, string) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil, ""
	}
	ip, err := remoteAddr(r)
	if err != nil {
		return nil, ""
	}
	u, err := s.st.SessionUser(c.Value, ip.String())
	if err != nil {
		return nil, ""
	}
	return u, c.Value
}

func (s *Server) getLogin(w http.ResponseWriter, r *http.Request) {
	if u, _ := s.currentUser(r); u != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	tok, err := auth.NewToken()
	if err != nil {
		http.Error(w, "erreur interne", http.StatusInternalServerError)
		return
	}
	s.setCookie(w, r, csrfCookie, tok, 30*time.Minute)
	s.render(w, "login.html", map[string]any{"CSRF": tok})
}

func (s *Server) postLogin(w http.ResponseWriter, r *http.Request) {
	ip, _ := remoteAddr(r)
	ipStr := ip.String()

	if err := r.ParseForm(); err != nil {
		http.Error(w, "requête invalide", http.StatusBadRequest)
		return
	}
	if !s.checkCSRF(r) {
		s.st.Audit("?", ipStr, "login", "", "csrf-invalide")
		http.Error(w, "jeton invalide", http.StatusForbidden)
		return
	}
	if !s.lim.Allow(ipStr) {
		s.st.Audit(r.FormValue("username"), ipStr, "login", "", "trop-de-tentatives")
		s.renderLoginError(w, r, "Trop de tentatives. Réessaie dans quinze minutes.")
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	u, err := s.st.UserByName(username)
	if err != nil {
		// Même traitement qu'un mot de passe faux : ne pas révéler
		// quels identifiants existent.
		if errors.Is(err, store.ErrNoUser) {
			_, _ = auth.HashPassword("comparaison-factice-pour-egaliser-le-temps")
		}
		s.st.Audit(username, ipStr, "login", "", "identifiants-invalides")
		s.renderLoginError(w, r, "Identifiants invalides.")
		return
	}
	ok, err := auth.VerifyPassword(r.FormValue("password"), u.PassHash)
	if err != nil || !ok {
		s.st.Audit(username, ipStr, "login", "", "identifiants-invalides")
		s.renderLoginError(w, r, "Identifiants invalides.")
		return
	}
	if u.TOTPSecret != "" && !auth.VerifyTOTP(u.TOTPSecret, strings.TrimSpace(r.FormValue("totp")), time.Now()) {
		s.st.Audit(username, ipStr, "login", "", "totp-invalide")
		s.renderLoginError(w, r, "Code à usage unique invalide.")
		return
	}

	tok, err := auth.NewToken()
	if err != nil {
		http.Error(w, "erreur interne", http.StatusInternalServerError)
		return
	}
	if err := s.st.CreateSession(tok, u.ID, ipStr, sessionTTL); err != nil {
		http.Error(w, "erreur interne", http.StatusInternalServerError)
		return
	}
	s.lim.Reset(ipStr)
	s.setCookie(w, r, sessionCookie, tok, sessionTTL)
	s.st.Audit(username, ipStr, "login", "", "succès")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) postLogout(w http.ResponseWriter, r *http.Request) {
	u, tok := s.currentUser(r)
	if !s.checkCSRF(r) {
		http.Error(w, "jeton invalide", http.StatusForbidden)
		return
	}
	_ = s.st.DeleteSession(tok)
	ip, _ := remoteAddr(r)
	if u != nil {
		s.st.Audit(u.Username, ip.String(), "logout", "", "succès")
	}
	s.setCookie(w, r, sessionCookie, "", -time.Hour)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ─── CSRF ───────────────────────────────────────────────────────────────

func (s *Server) checkCSRF(r *http.Request) bool {
	c, err := r.Cookie(csrfCookie)
	if err != nil {
		return false
	}
	got := r.FormValue("csrf")
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(got)) == 1
}

func (s *Server) setCookie(w http.ResponseWriter, r *http.Request, name, val string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    val,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})
}

// ─── Vues ───────────────────────────────────────────────────────────────

func (s *Server) getFleet(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.col.Fleet()
	if err != nil {
		http.Error(w, "erreur interne", http.StatusInternalServerError)
		return
	}
	u, _ := s.currentUser(r)
	csrf, _ := auth.NewToken()
	s.setCookie(w, r, csrfCookie, csrf, 30*time.Minute)

	totals := collector.Sum(hosts)
	spark := map[string][]int64{}
	for _, h := range hosts {
		hist, err := s.st.History(h.Name, 20)
		if err != nil {
			continue
		}
		var vals []int64
		for _, c := range hist {
			vals = append(vals, c.SizeBytes)
		}
		spark[h.Name] = vals
	}
	s.render(w, "fleet.html", map[string]any{
		"Hosts": hosts, "User": u, "CSRF": csrf, "Totals": totals,
		"Spark": spark, "Now": time.Now(),
	})
}

func (s *Server) getHost(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	u, _ := s.currentUser(r)
	csrf, _ := auth.NewToken()
	s.setCookie(w, r, csrfCookie, csrf, 30*time.Minute)

	// Tout est demandé à la volée à l'hôte : la console ne conserve ni
	// arborescence ni policy, elle ne fait que les relayer.
	d, err := s.col.HostDetail(r.Context(), name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ip, _ := remoteAddr(r)
	s.st.Audit(u.Username, ip.String(), "consultation", name, "succès")
	s.render(w, "host.html", map[string]any{"D": d, "User": u, "CSRF": csrf})
}

func (s *Server) getAlerts(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.col.Fleet()
	if err != nil {
		http.Error(w, "erreur interne", http.StatusInternalServerError)
		return
	}
	var firing []collector.HostView
	for _, h := range hosts {
		if h.State != collector.StateOK {
			firing = append(firing, h)
		}
	}
	u, _ := s.currentUser(r)
	csrf, _ := auth.NewToken()
	s.setCookie(w, r, csrfCookie, csrf, 30*time.Minute)
	s.render(w, "alerts.html", map[string]any{
		"Firing": firing, "Hosts": hosts, "User": u, "CSRF": csrf})
}

func (s *Server) getAudit(w http.ResponseWriter, r *http.Request) {
	entries, err := s.st.RecentAudit(200)
	if err != nil {
		http.Error(w, "erreur interne", http.StatusInternalServerError)
		return
	}
	u, _ := s.currentUser(r)
	csrf, _ := auth.NewToken()
	s.setCookie(w, r, csrfCookie, csrf, 30*time.Minute)
	s.render(w, "audit.html", map[string]any{"Entries": entries, "User": u, "CSRF": csrf})
}

func (s *Server) renderLoginError(w http.ResponseWriter, r *http.Request, msg string) {
	tok, _ := auth.NewToken()
	s.setCookie(w, r, csrfCookie, tok, 30*time.Minute)
	w.WriteHeader(http.StatusUnauthorized)
	s.render(w, "login.html", map[string]any{"CSRF": tok, "Error": msg})
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tpl.ExecuteTemplate(w, name, data); err != nil {
		s.log.Error("rendu impossible", "gabarit", name, "erreur", err)
	}
}
