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
	"net/url"
	"strings"
	"time"

	"github.com/6lex/amarre/internal/auth"
	"github.com/6lex/amarre/internal/collector"
	"github.com/6lex/amarre/internal/config"
	"github.com/6lex/amarre/internal/fleet"
	"github.com/6lex/amarre/internal/store"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS

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
	// Fragment d'arborescence : renvoie le listing seul, pour un
	// remplacement partiel côté navigateur.
	s.mux.HandleFunc("GET  /host/{name}/tree", s.requireAuth(s.getTreeFragment))
	s.mux.Handle("GET /static/", http.StripPrefix("/", http.FileServerFS(staticFS)))
	s.mux.HandleFunc("GET  /alerts", s.requireAuth(s.getAlerts))
	s.mux.HandleFunc("GET  /sante", s.requireAuth(s.getSante))
	// L'explorateur a rejoint la fiche d'hôte : tout ce qui concerne un
	// serveur se lit au même endroit. La route est conservée pour ne pas
	// casser un signet.
	s.mux.HandleFunc("GET  /explorer", s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if h := r.URL.Query().Get("host"); h != "" {
			http.Redirect(w, r, "/host/"+h, http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}))
	s.mux.HandleFunc("POST /host/{name}/action", s.requireAuth(s.postAction))
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
		// script-src 'self' autorise UNIQUEMENT les fichiers servis par la
		// console. Toujours aucun script en ligne, aucun eval, aucun code
		// tiers : la relâche est d'un cran, pas d'un ordre de grandeur.
		h.Set("Content-Security-Policy",
			"default-src 'none'; script-src 'self'; connect-src 'self'; "+
				"style-src 'unsafe-inline'; img-src data:; form-action 'self'; "+
				"frame-ancestors 'none'; base-uri 'none'")
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
	csrfTok, err := auth.NewToken()
	if err != nil {
		http.Error(w, "erreur interne", http.StatusInternalServerError)
		return
	}
	if err := s.st.CreateSession(tok, u.ID, ipStr, csrfTok, sessionTTL); err != nil {
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

// checkCSRF compare le jeton du formulaire à celui de la session. Avant la
// connexion, la session n'existe pas encore : on retombe sur le cookie.
func (s *Server) checkCSRF(r *http.Request) bool {
	got := r.FormValue("csrf")
	if got == "" {
		return false
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		if want, err := s.st.SessionCSRF(c.Value); err == nil && want != "" {
			return subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
		}
	}
	c, err := r.Cookie(csrfCookie)
	if err != nil {
		return false
	}
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
	d := s.page("parc", r, w)
	d["Hosts"] = hosts
	d["Totals"] = collector.Sum(hosts)
	d["Now"] = time.Now()
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
	d["Spark"] = spark
	s.render(w, "fleet.html", d)
}

func (s *Server) getHost(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	d := s.page("parc", r, w)
	det, err := s.col.HostDetail(r.Context(), name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// Volontairement AUCUNE entrée d'audit pour l'affichage d'une fiche ni
	// pour la navigation dans l'arborescence.
	//
	// Un journal doit dire ce qui a été FAIT, pas ce qui a été regardé :
	// noyées sous une entrée par clic et par rafraîchissement, les opérations
	// réelles deviennent introuvables. Et un rafraîchissement de navigateur
	// n'est pas une consultation — l'entrée serait fausse en plus d'être
	// inutile.
	//
	// La trace de qui a demandé quoi existe toujours, au bon endroit :
	// /var/log/amarre-shim.log sur l'hôte enregistre chaque requête reçue
	// avec son IP source. Un attaquant qui prendrait la console ne peut pas
	// l'effacer, ce qui en fait une preuve plus solide que la nôtre.

	// L'arborescence n'est PAS récupérée ici.
	//
	// Elle coûte un appel distant de 2,5 s — 8 s sur un gros Moodle — et
	// bloquait l'affichage de toute la fiche pour une donnée que l'opérateur
	// ne consulte pas systématiquement. Le bloc est rendu vide avec l'adresse
	// du fragment, et le navigateur va le chercher après coup.
	//
	// Sans JavaScript, le bloc affiche un lien : la page reste utilisable,
	// simplement l'arborescence demande un clic.
	snap := r.URL.Query().Get("snap")
	if snap == "" && len(det.Snapshots) > 0 {
		snap = det.Snapshots[0].ID
	}
	path := r.URL.Query().Get("path")
	if path == "" {
		path = "/"
	}
	d["Snap"] = snap
	d["Path"] = path
	d["Crumbs"] = crumbs(path)
	d["TreeDeferred"] = true

	for _, e := range det.Policy {
		switch e.Key {
		case "SHIM_ALLOW_RESTORE":
			d["CanRestore"] = e.Allowed
		case "SHIM_STREAM_TO_CONSOLE":
			d["CanStream"] = e.Allowed
		}
	}

	d["D"] = det
	d["Actions"], _ = s.st.ActionsFor(name, 6)
	d["Journal"], _ = s.st.AuditFor(name, 25)
	d["Done"] = r.URL.Query().Get("done")
	s.render(w, "host.html", d)
}

// getTreeFragment rend le seul listing, sans la coque de la page.
func (s *Server) getTreeFragment(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	snap := r.URL.Query().Get("snap")
	path := r.URL.Query().Get("path")
	if path == "" {
		path = "/"
	}
	d := map[string]any{"Host": name, "Snap": snap, "Path": path, "Crumbs": crumbs(path)}
	nodes, _, err := s.col.Browse(r.Context(), name, snap, path)
	if err != nil {
		d["BrowseErr"] = err.Error()
		nodes = []fleet.Node{}
	}
	d["Nodes"] = nodes
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tpl.ExecuteTemplate(w, "tree.html", d); err != nil {
		s.log.Error("rendu impossible", "gabarit", "tree.html", "erreur", err)
	}
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
	d := s.page("alertes", r, w)
	d["Firing"] = firing
	d["Hosts"] = hosts
	s.render(w, "alerts.html", d)
}

// page fabrique les données que le rail attend, communes à tous les écrans.
func (s *Server) page(name string, r *http.Request, w http.ResponseWriter) map[string]any {
	u, tok := s.currentUser(r)
	csrf, _ := s.st.SessionCSRF(tok)
	if csrf == "" {
		// Session ouverte avant que le jeton ne soit porté par la session :
		// on lui en attache un plutôt que de refuser ses formulaires.
		csrf, _ = auth.NewToken()
		_ = s.st.SetSessionCSRF(tok, csrf)
	}
	hosts, _ := s.col.Fleet()
	alerts := 0
	for _, h := range hosts {
		if h.State != collector.StateOK {
			alerts++
		}
	}
	// État de santé agrégé, pour la pastille du rail. Lu depuis la base,
	// donc négligeable : aucun hôte n'est interrogé.
	sc, sw := 0, 0
	if sante, err := s.col.SanteFleet(); err == nil {
		for _, h := range sante {
			for _, a := range h.Alertes {
				if a.Niveau == "crit" {
					sc++
				} else {
					sw++
				}
			}
		}
	}

	return map[string]any{
		"Page": name, "User": u, "CSRF": csrf,
		"NHosts": len(hosts), "NAlerts": alerts,
		"SanteCrit": sc, "SanteWarn": sw,
	}
}

func (s *Server) postAction(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || !s.checkCSRF(r) {
		http.Error(w, "jeton invalide", http.StatusForbidden)
		return
	}
	name := r.PathValue("name")
	verb := r.FormValue("verb")
	u, _ := s.currentUser(r)
	ip, _ := remoteAddr(r)
	if err := s.col.Action(name, verb, u.Username, ip.String()); err != nil {
		s.st.Audit(u.Username, ip.String(), verb, name, "refusé : "+err.Error())
		http.Redirect(w, r, "/host/"+name+"?busy="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	// L'accusé de réception passe par l'URL : sans script ni stockage de
	// message côté serveur, c'est le moyen le plus simple de dire à
	// l'opérateur que sa demande est partie.
	http.Redirect(w, r, "/host/"+name+"?done="+url.QueryEscape(verb), http.StatusSeeOther)
}

// Crumb est un segment de fil d'Ariane.
type Crumb struct{ Name, Path string }

func crumbs(p string) []Crumb {
	out := []Crumb{{Name: "/", Path: "/"}}
	cur := ""
	for _, seg := range strings.Split(strings.Trim(p, "/"), "/") {
		if seg == "" {
			continue
		}
		cur += "/" + seg
		out = append(out, Crumb{Name: seg, Path: cur})
	}
	return out
}

func (s *Server) getExplorer(w http.ResponseWriter, r *http.Request) {
	data := s.page("explorer", r, w)
	u := data["User"].(*store.User)

	host := r.URL.Query().Get("host")
	snap := r.URL.Query().Get("snap")
	path := r.URL.Query().Get("path")
	if path == "" {
		path = "/"
	}

	data["AllHosts"] = s.col.Hosts()
	data["Host"] = host
	data["Snap"] = snap
	data["Path"] = path
	data["Crumbs"] = crumbs(path)
	if host == "" {
		s.render(w, "explorer.html", data)
		return
	}

	// Tout est demandé à l'hôte au moment de l'affichage. La console ne
	// conserve aucune arborescence : même sans clé de dépôt, un cache de
	// chemins en clair serait une fuite d'information sur le contenu.
	if snaps, err := s.col.SnapshotsOf(r.Context(), host); err == nil {
		data["Snapshots"] = snaps
		if snap == "" && len(snaps) > 0 {
			snap = snaps[0].ID
			data["Snap"] = snap
		}
	} else {
		data["Err"] = err.Error()
		s.render(w, "explorer.html", data)
		return
	}
	if pol, err := s.col.PolicyOf(r.Context(), host); err == nil {
		data["Policy"] = pol
		for _, e := range pol {
			switch e.Key {
			case "SHIM_ALLOW_RESTORE":
				data["CanRestore"] = e.Allowed
			case "SHIM_STREAM_TO_CONSOLE":
				data["CanStream"] = e.Allowed
			}
		}
	}
	// Nodes est TOUJOURS défini, même vide : un gabarit qui appelle len sur
	// une clé absente échoue au rendu, et la page part alors tronquée sans
	// que l'utilisateur comprenne pourquoi.
	nodes, _, err := s.col.Browse(r.Context(), host, snap, path)
	if err != nil {
		data["Err"] = err.Error()
		nodes = []fleet.Node{}
	}
	data["Nodes"] = nodes
	ip, _ := remoteAddr(r)
	s.st.Audit(u.Username, ip.String(), "navigation", host+":"+path, "succès")
	s.render(w, "explorer.html", data)
}

func (s *Server) getSante(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.col.SanteFleet()
	if err != nil {
		http.Error(w, "erreur interne", http.StatusInternalServerError)
		return
	}
	var crit, warn int
	for _, h := range hosts {
		for _, a := range h.Alertes {
			if a.Niveau == "crit" {
				crit++
			} else {
				warn++
			}
		}
	}
	d := s.page("sante", r, w)
	d["Hosts"] = hosts
	d["Crit"] = crit
	d["Warn"] = warn
	s.render(w, "sante.html", d)
}

func (s *Server) getAudit(w http.ResponseWriter, r *http.Request) {
	entries, err := s.st.RecentAudit(200)
	if err != nil {
		http.Error(w, "erreur interne", http.StatusInternalServerError)
		return
	}
	d := s.page("journal", r, w)
	d["Entries"] = entries
	s.render(w, "audit.html", d)
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
