package collector

import (
	"sort"
	"strings"
	"time"

	"github.com/6lex/amarre/internal/fleet"
)

// Sante rassemble, pour un hôte, les quelques signaux qui décident vraiment
// s'il peut encore être sauvegardé et restauré.
//
// Le parti pris est d'en afficher peu. Une page de supervision couverte de
// jauges ne se lit pas : on finit par ne plus rien y voir, et c'est ainsi
// qu'une panne réelle passe inaperçue au milieu de trente indicateurs verts.
type Sante struct {
	Name   string
	Crit   int
	Warn   int
	Health *fleet.Health
	Probe  *Probe
	View   HostView

	// Alertes est la liste des choses qui ne vont pas, formulées comme une
	// phrase actionnable. Vide = tout va bien, et c'est le cas normal.
	Alertes []Alerte
}

type Alerte struct {
	Niveau  string // "crit" | "warn"
	Sujet   string
	Detail  string
}

// Evaluate établit les alertes d'un hôte à partir de son relevé.
func (s *Sante) Evaluate(expect time.Duration) {
	h, p := s.Health, s.Probe
	add := func(n, sujet, detail string) {
		s.Alertes = append(s.Alertes, Alerte{Niveau: n, Sujet: sujet, Detail: detail})
	}

	// ── Sauvegarde ───────────────────────────────────────────────────────
	switch s.View.State {
	case StateOverdue:
		add("crit", "Sauvegarde en retard",
			"Aucun snapshot dans la fenêtre attendue de "+expect.String()+".")
	case StateNoBackup:
		add("crit", "Aucune sauvegarde", "Le dépôt ne contient aucun snapshot.")
	case StateUnknown:
		add("crit", "Hôte injoignable", s.View.Err)
	}

	if h != nil {
		bs := h.BackupStatus
		// Une sauvegarde dont l'intégrité n'est pas vérifiée est une
		// sauvegarde dont on ignore l'état.
		// Le libellé suit la CAUSE. Un dépôt verrouillé n'est pas un dépôt
		// abîmé : l'annoncer comme une corruption déclencherait une panique
		// inutile, et à force la prochaine vraie alerte ne serait plus crue.
		if bs.CheckAt > 0 && !bs.CheckOK {
			switch checkKind(bs.CheckKind, bs.CheckError) {
			case "verrou":
				add("warn", "Vérification impossible : dépôt verrouillé",
					"Un verrou orphelin bloque le contrôle. Le bouton « Déverrouiller » le retire ; rien n'indique une corruption.")
			case "absent":
				add("crit", "Dépôt introuvable au moment du contrôle", bs.CheckError)
			case "indetermine":
				add("warn", "Vérification structurelle en échec",
					"Cause non déterminée : "+bs.CheckError)
			default:
				add("crit", "Intégrité structurelle en échec", bs.CheckError)
			}
		}
		if bs.DeepAt > 0 && !bs.DeepOK {
			switch checkKind(bs.DeepKind, bs.DeepError) {
			case "verrou":
				add("warn", "Relecture impossible : dépôt verrouillé",
					"La vérification approfondie n'a pas pu démarrer. Ce n'est pas un signe de corruption.")
			case "absent":
				add("crit", "Dépôt introuvable à la relecture", bs.DeepError)
			case "motdepasse":
				add("crit", "Mot de passe de dépôt refusé", "Le dépôt existe mais ne s'ouvre pas.")
			case "indetermine":
				add("warn", "Relecture en échec",
					"Cause non déterminée, relevé antérieur au diagnostic détaillé : "+bs.DeepError)
			default:
				add("crit", "Corruption détectée à la relecture", bs.DeepError)
			}
		}
		if bs.CheckAt == 0 {
			add("warn", "Intégrité jamais vérifiée",
				"Aucune vérification depuis le raccordement de cet hôte.")
		}
		for name, t := range h.Timers {
			if !t.Active {
				add("crit", "Planification désactivée",
					name+" n'est pas actif : la sauvegarde a cessé d'exister.")
			}
		}

		// ── Capacité ─────────────────────────────────────────────────────
		// Un disque plein casse le dump SQL AVANT la sauvegarde, donc sans
		// qu'aucun snapshot manquant ne le signale.
		for _, f := range h.Filesystems {
			switch {
			case f.Pct >= 92:
				add("crit", "Disque presque plein",
					f.Mount+" à "+itoa(f.Pct)+" % — la sauvegarde échouera avant d'écrire.")
			case f.Pct >= 85:
				add("warn", "Disque à surveiller", f.Mount+" à "+itoa(f.Pct)+" %.")
			}
		}
		if h.MemTotal > 0 && h.MemAvailable*10 < h.MemTotal {
			add("warn", "Mémoire disponible faible",
				"Moins de 10 % de mémoire réellement disponible.")
		}

		// ── Santé ────────────────────────────────────────────────────────
		if n := len(h.FailedUnits); n > 0 {
			add("crit", "Unité systemd en échec", join(h.FailedUnits))
		}
		if h.OOM7d > 0 {
			add("warn", "Processus tués faute de mémoire",
				itoa(h.OOM7d)+" occurrences sur 7 jours — un OOM pendant une sauvegarde laisse un verrou orphelin.")
		}
		if h.IOErrors7d > 0 {
			add("crit", "Erreurs d'entrée-sortie",
				itoa(h.IOErrors7d)+" sur 7 jours — vérifier le disque avant toute autre chose.")
		}

		// ── Système ──────────────────────────────────────────────────────
		if h.RebootRequired {
			add("warn", "Redémarrage requis",
				"Le système tourne sur du code qui n'est plus celui installé : "+join(h.RebootPackages))
		}
		if h.Updates.Security > 0 {
			add("warn", "Correctifs de sécurité en attente",
				itoa(h.Updates.Security)+" paquets.")
		}
		if eol, ok := h.EOLDate(); ok {
			d := time.Until(eol)
			switch {
			case d < 0:
				add("crit", "Système en fin de vie",
					h.OS+" n'est plus maintenu depuis le "+eol.Format("02/01/2006")+".")
			case d < 90*24*time.Hour:
				add("crit", "Fin de support imminente",
					h.OS+" cesse d'être maintenu le "+eol.Format("02/01/2006")+".")
			case d < 180*24*time.Hour:
				add("warn", "Fin de support approchante",
					h.OS+" jusqu'au "+eol.Format("02/01/2006")+".")
			}
		}
	} else {
		add("warn", "Relevé de santé indisponible",
			"L'hôte n'a pas encore répondu au relevé.")
	}

	// ── Disponibilité du site ────────────────────────────────────────────
	// Une sonde locale ne vaut pas une sonde externe, mais elle vaut mieux que
	// rien quand le site est filtré par IP.
	if h != nil && h.LocalProbe != nil && h.LocalProbe.URL != "" {
		lp := h.LocalProbe
		if !lp.Up {
			// Le site est filtré par IP : « injoignable » serait faux, il est
			// joignable pour qui a le droit. Ce qu'on constate ici, c'est que
			// l'application elle-même ne répond plus.
			add("crit", "Application sans réponse",
				lp.URL+" — "+lp.Err+" (sondé depuis l'hôte, après "+itoa(lp.Attempts)+" tentatives)")
		}
	}
	if p != nil {
		if !p.Up {
			add("crit", "Site indisponible",
				p.URL+" — "+p.Err+" (après "+itoa(p.Attempts)+" tentatives espacées)")
		}
		if !p.CertExpiry.IsZero() {
			d := time.Until(p.CertExpiry)
			switch {
			case d < 0:
				add("crit", "Certificat expiré", "Depuis le "+p.CertExpiry.Format("02/01/2006")+".")
			case d < 15*24*time.Hour:
				add("crit", "Certificat proche de l'expiration",
					"Le "+p.CertExpiry.Format("02/01/2006")+" — le renouvellement automatique a-t-il échoué ?")
			}
		}
	}
}

// checkKind déduit la cause d'un échec quand elle n'est pas renseignée.
//
// Un état écrit avant que la distinction n'existe ne porte pas de « kind ».
// Retomber sur « corruption » par défaut serait le pire choix : c'est
// l'hypothèse la plus grave, annoncée sans preuve. On lit le message, et à
// défaut on reste évasif plutôt qu'alarmiste.
func checkKind(kind, msg string) string {
	if kind != "" {
		return kind
	}
	m := strings.ToLower(msg)
	switch {
	case strings.Contains(m, "lock") || strings.Contains(m, "verrou"):
		return "verrou"
	case strings.Contains(m, "does not exist") || strings.Contains(m, "unable to open repository"):
		return "absent"
	case strings.Contains(m, "wrong password") || strings.Contains(m, "mot de passe"):
		return "motdepasse"
	default:
		return "indetermine"
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func join(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ", "
		}
		out += v
	}
	return out
}

// SanteFleet compose la page de supervision.
func (c *Collector) SanteFleet() ([]Sante, error) {
	views, err := c.Fleet()
	if err != nil {
		return nil, err
	}
	out := make([]Sante, 0, len(views))
	for _, v := range views {
		s := Sante{Name: v.Name, View: v}
		var h fleet.Health
		if err := c.loadMeta(v.Name, "health", &h); err == nil {
			s.Health = &h
		}
		var p Probe
		if err := c.loadMeta(v.Name, "probe", &p); err == nil && p.URL != "" {
			s.Probe = &p
		}
		s.Evaluate(v.Expect)
		for _, a := range s.Alertes {
			if a.Niveau == "crit" {
				s.Crit++
			} else {
				s.Warn++
			}
		}
		out = append(out, s)
	}

	// Le plus grave en premier. Une page de supervision se lit du haut : ce
	// qui exige une action doit s'y trouver, pas au milieu d'une liste
	// alphabétique où l'ordre ne veut rien dire.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Crit != out[j].Crit {
			return out[i].Crit > out[j].Crit
		}
		if out[i].Warn != out[j].Warn {
			return out[i].Warn > out[j].Warn
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// State rend l'état global d'un hôte.
func (s *Sante) State() string {
	switch {
	case s.Crit > 0:
		return "crit"
	case s.Warn > 0:
		return "warn"
	default:
		return "ok"
	}
}

// Summary résume en une phrase ce qui ne va pas, pour l'historique.
func (s *Sante) Summary() string {
	if len(s.Alertes) == 0 {
		return ""
	}
	var parts []string
	for _, a := range s.Alertes {
		parts = append(parts, a.Sujet)
	}
	if len(parts) > 3 {
		parts = parts[:3]
	}
	return strings.Join(parts, " · ")
}
