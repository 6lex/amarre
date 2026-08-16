package collector

import (
	"sort"
	"time"

	"github.com/6lex/amarre/internal/store"
)

// ── Fenêtres ────────────────────────────────────────────────────────────
//
// La largeur des cases est le premier critère : une frise de 336 cases sur
// 700 pixels donne 2 pixels par case, où l'on ne distingue rien. On choisit
// donc le pas de regroupement pour que chaque case reste visible, quitte à
// perdre en finesse sur les longues fenêtres.

type Window struct {
	Key      string
	Label    string
	Duration time.Duration
	Bucket   time.Duration
	Format   string
}

var Windows = []Window{
	{"24h", "24 heures", 24 * time.Hour, time.Hour, "15h"},
	{"7j", "7 jours", 7 * 24 * time.Hour, 4 * time.Hour, "02/01"},
	{"14j", "14 jours", 14 * 24 * time.Hour, 6 * time.Hour, "02/01"},
}

func WindowByKey(k string) Window {
	for _, w := range Windows {
		if w.Key == k {
			return w
		}
	}
	return Windows[0]
}

// Cell est une case de la frise.
type Cell struct {
	From    time.Time
	State   string // ok | warn | crit | unknown
	Samples int
	Title   string
}

// Row est la frise d'un hôte.
type Row struct {
	Name                    string
	Cells                   []Cell
	OKs, Warns, Crits, Gaps int
	Coverage                int // pourcentage d'intervalles observés
}

// Episode est une période continue hors du normal. C'est le contenu utile de
// la page : « quand, combien de temps, pourquoi » — une frise colorée seule
// ne répond à aucune des trois.
type Episode struct {
	Host     string
	Start    time.Time
	End      time.Time
	Ongoing  bool
	State    string
	Cause    string
	Duration time.Duration
}

// Axis est une graduation.
type Axis struct {
	Index int
	Label string
}

type TimelineData struct {
	Window   Window
	Rows     []Row
	Axis     []Axis
	Episodes []Episode
	Buckets  int
	// Depuis date la première mesure connue : une frise vide doit se lire
	// « pas encore de données » et non « tout va mal ».
	Depuis    time.Time
	Mesures   int
	Tronquee  bool // la fenêtre demandée dépasse l'historique disponible
}

// Timeline compose la page d'historique.
func (c *Collector) Timeline(key string) (*TimelineData, error) {
	w := WindowByKey(key)
	first, _, n, err := c.st.HealthCoverage()
	if err != nil {
		return nil, err
	}

	end := time.Now().Truncate(w.Bucket).Add(w.Bucket)
	start := end.Add(-w.Duration)
	buckets := int(w.Duration / w.Bucket)

	td := &TimelineData{Window: w, Buckets: buckets, Depuis: first, Mesures: n}
	if !first.IsZero() && first.After(start) {
		td.Tronquee = true
	}

	// Graduations : environ une tous les huit intervalles, pour éviter que
	// les étiquettes ne se chevauchent.
	step := buckets / 8
	if step < 1 {
		step = 1
	}
	for i := 0; i < buckets; i += step {
		td.Axis = append(td.Axis, Axis{Index: i, Label: start.Add(time.Duration(i) * w.Bucket).Format(w.Format)})
	}

	rank := map[string]int{"unknown": 0, "ok": 1, "warn": 2, "crit": 3}
	name := map[string]string{"ok": "tout va bien", "warn": "à surveiller",
		"crit": "critique", "unknown": "aucune mesure"}

	for _, hc := range c.cfg.Hosts {
		if hc.Disabled {
			continue
		}
		pts, err := c.st.HealthSeries(hc.Name, start)
		if err != nil {
			return nil, err
		}
		r := Row{Name: hc.Name, Cells: make([]Cell, buckets)}
		for i := range r.Cells {
			from := start.Add(time.Duration(i) * w.Bucket)
			r.Cells[i] = Cell{From: from, State: "unknown",
				Title: from.Format("02/01 15h04") + " — aucune mesure"}
		}
		for _, p := range pts {
			i := int(p.At.Sub(start) / w.Bucket)
			if i < 0 || i >= buckets {
				continue
			}
			cell := &r.Cells[i]
			cell.Samples++
			// Le pire état de l'intervalle l'emporte : une panne de dix
			// minutes ne doit pas disparaître derrière trois relevés sains.
			if rank[p.State] > rank[cell.State] {
				cell.State = p.State
				cell.Title = cell.From.Format("02/01 15h04") + " — " + name[p.State]
				if p.Summary != "" {
					cell.Title += " : " + p.Summary
				}
			}
		}
		for _, cl := range r.Cells {
			switch cl.State {
			case "ok":
				r.OKs++
			case "warn":
				r.Warns++
			case "crit":
				r.Crits++
			default:
				r.Gaps++
			}
		}
		if buckets > 0 {
			r.Coverage = (buckets - r.Gaps) * 100 / buckets
		}
		td.Rows = append(td.Rows, r)
		td.Episodes = append(td.Episodes, episodes(hc.Name, pts)...)
	}

	// Le plus récent en premier : on cherche presque toujours ce qui vient
	// de se passer, pas ce qui s'est passé il y a douze jours.
	sort.Slice(td.Episodes, func(i, j int) bool {
		return td.Episodes[i].Start.After(td.Episodes[j].Start)
	})
	sort.SliceStable(td.Rows, func(i, j int) bool {
		if td.Rows[i].Crits != td.Rows[j].Crits {
			return td.Rows[i].Crits > td.Rows[j].Crits
		}
		if td.Rows[i].Warns != td.Rows[j].Warns {
			return td.Rows[i].Warns > td.Rows[j].Warns
		}
		return td.Rows[i].Name < td.Rows[j].Name
	})
	return td, nil
}

// episodes extrait les périodes continues hors du normal.
//
// Un épisode se termine au premier relevé sain — pas à la première case d'une
// couleur différente : agréger d'abord effacerait les épisodes plus courts que
// l'intervalle de regroupement.
func episodes(host string, pts []store.HealthPoint) []Episode {
	var out []Episode
	var cur *Episode
	for _, p := range pts {
		if p.State == "ok" || p.State == "unknown" {
			if cur != nil {
				cur.End = p.At
				cur.Duration = cur.End.Sub(cur.Start)
				out = append(out, *cur)
				cur = nil
			}
			continue
		}
		if cur == nil {
			cur = &Episode{Host: host, Start: p.At, State: p.State, Cause: p.Summary}
			continue
		}
		// Un épisode qui s'aggrave garde son début mais change de niveau.
		if p.State == "crit" && cur.State != "crit" {
			cur.State = "crit"
			cur.Cause = p.Summary
		}
		if cur.Cause == "" {
			cur.Cause = p.Summary
		}
	}
	if cur != nil {
		cur.End = time.Now()
		cur.Duration = cur.End.Sub(cur.Start)
		cur.Ongoing = true
		out = append(out, *cur)
	}
	return out
}
