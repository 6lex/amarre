package collector

import (
	"time"
)

// Cell est une heure de la frise.
type Cell struct {
	Hour  time.Time
	State string // ok | warn | crit | unknown
	Title string // texte au survol : l'état ne doit jamais tenir à la couleur seule
}

// Row est la frise d'un hôte.
type Row struct {
	Name  string
	Cells []Cell
	// Compteurs de la période, pour situer d'un coup d'œil.
	OKh, WarnH, CritH, GapH int
}

// DayMark repère un début de journée sur l'axe.
type DayMark struct {
	Index int
	Label string
}

// Timeline compose la frise d'état de tout le parc, heure par heure.
//
// Forme choisie : une frise d'état, pas une courbe. Un état n'est pas une
// grandeur — le tracer comme une ligne suggérerait des valeurs intermédiaires
// qui n'existent pas. Une case par heure, colorée, se lit d'un balayage.
//
// Chaque heure porte le PIRE état observé : une panne de dix minutes ne doit
// pas disparaître parce que les trois autres relevés de l'heure étaient bons.
func (c *Collector) Timeline(days int) ([]Row, []time.Time, []DayMark, error) {
	end := time.Now().Truncate(time.Hour).Add(time.Hour)
	start := end.Add(-time.Duration(days) * 24 * time.Hour)

	var hours []time.Time
	for t := start; t.Before(end); t = t.Add(time.Hour) {
		hours = append(hours, t)
	}

	var marks []DayMark
	for i, h := range hours {
		if h.Hour() == 0 {
			marks = append(marks, DayMark{Index: i, Label: h.Format("02/01")})
		}
	}

	var rows []Row
	for _, hc := range c.cfg.Hosts {
		if hc.Disabled {
			continue
		}
		hist, err := c.st.HourlyHistory(hc.Name, start)
		if err != nil {
			return nil, nil, nil, err
		}
		r := Row{Name: hc.Name}
		for _, h := range hours {
			st, ok := hist[h.Unix()]
			cell := Cell{Hour: h, State: "unknown",
				Title: h.Format("02/01 15h") + " — aucune donnée"}
			if ok {
				cell.State = st.State
				label := map[string]string{
					"ok": "tout va bien", "warn": "à surveiller",
					"crit": "critique", "unknown": "aucune donnée",
				}[st.State]
				cell.Title = h.Format("02/01 15h") + " — " + label
				if st.Summary != "" {
					cell.Title += " : " + st.Summary
				}
			}
			switch cell.State {
			case "ok":
				r.OKh++
			case "warn":
				r.WarnH++
			case "crit":
				r.CritH++
			default:
				r.GapH++
			}
			r.Cells = append(r.Cells, cell)
		}
		rows = append(rows, r)
	}
	return rows, hours, marks, nil
}
