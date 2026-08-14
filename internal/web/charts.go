package web

import (
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/6lex/amarre/internal/fleet"
)

// Les graphes sont du SVG produit côté serveur : la politique de sécurité de
// contenu de la console interdit tout script, donc aucune bibliothèque de
// visualisation n'est utilisable. C'est une contrainte assumée — un graphe
// statique se lit aussi bien, et la page ne dépend de rien.

const (
	chW, chH = 320.0, 118.0
	padL     = 34.0
	padR     = 6.0
	padT     = 8.0
	padB     = 20.0
)

func axes(b *strings.Builder, max float64, fmtV func(float64) string) {
	iw, ih := chW-padL-padR, chH-padT-padB
	for i := 0; i <= 2; i++ {
		y := padT + ih - ih*float64(i)/2
		fmt.Fprintf(b, `<line x1="%.0f" y1="%.1f" x2="%.0f" y2="%.1f" stroke="var(--grid)" stroke-width="1"/>`,
			padL, y, chW-padR, y)
		fmt.Fprintf(b, `<text x="%.1f" y="%.1f" text-anchor="end" font-family="ui-monospace,monospace" `+
			`font-size="9" fill="var(--ink-3)">%s</text>`, padL-5, y+3, fmtV(max*float64(i)/2))
	}
	_ = iw
}

// BarChart : volume réellement ajouté au dépôt par sauvegarde.
func barChart(snaps []fleet.Snapshot) template.HTML {
	if len(snaps) == 0 {
		return template.HTML(`<span class="muted">Pas de données.</span>`)
	}
	iw, ih := chW-padL-padR, chH-padT-padB
	var max float64
	for _, s := range snaps {
		if float64(s.Packed) > max {
			max = float64(s.Packed)
		}
	}
	if max == 0 {
		max = 1
	}
	max *= 1.12

	var b strings.Builder
	fmt.Fprintf(&b, `<svg viewBox="0 0 %.0f %.0f" style="width:100%%;height:auto" role="img" `+
		`aria-label="Volume ajouté au dépôt par sauvegarde">`, chW, chH)
	axes(&b, max, func(v float64) string { return fmt.Sprintf("%.0f", v/1e6) })

	bw := iw / float64(len(snaps))
	const gap, r = 2.0, 4.0
	for i, s := range snaps {
		h := (float64(s.Packed) / max) * ih
		if h < 2 {
			h = 2
		}
		x := padL + float64(i)*bw + gap/2
		w := bw - gap
		if w < 1 {
			w = 1
		}
		y := padT + ih - h
		rr := r
		if rr > h {
			rr = h
		}
		if rr > w/2 {
			rr = w / 2
		}
		// Extrémité arrondie côté valeur, pied ancré sur la ligne de base.
		fmt.Fprintf(&b, `<path d="M%.1f %.1f L%.1f %.1f Q%.1f %.1f %.1f %.1f L%.1f %.1f `+
			`Q%.1f %.1f %.1f %.1f L%.1f %.1f Z" fill="var(--accent)" opacity="%.2f"><title>%s — %s</title></path>`,
			x, y+h, x, y+rr, x, y, x+rr, y, x+w-rr, y, x+w, y, x+w, y+rr, x+w, y+h,
			mapOpacity(s.Packed, max), s.Time.Local().Format("02/01 15:04"), humanBytes(s.Packed))
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

func mapOpacity(v int64, max float64) float64 {
	if float64(v) >= max/1.12*0.999 {
		return 1
	}
	return 0.72
}

// lineChart : durée de chaque sauvegarde.
func lineChart(snaps []fleet.Snapshot) template.HTML {
	if len(snaps) < 2 {
		return template.HTML(`<span class="muted">Deux sauvegardes sont nécessaires pour une courbe.</span>`)
	}
	iw, ih := chW-padL-padR, chH-padT-padB
	var max float64
	for _, s := range snaps {
		if s.Duration.Seconds() > max {
			max = s.Duration.Seconds()
		}
	}
	if max == 0 {
		max = 1
	}
	max *= 1.15

	step := iw / float64(len(snaps)-1)
	x := func(i int) float64 { return padL + float64(i)*step }
	y := func(d time.Duration) float64 { return padT + ih - (d.Seconds()/max)*ih }

	var b strings.Builder
	fmt.Fprintf(&b, `<svg viewBox="0 0 %.0f %.0f" style="width:100%%;height:auto" role="img" `+
		`aria-label="Durée des sauvegardes">`, chW, chH)
	axes(&b, max, func(v float64) string { return fmt.Sprintf("%.0fs", v) })

	var path strings.Builder
	for i, s := range snaps {
		if i == 0 {
			fmt.Fprintf(&path, "M%.1f %.1f", x(i), y(s.Duration))
		} else {
			fmt.Fprintf(&path, " L%.1f %.1f", x(i), y(s.Duration))
		}
	}
	d := path.String()
	fmt.Fprintf(&b, `<path d="%s L%.1f %.1f L%.1f %.1f Z" fill="var(--accent)" opacity=".09"/>`,
		d, x(len(snaps)-1), padT+ih, padL, padT+ih)
	fmt.Fprintf(&b, `<path d="%s" fill="none" stroke="var(--accent)" stroke-width="2" `+
		`stroke-linejoin="round" stroke-linecap="round"/>`, d)
	for i, s := range snaps {
		fmt.Fprintf(&b, `<circle cx="%.1f" cy="%.1f" r="%s" fill="var(--accent)" `+
			`stroke="var(--surface)" stroke-width="2"><title>%s — %s</title></circle>`,
			x(i), y(s.Duration), map[bool]string{true: "3.6", false: "2.4"}[i == len(snaps)-1],
			s.Time.Local().Format("02/01 15:04"), s.Duration.Round(time.Second))
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

func humanBytes(n int64) string {
	const u = 1024
	if n < u {
		return fmt.Sprintf("%d o", n)
	}
	div, exp := int64(u), 0
	for m := n / u; m >= u; m /= u {
		div *= u
		exp++
	}
	return fmt.Sprintf("%.1f %co", float64(n)/float64(div), "kMGTP"[exp])
}
