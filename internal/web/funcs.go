package web

import (
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/6lex/amarre/internal/store"
)

// sparkSVG rend une courbe en SVG inline. Aucun script, aucune dépendance :
// la politique de sécurité de contenu de la console interdit tout code externe,
// donc les graphes doivent être du balisage pur.
func sparkSVG(vals []int64, w, h float64) template.HTML {
	if len(vals) < 2 {
		return template.HTML(`<span class="muted">—</span>`)
	}
	mx, mn := vals[0], vals[0]
	for _, v := range vals {
		if v > mx {
			mx = v
		}
		if v < mn {
			mn = v
		}
	}
	span := float64(mx - mn)
	if span == 0 {
		span = 1
	}
	step := w / float64(len(vals)-1)
	y := func(v int64) float64 { return h - 2 - (float64(v-mn)/span)*(h-5) }

	var b strings.Builder
	for i, v := range vals {
		if i == 0 {
			fmt.Fprintf(&b, "M%.1f %.1f", 0.0, y(v))
		} else {
			fmt.Fprintf(&b, " L%.1f %.1f", float64(i)*step, y(v))
		}
	}
	d := b.String()
	last := len(vals) - 1
	return template.HTML(fmt.Sprintf(
		`<svg width="%.0f" height="%.0f" viewBox="0 0 %.0f %.0f" preserveAspectRatio="none" `+
			`style="max-width:100%%" aria-hidden="true">`+
			`<path d="%s L%.1f %.0f L0 %.0f Z" fill="var(--accent)" opacity=".10"/>`+
			`<path d="%s" fill="none" stroke="var(--accent)" stroke-width="2" `+
			`stroke-linejoin="round" stroke-linecap="round" vector-effect="non-scaling-stroke"/>`+
			`<circle cx="%.1f" cy="%.1f" r="2.6" fill="var(--accent)" `+
			`stroke="var(--surface)" stroke-width="2"/></svg>`,
		w, h, w, h, d, w, h, h, d, float64(last)*step, y(vals[last])))
}

var funcs = template.FuncMap{
	"add": func(a, b int) int { return a + b },
	"pct": func(a, b int) string {
		if b == 0 {
			return "—"
		}
		return fmt.Sprintf("%.0f", float64(a)*100/float64(b))
	},
	// dict construit un contexte pour un sous-gabarit : le listing est rendu
	// à la fois dans la page complète et comme fragment autonome, à partir du
	// même code — sinon les deux divergent au premier changement.
	"dict": func(kv ...any) map[string]any {
		m := map[string]any{}
		for i := 0; i+1 < len(kv); i += 2 {
			if k, ok := kv[i].(string); ok {
				m[k] = kv[i+1]
			}
		}
		return m
	},
	"age": func(d time.Duration) string {
		switch {
		case d <= 0:
			return "—"
		case d < time.Minute:
			return "à l'instant"
		case d < time.Hour:
			return fmt.Sprintf("%d min", int(d.Minutes()))
		case d < 48*time.Hour:
			return fmt.Sprintf("%d h", int(d.Hours()))
		default:
			return fmt.Sprintf("%d j", int(d.Hours()/24))
		}
	},
	"bytes": func(n int64) string {
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
	},
	"stamp": func(t time.Time) string {
		if t.IsZero() {
			return "—"
		}
		return t.Local().Format("02/01 15:04")
	},
	"since": func(t time.Time) time.Duration {
		if t.IsZero() {
			return 0
		}
		return time.Since(t)
	},
	"join": func(ss []string) string { return strings.Join(ss, "  ") },
	// short tronque proprement : un message d'erreur SSH complet déborde de
	// n'importe quelle colonne. L'intégralité reste accessible en title.
	"short": func(n int, s string) string {
		r := []rune(s)
		if len(r) <= n {
			return s
		}
		return string(r[:n-1]) + "…"
	},
	"ratio": func(f float64) string {
		if f <= 0 {
			return "—"
		}
		return fmt.Sprintf("%.2f ×", f)
	},
	"sparkline":  func(vals []int64) template.HTML { return sparkSVG(vals, 84, 20) },
	"barChart":   barChart,
	"lineChart":  lineChart,
	"duration": func(d time.Duration) string {
		if d <= 0 {
			return "—"
		}
		if d < time.Minute {
			return fmt.Sprintf("%.0f s", d.Seconds())
		}
		return fmt.Sprintf("%d min %02d", int(d.Minutes()), int(d.Seconds())%60)
	},
	"sparklineFromChecks": func(cs []store.Check) template.HTML {
		vals := make([]int64, 0, len(cs))
		for _, c := range cs {
			vals = append(vals, c.SizeBytes)
		}
		return sparkSVG(vals, 640, 60)
	},
	// outcomeShort rend l'état en un mot : c'est lui qu'on lit en balayant
	// une colonne. Le détail complet vit dans la ligne dépliable.
	"outcomeShort": func(s string) string {
		switch {
		case s == "succès":
			return "succès"
		case s == "demandé":
			return "demandé"
		case strings.HasPrefix(s, "refusé"):
			return "refusé"
		case strings.HasPrefix(s, "échec"):
			return "échec"
		default:
			return "échec"
		}
	},
	"outcomeClass": func(s string) string {
		switch {
		case s == "succès":
			return "o-ok"
		case s == "demandé":
			return "o-mute"
		case strings.HasPrefix(s, "refusé"):
			return "o-warn"
		default:
			return "o-crit"
		}
	},
	"stateLabel": func(s string) string {
		switch s {
		case "ok":
			return "à jour"
		case "overdue":
			return "échéance dépassée"
		case "nobackup":
			return "aucune sauvegarde"
		default:
			return "injoignable"
		}
	},
}
