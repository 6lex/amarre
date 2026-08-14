package web

import (
	"fmt"
	"html/template"
	"time"
)

var funcs = template.FuncMap{
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
