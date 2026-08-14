// Package qr rend un QR code lisible dans un terminal.
//
// Rendu en demi-blocs : le caractère ▀ porte DEUX modules superposés — le
// module haut par sa couleur d'avant-plan, le module bas par son fond. Comme
// une cellule de terminal est environ deux fois plus haute que large, un
// module y occupe alors une largeur pour une demi-hauteur : le code reste
// carré, donc scannable, tout en tenant sur un écran de 80 colonnes.
//
// Un rendu naïf à deux colonnes par module doublerait la largeur et déborderait.
package qr

import (
	"fmt"
	"strings"

	"rsc.io/qr"
)

// Marge silencieuse. La norme en recommande 4 ; 2 suffit en pratique pour un
// scan à l'écran et économise 4 lignes et 4 colonnes, ce qui compte sur un
// terminal standard.
const quiet = 2

const (
	fgDark  = "\033[30m"
	fgLight = "\033[97m"
	bgDark  = "\033[40m"
	bgLight = "\033[107m"
	reset   = "\033[0m"
)

// Terminal encode s en QR code et rend une chaîne prête à afficher.
func Terminal(s string) (string, error) {
	code, err := qr.Encode(s, qr.M)
	if err != nil {
		return "", fmt.Errorf("encodage du QR code : %w", err)
	}
	n := code.Size
	total := n + 2*quiet

	// black(x, y) en coordonnées « avec marge », hors grille = clair.
	black := func(x, y int) bool {
		x -= quiet
		y -= quiet
		if x < 0 || y < 0 || x >= n || y >= n {
			return false
		}
		return code.Black(x, y)
	}

	var b strings.Builder
	for y := 0; y < total; y += 2 {
		for x := 0; x < total; x++ {
			up, low := black(x, y), black(x, y+1)
			switch {
			case up && low:
				b.WriteString(fgDark + bgDark)
			case up && !low:
				b.WriteString(fgDark + bgLight)
			case !up && low:
				b.WriteString(fgLight + bgDark)
			default:
				b.WriteString(fgLight + bgLight)
			}
			b.WriteString("▀")
		}
		b.WriteString(reset + "\n")
	}
	return b.String(), nil
}

// Dimensions rend la taille du rendu, pour prévenir si le terminal est étroit.
func Dimensions(s string) (cols, rows int, err error) {
	code, err := qr.Encode(s, qr.M)
	if err != nil {
		return 0, 0, err
	}
	total := code.Size + 2*quiet
	return total, (total + 1) / 2, nil
}
