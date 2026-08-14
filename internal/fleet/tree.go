package fleet

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"time"
)

// Tree est l'arborescence complète d'un snapshot, indexée par répertoire.
//
// Un snapshot est IMMUABLE : son arborescence ne changera jamais. La construire
// une fois puis la servir de mémoire est donc exact, pas approximatif — c'est
// ce qui distingue ce cache d'un cache de données vivantes.
type Tree struct {
	Snapshot string
	Built    time.Time
	Dirs     map[string][]Node // répertoire → enfants immédiats
	Count    int
}

// Children rend les enfants immédiats d'un répertoire.
func (t *Tree) Children(dir string) []Node {
	if dir != "/" {
		dir = path.Clean(dir)
	}
	return t.Dirs[dir]
}

// FetchTree récupère l'arborescence complète en un seul appel distant.
func (c *Client) FetchTree(ctx context.Context, addr, user string, port int, snapshot string) (*Tree, error) {
	if snapshot == "" {
		snapshot = "latest"
	}
	out, err := c.run(ctx, addr, user, port, "tree "+snapshot)
	if err != nil {
		return nil, err
	}

	t := &Tree{Snapshot: snapshot, Built: time.Now(), Dirs: map[string][]Node{}}
	sc := bufio.NewScanner(bytes.NewReader(out))
	// Une ligne peut être longue : chemin profond et nom de fichier étendu.
	sc.Buffer(make([]byte, 0, 128*1024), 8*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var n Node
		if err := json.Unmarshal(line, &n); err != nil || n.StructType != "node" {
			continue
		}
		parent := path.Dir(n.Path)
		t.Dirs[parent] = append(t.Dirs[parent], n)
		t.Count++
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("arborescence illisible : %w", err)
	}

	// Répertoires d'abord, puis ordre alphabétique : c'est la convention
	// qu'attend l'œil dans un explorateur de fichiers.
	for _, kids := range t.Dirs {
		sort.Slice(kids, func(i, j int) bool {
			if kids[i].IsDir() != kids[j].IsDir() {
				return kids[i].IsDir()
			}
			return kids[i].Name < kids[j].Name
		})
	}
	return t, nil
}
