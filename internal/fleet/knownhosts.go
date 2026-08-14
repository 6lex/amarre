package fleet

import (
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// knownHostsCallback impose la vérification des clés d'hôte.
//
// Le fichier doit exister : le créer vide à la volée reviendrait à accepter
// silencieusement la première clé présentée, ce qui n'est pas un contrôle.
// On préfère un échec explicite au démarrage, avec la marche à suivre.
func knownHostsCallback(path string) (ssh.HostKeyCallback, error) {
	if path == "" {
		return nil, fmt.Errorf("known_hosts non configuré : la vérification des clés d'hôte est obligatoire")
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf(
			"known_hosts introuvable (%s). Le renseigner d'abord, par exemple :\n"+
				"  ssh-keyscan -H <hôte> >> %s\n"+
				"puis vérifier chaque empreinte auprès de l'hôte concerné", path, path)
	}
	cb, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("known_hosts illisible : %w", err)
	}
	return cb, nil
}
