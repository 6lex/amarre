// Amarre — console de sauvegarde restic de parc, sans centralisation des clés.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/6lex/amarre/internal/auth"
	"github.com/6lex/amarre/internal/collector"
	"github.com/6lex/amarre/internal/config"
	"github.com/6lex/amarre/internal/fleet"
	"github.com/6lex/amarre/internal/store"
)

var version = "dev"

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(log, os.Args[2:])
	case "useradd":
		err = cmdUserAdd(os.Args[2:])
	case "version":
		fmt.Println("amarre", version)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		log.Error("échec", "erreur", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `amarre %s — console de sauvegarde restic de parc

  amarre serve   --config amarre.yml
  amarre useradd --config amarre.yml --user <nom>
  amarre version
`, version)
}

func cmdServe(log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", "amarre.yml", "chemin de la configuration")
	knownHosts := fs.String("known-hosts", "", "fichier known_hosts (défaut : ~/.ssh/known_hosts)")
	_ = fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if len(cfg.AllowedCIDRs) == 0 {
		// Refus de démarrer plutôt que d'ouvrir à tous : sur cette machine,
		// un défaut permissif donnerait accès à la clé du parc.
		return errors.New("allowed_cidrs est vide : la console refuserait toute requête. " +
			"Déclarer au moins une source autorisée")
	}
	kh := *knownHosts
	if kh == "" {
		kh = os.Getenv("HOME") + "/.ssh/known_hosts"
	}

	st, err := store.Open(cfg.StateDB)
	if err != nil {
		return err
	}
	defer st.Close()

	n, err := st.CountUsers()
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("aucun compte. Créer le premier : amarre useradd --user <nom>")
	}

	fl, err := fleet.NewClient(cfg.FleetKey, kh)
	if err != nil {
		return err
	}
	col := collector.New(cfg, fl, st, log)
	srv, err := newHTTPServer(cfg, st, col, log)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go col.Run(ctx)

	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sc)
	}()

	log.Info("console démarrée", "écoute", cfg.Listen, "hôtes", len(cfg.Hosts),
		"sources autorisées", strings.Join(cfg.AllowedCIDRs, ","))

	if cfg.TLS.CertFile != "" && cfg.TLS.KeyFile != "" {
		err = srv.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	} else {
		log.Warn("TLS non configuré — n'écouter en clair que sur la boucle locale")
		err = srv.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func cmdUserAdd(args []string) error {
	fs := flag.NewFlagSet("useradd", flag.ExitOnError)
	cfgPath := fs.String("config", "amarre.yml", "chemin de la configuration")
	user := fs.String("user", "", "identifiant à créer")
	stdinPw := fs.Bool("password-stdin", false, "lire le mot de passe sur l'entrée standard (provisionnement automatisé)")
	_ = fs.Parse(args)
	if *user == "" {
		return errors.New("--user est obligatoire")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.StateDB)
	if err != nil {
		return err
	}
	defer st.Close()

	var p1 []byte
	if *stdinPw {
		// Provisionnement Ansible : pas de terminal disponible.
		line, rerr := bufio.NewReader(os.Stdin).ReadString('\n')
		if rerr != nil && line == "" {
			return fmt.Errorf("lecture du mot de passe sur stdin : %w", rerr)
		}
		p1 = []byte(strings.TrimRight(line, "\r\n"))
	} else {
		fmt.Print("Mot de passe : ")
		var rerr error
		p1, rerr = term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if rerr != nil {
			return rerr
		}
		fmt.Print("Confirmation : ")
		p2, rerr := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if rerr != nil {
			return rerr
		}
		if string(p1) != string(p2) {
			return errors.New("les deux saisies diffèrent")
		}
	}
	if len(p1) < 12 {
		return errors.New("mot de passe trop court (12 caractères minimum)")
	}
	hash, err := auth.HashPassword(string(p1))
	if err != nil {
		return err
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		return err
	}
	if err := st.CreateUser(*user, hash, secret); err != nil {
		return fmt.Errorf("création du compte : %w", err)
	}
	fmt.Printf(`
Compte « %s » créé.

Second facteur — à enregistrer MAINTENANT dans ton application TOTP :

  secret : %s
  URI    : %s

Sans ce code, la connexion sera refusée même avec le bon mot de passe.
`, *user, secret, auth.ProvisioningURI("Amarre", *user, secret))
	return nil
}

func newHTTPServer(cfg *config.Config, st *store.Store, col *collector.Collector, log *slog.Logger) (*http.Server, error) {
	h, err := newWebHandler(cfg, st, col, log)
	if err != nil {
		return nil, err
	}
	return &http.Server{
		Addr:              cfg.Listen,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{
				tls.X25519, tls.CurveP256,
			},
		},
	}, nil
}
