// Package config charge et valide la configuration d'Amarre.
package config

import (
	"fmt"
	"net/netip"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config décrit l'ensemble du paramétrage de la console.
type Config struct {
	Listen   string        `yaml:"listen"`
	StateDB  string        `yaml:"state_db"`
	FleetKey string        `yaml:"fleet_key"`
	Interval time.Duration `yaml:"collect_interval"`

	// AllowedCIDRs est le filtrage IP applicatif. Il double celui de
	// nftables : si une règle réseau saute lors d'une manipulation, la
	// console refuse toujours. Deux barrières indépendantes valent mieux
	// qu'une seule bien configurée.
	AllowedCIDRs []string `yaml:"allowed_cidrs"`

	TLS   TLSConfig    `yaml:"tls"`
	Hosts []HostConfig `yaml:"hosts"`

	allowed []netip.Prefix
}

type TLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// HostConfig décrit un hôte sauvegardé. La console ne connaît que de quoi
// le joindre : jamais un mot de passe de dépôt, jamais un identifiant
// Storage Box.
type HostConfig struct {
	Name     string        `yaml:"name"`
	// HTTPCheck est l'adresse d'une page du site à interroger pour établir sa
	// disponibilité RÉELLE, vue de l'extérieur. Un service peut tourner sans
	// que le site réponde ; seule une requête sur une vraie page le dit.
	HTTPCheck string `yaml:"http_check"`
	HTTPExpect int   `yaml:"http_expect"`
	Addr     string        `yaml:"addr"`
	User     string        `yaml:"user"`
	Port     int           `yaml:"port"`
	Expect   time.Duration `yaml:"expect_within"`
	Disabled bool          `yaml:"disabled"`
}

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("lecture de la configuration : %w", err)
	}
	c := &Config{
		Listen:   "127.0.0.1:8443",
		StateDB:  "amarre.db",
		Interval: 15 * time.Minute,
	}
	if err := yaml.Unmarshal(raw, c); err != nil {
		return nil, fmt.Errorf("configuration illisible : %w", err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) validate() error {
	if c.FleetKey == "" {
		return fmt.Errorf("fleet_key est obligatoire : sans clé, la console ne peut joindre aucun hôte")
	}
	// Une liste vide n'ouvre pas la console à tous : elle la ferme.
	// Le sens du défaut compte — se tromper doit fermer, pas ouvrir.
	for _, s := range c.AllowedCIDRs {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			// Tolère une IP nue en plus d'un CIDR.
			a, aerr := netip.ParseAddr(s)
			if aerr != nil {
				return fmt.Errorf("allowed_cidrs : %q n'est ni une IP ni un CIDR", s)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		c.allowed = append(c.allowed, p)
	}
	seen := map[string]bool{}
	for i, h := range c.Hosts {
		if h.Name == "" {
			return fmt.Errorf("hosts[%d] : name est obligatoire", i)
		}
		if seen[h.Name] {
			return fmt.Errorf("hôte %q déclaré deux fois", h.Name)
		}
		seen[h.Name] = true
		if c.Hosts[i].Addr == "" {
			c.Hosts[i].Addr = h.Name
		}
		if c.Hosts[i].User == "" {
			c.Hosts[i].User = "root"
		}
		if c.Hosts[i].Port == 0 {
			c.Hosts[i].Port = 22
		}
		if c.Hosts[i].Expect == 0 {
			c.Hosts[i].Expect = 26 * time.Hour
		}
	}
	return nil
}

// IPAllowed indique si une adresse est autorisée à joindre la console.
// Une liste vide refuse tout.
func (c *Config) IPAllowed(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range c.allowed {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
