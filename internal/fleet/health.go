package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Health est le relevé de santé d'un hôte.
//
// Les indicateurs répondent à une seule question : cet hôte peut-il encore
// être sauvegardé et restauré ? D'où ce qui est absent autant que ce qui est
// présent — pas de pourcentage CPU instantané, qui ne dit rien d'une charge,
// ni de « mémoire utilisée », que le cache de pages rend systématiquement
// alarmant sous Linux.
type Health struct {
	CollectedAt int64 `json:"collected_at"`

	UptimeS         int64    `json:"uptime_s"`
	BootTime        int64    `json:"boot_time"`
	RebootRequired  bool     `json:"reboot_required"`
	RebootPackages  []string `json:"reboot_packages"`

	CPUs int       `json:"cpus"`
	Load []float64 `json:"load"` // déjà normalisée par le nombre de cœurs

	MemTotal     int64 `json:"mem_total"`
	MemAvailable int64 `json:"mem_available"`
	SwapTotal    int64 `json:"swap_total"`
	SwapUsed     int64 `json:"swap_used"`

	Filesystems []Filesystem `json:"filesystems"`

	FailedUnits []string `json:"failed_units"`
	OOM7d       int      `json:"oom_7d"`
	IOErrors7d  int      `json:"io_errors_7d"`

	Updates struct {
		Total    int `json:"total"`
		Security int `json:"security"`
	} `json:"updates"`
	LastUnattended int64 `json:"last_unattended"`

	// LastUpgrade est la dernière mise à jour RÉELLEMENT appliquée, lue dans
	// le journal d'apt. La date du dernier « apt update » ne prouverait rien :
	// on peut rafraîchir un index tous les jours sans jamais rien installer.
	LastUpgrade LastUpgrade `json:"last_upgrade"`

	OS    string `json:"os"`
	OSEOL string `json:"os_eol"`

	// LocalProbe est la sonde effectuée PAR L'HÔTE, quand le site est filtré
	// par IP et que la console ne peut pas l'atteindre. Garantie plus faible :
	// elle prouve que l'application répond, pas qu'elle est joignable du
	// dehors. L'interface doit le distinguer, sans quoi on croirait avoir
	// vérifié quelque chose qu'on n'a pas vérifié.
	LocalProbe *LocalProbe `json:"local_probe"`

	BackupStatus BackupStatus            `json:"backup_status"`
	Timers       map[string]TimerState   `json:"timers"`
}

type LastUpgrade struct {
	At       int64    `json:"at"`
	Count    int      `json:"count"`
	Auto     bool     `json:"auto"`
	Packages []string `json:"packages"`
}

// Age rend le temps écoulé depuis la dernière mise à jour appliquée.
func (u LastUpgrade) Age() time.Duration {
	if u.At == 0 {
		return 0
	}
	return time.Since(time.Unix(u.At, 0))
}

func (u LastUpgrade) Time() time.Time { return time.Unix(u.At, 0) }

type Filesystem struct {
	Mount string `json:"mount"`
	Size  int64  `json:"size"`
	Avail int64  `json:"avail"`
	Pct   int    `json:"pct"`
}

// BackupStatus est publié par le script de sauvegarde de l'hôte. La console
// lit ainsi le résultat des vérifications d'intégrité sans avoir le moindre
// accès au dépôt.
type BackupStatus struct {
	BackupAt   int64  `json:"backup_at"`
	BackupOK   bool   `json:"backup_ok"`
	CheckAt    int64  `json:"check_at"`
	CheckOK    bool   `json:"check_ok"`
	CheckDur   int    `json:"check_duration_s"`
	CheckError string `json:"check_error"`
	// CheckKind dit CE QUI a échoué : « verrou », « absent », « corruption »…
	// Confondre un dépôt verrouillé avec un dépôt corrompu affole pour rien,
	// et crier au loup use la confiance dans les alertes qui comptent.
	CheckKind  string `json:"check_kind"`
	DeepAt     int64  `json:"deep_at"`
	DeepOK     bool   `json:"deep_ok"`
	DeepDur    int    `json:"deep_duration_s"`
	DeepError  string `json:"deep_error"`
	DeepSubset string `json:"deep_subset"`
	DeepKind   string `json:"deep_kind"`
}

type LocalProbe struct {
	URL           string `json:"url"`
	Up            bool   `json:"up"`
	Status        int    `json:"status"`
	Attempts      int    `json:"attempts"`
	LatencyMS     int    `json:"latency_ms"`
	Err           string `json:"err"`
	CheckedAt     int64  `json:"checked_at"`
	CertExpiryRaw string `json:"cert_expiry_raw"`
}

type TimerState struct {
	Active bool   `json:"active"`
	Next   string `json:"next"`
}

// Uptime rend la durée depuis le dernier démarrage.
func (h *Health) Uptime() time.Duration { return time.Duration(h.UptimeS) * time.Second }

// EOLDate rend la date de fin de support de l'OS, si connue.
func (h *Health) EOLDate() (time.Time, bool) {
	if h.OSEOL == "" {
		return time.Time{}, false
	}
	t, err := time.Parse("2006-01-02", h.OSEOL)
	return t, err == nil
}

// FetchHealth interroge l'hôte.
func (c *Client) FetchHealth(ctx context.Context, addr, user string, port int) (*Health, error) {
	out, err := c.run(ctx, addr, user, port, "health")
	if err != nil {
		return nil, err
	}
	var h Health
	if err := json.Unmarshal(out, &h); err != nil {
		return nil, fmt.Errorf("relevé de santé illisible : %w", err)
	}
	return &h, nil
}
