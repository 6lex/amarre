package auth

import (
	"testing"
	"time"
)

func TestPasswordRoundTrip(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyPassword("correct horse battery staple", h)
	if err != nil || !ok {
		t.Fatalf("le bon mot de passe est refusé (err=%v)", err)
	}
	ok, _ = VerifyPassword("mauvais", h)
	if ok {
		t.Fatal("un mauvais mot de passe est accepté")
	}
}

// Vecteurs de test de la RFC 6238, appendice B (secret « 12345678901234567890 »
// en base32, SHA-1). Ils garantissent que notre implémentation est conforme
// et non « seulement cohérente avec elle-même ».
func TestTOTPRFC6238(t *testing.T) {
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	}
	for _, c := range cases {
		got, err := totpAt(secret, uint64(c.unix)/totpPeriod)
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("t=%d : obtenu %s, attendu %s", c.unix, got, c.want)
		}
	}
}

func TestTOTPWindow(t *testing.T) {
	s, _ := NewTOTPSecret()
	now := time.Now()
	code, _ := totpAt(s, uint64(now.Unix())/totpPeriod)
	if !VerifyTOTP(s, code, now) {
		t.Fatal("le code courant est refusé")
	}
	if VerifyTOTP(s, "000000", now) && code != "000000" {
		t.Fatal("un code arbitraire est accepté")
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !l.Allow("ip") {
			t.Fatalf("tentative %d refusée trop tôt", i+1)
		}
	}
	if l.Allow("ip") {
		t.Fatal("la 4e tentative aurait dû être refusée")
	}
	l.Reset("ip")
	if !l.Allow("ip") {
		t.Fatal("le compteur n'a pas été remis à zéro")
	}
}
