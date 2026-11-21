package deploy

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// renderChart runs helm template on the chart; skipped when helm isn't
// installed (CI's kind-e2e job has it).
func renderChart(t *testing.T, args ...string) string {
	t.Helper()
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm not installed")
	}
	// Read every chart file so go test's cache notices chart edits (it can't
	// see the files helm opens).
	_ = filepath.WalkDir("deploy/helm/langstroth-relay", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			_, _ = os.ReadFile(p)
		}
		return nil
	})
	cmd := exec.Command(helm, append([]string{"template", "t", "deploy/helm/langstroth-relay", "--kube-version", "1.30.0"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helm template %v: %v\n%s", args, err, out)
	}
	return string(out)
}

// docs splits rendered YAML into documents.
func docs(out string) []string { return strings.Split(out, "\n---\n") }

func docOfKind(out, kind, nameSuffix string) string {
	for _, d := range docs(out) {
		if strings.Contains(d, "kind: "+kind+"\n") && strings.Contains(d, "name: t-langstroth-relay"+nameSuffix+"\n") {
			return d
		}
	}
	return ""
}

// H-01: the chart defaulted tunnel.mode to open, so a default install was a
// public tunnel provider: any host on the internet could register (a durable
// store row per key pair) and relay phone sessions, although the binary's own
// default is off.
func TestChartTunnelOffByDefault(t *testing.T) {
	out := renderChart(t)
	if !regexp.MustCompile(`name: LANGSTROTH_RELAY_TUNNEL\s+value: "off"`).MatchString(out) {
		t.Fatalf("default install must render LANGSTROTH_RELAY_TUNNEL=off")
	}
	split := renderChart(t, "--set", "postgres.enabled=true", "--set", "postgres.existingSecret=pg")
	if docOfKind(split, "Deployment", "-tunnel") != "" {
		t.Fatal("default split install must not render a tunnel Deployment")
	}
	if !strings.Contains(renderChart(t, "--set", "tunnel.mode=open"), "value: \"open\"") {
		t.Fatal("tunnel.mode=open must still render")
	}
}

// H-02: the liveness probe hit /v1/health, which round-trips the database, so
// a database outage or a slow query made the kubelet restart every relay pod
// (dropping every tunnel socket) without fixing anything. Liveness must only
// check the process; readiness keeps the store check.
func TestChartLivenessDoesNotDependOnStore(t *testing.T) {
	out := renderChart(t, "--set", "postgres.enabled=true", "--set", "postgres.existingSecret=pg", "--set", "tunnel.mode=open")
	for _, suffix := range []string{"-sync", "-tunnel"} {
		d := docOfKind(out, "Deployment", suffix)
		if d == "" {
			t.Fatalf("no %s Deployment", suffix)
		}
		i := strings.Index(d, "livenessProbe:")
		if i < 0 {
			t.Fatalf("%s: no livenessProbe", suffix)
		}
		probe := d[i:]
		if j := strings.Index(probe, "resources:"); j > 0 {
			probe = probe[:j]
		}
		if strings.Contains(probe, "/v1/health") {
			t.Errorf("%s: livenessProbe depends on the store via /v1/health:\n%s", suffix, probe)
		}
		if !strings.Contains(d, "readinessProbe:\n") || !strings.Contains(d, "path: /v1/health") {
			t.Errorf("%s: readinessProbe should still check /v1/health", suffix)
		}
	}
}

// Regression: the APNs key reaches the tunnel pod only, never relay-sync.
func TestChartAPNsKeyOnlyOnTunnelPod(t *testing.T) {
	out := renderChart(t, "--set", "postgres.enabled=true", "--set", "postgres.existingSecret=pg", "--set", "tunnel.mode=open",
		"--set", "tunnel.apns.existingSecret=apns", "--set", "tunnel.apns.keyId=K", "--set", "tunnel.apns.teamId=T", "--set", "tunnel.apns.topic=x.y")
	if d := docOfKind(out, "Deployment", "-sync"); strings.Contains(d, "APNS") || strings.Contains(d, "secretName: apns") {
		t.Fatal("relay-sync must not get the APNs key")
	}
	if d := docOfKind(out, "Deployment", "-tunnel"); !strings.Contains(d, "LANGSTROTH_RELAY_APNS_KEY_FILE") || !strings.Contains(d, "secretName: apns") {
		t.Fatal("the tunnel pod should get the APNs key file")
	}
}

// renderChartErr runs helm template and returns its error output (or "" when
// it rendered).
func renderChartErr(t *testing.T, args ...string) string {
	t.Helper()
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm not installed")
	}
	cmd := exec.Command(helm, append([]string{"template", "t", "deploy/helm/langstroth-relay", "--kube-version", "1.30.0"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return ""
	}
	return string(out)
}

// config.env keys under the names from before the Langstroth rename are no
// longer read (and stop the relay), so the chart refuses them up front.
func TestChartRefusesRemovedEnvNames(t *testing.T) {
	base := []string{"--set", "postgres.enabled=true", "--set", "postgres.existingSecret=pg"}
	for k, want := range map[string]string{"HIVE_RELAY_TUNNEL": "LANGSTROTH_RELAY_TUNNEL", "LIGUS_RELAY_MAX_SSE": "LANGSTROTH_RELAY_MAX_SSE"} {
		if msg := renderChartErr(t, append(base, "--set", "config.env."+k+"=x")...); !strings.Contains(msg, "use "+want) {
			t.Fatalf("config.env.%s must fail naming %s, got %q", k, want, msg)
		}
	}
	if msg := renderChartErr(t, append(base, "--set", "config.env.LANGSTROTH_RELAY_MAX_SSE=10")...); msg != "" {
		t.Fatalf("canonical name must render: %s", msg)
	}
}

// The APNs key must come only from the tunnel-only Secret: config.existingSecret
// and config.env reach every pod, relay-sync included.
func TestChartAPNsKeyNotThroughSharedConfig(t *testing.T) {
	base := []string{"--set", "postgres.enabled=true", "--set", "postgres.existingSecret=pg", "--set", "tunnel.mode=open"}
	if msg := renderChartErr(t, append(base, "--set", "config.existingSecret=shared", "--set", "tunnel.apns.existingSecret=shared")...); !strings.Contains(msg, "tunnel.apns.existingSecret") {
		t.Fatalf("sharing config.existingSecret with the APNs Secret must fail, got %q", msg)
	}
	for _, k := range []string{"LANGSTROTH_RELAY_APNS_KEY", "LANGSTROTH_RELAY_APNS_KEY_FILE", "LANGSTROTH_RELAY_APNS_TOPIC"} {
		if msg := renderChartErr(t, append(base, "--set", "config.env."+k+"=x")...); !strings.Contains(msg, "APNs") {
			t.Fatalf("config.env.%s must fail, got %q", k, msg)
		}
	}
	if msg := renderChartErr(t, append(base, "--set", "config.existingSecret=shared", "--set", "tunnel.apns.existingSecret=apns")...); msg != "" {
		t.Fatalf("separate Secrets must render: %s", msg)
	}
}

// Egress DNS was open to port 53 anywhere, so a compromised relay pod could
// tunnel data out over DNS to any resolver. It is limited to kube-dns.
func TestChartDNSEgressOnlyToKubeDNS(t *testing.T) {
	np := docOfKind(renderChart(t), "NetworkPolicy", "")
	i := strings.Index(np, "egress:")
	if i < 0 {
		t.Fatal("no egress rules")
	}
	egress := np[i:]
	j := strings.Index(egress, "port: 53")
	if j < 0 {
		t.Fatal("no DNS egress rule")
	}
	rule := egress[:j]
	for _, want := range []string{"namespaceSelector:", "kubernetes.io/metadata.name: kube-system", "podSelector:", "k8s-app: kube-dns"} {
		if !strings.Contains(rule, want) {
			t.Fatalf("DNS egress rule lacks %q:\n%s", want, egress)
		}
	}
	custom := docOfKind(renderChart(t, "--set", "networkPolicy.dns.podSelector.matchLabels.k8s-app=coredns"), "NetworkPolicy", "")
	if !strings.Contains(custom, "k8s-app: coredns") {
		t.Fatal("networkPolicy.dns.podSelector must be overridable")
	}
}

// v0.3: contacts on and the deprecated GitHub routes off by default; the
// contacts values render as their LANGSTROTH_RELAY_* variables, integers intact.
func TestChartContactsAndGitHubRoutes(t *testing.T) {
	out := renderChart(t)
	cm := docOfKind(out, "ConfigMap", "")
	if strings.Contains(cm, "LANGSTROTH_RELAY_CONTACT") || strings.Contains(cm, "LANGSTROTH_RELAY_GITHUB_ROUTES") {
		t.Fatalf("default install must keep the binary defaults:\n%s", cm)
	}
	out = renderChart(t, "--set", "contacts.enabled=false", "--set", "contacts.dropMaxBoxBytes=4194304",
		"--set", "contacts.dropRate=0.5", "--set", "githubRoutes=true")
	cm = docOfKind(out, "ConfigMap", "")
	for _, want := range []string{
		`LANGSTROTH_RELAY_CONTACTS: "off"`,
		`LANGSTROTH_RELAY_CONTACT_DROP_MAX_BOX_BYTES: "4194304"`,
		`LANGSTROTH_RELAY_CONTACT_DROP_RATE: "0.5"`,
		`LANGSTROTH_RELAY_GITHUB_ROUTES: "on"`,
	} {
		if !strings.Contains(cm, want) {
			t.Errorf("missing %s in:\n%s", want, cm)
		}
	}
}

// Secrets are files, never environment variables, and the chart generates
// none (lookup-generated passwords changed on every helm template / GitOps
// render).
func TestChartSecretsAreFiles(t *testing.T) {
	out := renderChart(t, "--set", "postgres.enabled=true", "--set", "postgres.existingSecret=pg",
		"--set", "config.existingSecret=relay-env", "--set", "tunnel.mode=open")
	if strings.Contains(out, "secretKeyRef") || strings.Contains(out, "secretRef:") {
		t.Fatal("a Secret reaches a container through env or envFrom")
	}
	for _, want := range []string{"DATABASE_URL_FILE", "LANGSTROTH_RELAY_SECRETS_DIR", "POSTGRES_PASSWORD_FILE", "checksum/secrets:"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s", want)
		}
	}
	if regexp.MustCompile(`(?m)^kind: Secret$`).MatchString(out) {
		t.Fatal("the in-chart Postgres must not render (generate) a Secret")
	}
	if strings.Contains(out, "defaultMode: 0440") || !strings.Contains(out, "defaultMode: 0400") {
		t.Fatal("secret volumes must be 0400")
	}
	again := renderChart(t, "--set", "postgres.enabled=true", "--set", "postgres.existingSecret=pg",
		"--set", "config.existingSecret=relay-env", "--set", "tunnel.mode=open")
	if again != out {
		t.Fatal("two renders differ")
	}
	if err := exec.Command("helm", "template", "t", "deploy/helm/langstroth-relay", "--kube-version", "1.30.0",
		"--set", "postgres.enabled=true").Run(); err == nil {
		t.Fatal("postgres.enabled without postgres.existingSecret must fail")
	}
}

func renderAuth(t *testing.T, args ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed")
	}
	cmd := exec.Command("helm", append([]string{"template", "t", "deploy/helm/langstroth-auth", "--kube-version", "1.30.0",
		"-f", "deploy/helm/langstroth-auth/ci/dex-values.yaml"}, args...)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// langstroth-auth had no NetworkPolicy: its admin port was reachable from every
// pod, agent-running serve pods included.
func TestAuthChartNetworkPolicy(t *testing.T) {
	out, err := renderAuth(t)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	np := ""
	for _, d := range docs(out) {
		if strings.Contains(d, "kind: NetworkPolicy\n") {
			np = d
		}
	}
	if np == "" {
		t.Fatal("no NetworkPolicy")
	}
	if strings.Contains(np, "port: admin") {
		t.Fatal("admin port admitted by default")
	}
	if !strings.Contains(np, "- Egress") || !strings.Contains(np, "169.254.0.0/16") || !strings.Contains(np, "k8s-app: kube-dns") {
		t.Fatalf("egress must be restricted to DNS and the IdP, never cloud metadata:\n%s", np)
	}
	if !strings.Contains(out, "kind: ServiceAccount") || !strings.Contains(out, "enableServiceLinks: false") {
		t.Fatal("langstroth-auth needs its own token-less ServiceAccount and no service links")
	}
	out, _ = renderAuth(t, "--set", "networkPolicy.adminIngressFrom[0].podSelector.matchLabels.app=admin-ui")
	if !strings.Contains(out, "port: admin") {
		t.Fatal("adminIngressFrom must open the admin port to the listed peers")
	}
}

// relay-sync and langstroth-auth keep per-process state: more than one replica,
// an HPA, a PDB on one replica or a rolling update must not render.
func TestChartsRefuseUnsupportedHA(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed")
	}
	for _, sets := range [][]string{{"sync.replicas=2"}, {"sync.autoscaling.enabled=true"}, {"sync.pdb.enabled=true"}} {
		args := []string{"template", "t", "deploy/helm/langstroth-relay", "--kube-version", "1.30.0", "--set", "externalDatabase.url=postgres://u:p@db/r"}
		for _, s := range sets {
			args = append(args, "--set", s)
		}
		if err := exec.Command("helm", args...).Run(); err == nil {
			t.Errorf("relay rendered with %v", sets)
		}
	}
	out := renderChart(t, "--set", "externalDatabase.url=postgres://u:p@db/r")
	sync := docOfKind(out, "Deployment", "-sync")
	if !strings.Contains(sync, "type: Recreate") || strings.Contains(sync, "maxSurge") {
		t.Fatal("relay-sync must use Recreate (a surge pod is a second pairing store)")
	}
	if strings.Contains(out, "kind: PodDisruptionBudget") || strings.Contains(out, "kind: HorizontalPodAutoscaler") {
		t.Fatal("no PDB or HPA for single-replica relay-sync")
	}
	for _, sets := range [][]string{{"replicas=2"}, {"store.driver=postgres", "store.databaseUrl.existingSecret=db", "replicas=2"}, {"persistence.enabled=false"}} {
		var args []string
		for _, s := range sets {
			args = append(args, "--set", s)
		}
		if out, err := renderAuth(t, args...); err == nil {
			t.Errorf("langstroth-auth rendered with %v:\n%.200s", sets, out)
		}
	}
	out, err := renderAuth(t, "--set", "store.driver=postgres", "--set", "store.databaseUrl.existingSecret=db")
	if err != nil || !strings.Contains(out, "type: Recreate") {
		t.Fatalf("langstroth-auth with Postgres must use Recreate: %v", err)
	}
}

// A public relay: TLS required, streaming timeouts and no SSE buffering by
// default, trusted proxies required, /metrics behind a token.
func TestChartPublicRelayDefaults(t *testing.T) {
	pub := []string{"--set", "externalDatabase.url=postgres://u:p@db/r", "--set", "ingress.enabled=true", "--set", "httpRoute.enabled=true"}
	good := append(append([]string{}, pub...), "--set", "ingress.tls.secretName=relay-tls",
		"--set", "clientIP.trustedProxies[0]=10.0.0.5/32", "--set", "metrics.token.existingSecret=mt",
		"--set", "ingress.annotations.nginx\\.ingress\\.kubernetes\\.io/proxy-read-timeout=7200")
	out := renderChart(t, good...)
	ing := ""
	for _, d := range docs(out) {
		if strings.Contains(d, "kind: Ingress\n") {
			ing = d
		}
	}
	for _, want := range []string{`proxy-buffering: "off"`, `proxy-send-timeout: "3600"`, `proxy-read-timeout: "7200"`, "idle_timeout.timeout_seconds=3600", "secretName: relay-tls"} {
		if !strings.Contains(ing, want) {
			t.Errorf("ingress lacks %s:\n%s", want, ing)
		}
	}
	if !strings.Contains(out, "request: 3600s") || !strings.Contains(out, "LANGSTROTH_RELAY_METRICS_TOKEN_FILE") {
		t.Error("httpRoute timeouts or the metrics token file missing")
	}
	drop := map[string]bool{"ingress.tls.secretName=relay-tls": true, "clientIP.trustedProxies[0]=10.0.0.5/32": true, "metrics.token.existingSecret=mt": true}
	for k := range drop {
		args := []string{"template", "t", "deploy/helm/langstroth-relay", "--kube-version", "1.30.0"}
		for i := 0; i < len(good); i += 2 {
			if good[i+1] != k {
				args = append(args, good[i], good[i+1])
			}
		}
		if err := exec.Command("helm", args...).Run(); err == nil {
			t.Errorf("rendered a public relay without %s", k)
		}
	}
}

// The tunnel pod serves only the tunnel; relay-sync never gets the setting.
func TestChartTunnelPodServesOnlyTunnel(t *testing.T) {
	out := renderChart(t, "--set", "externalDatabase.url=postgres://u:p@db/r", "--set", "tunnel.mode=open")
	if !strings.Contains(docOfKind(out, "Deployment", "-tunnel"), "LANGSTROTH_RELAY_ROUTES") {
		t.Fatal("tunnel pod must set LANGSTROTH_RELAY_ROUTES=tunnel")
	}
	if strings.Contains(docOfKind(out, "Deployment", "-sync"), "LANGSTROTH_RELAY_ROUTES") {
		t.Fatal("relay-sync must serve every route")
	}
}

// A LoadBalancer or NodePort Service publishes the relay as surely as an
// Ingress does, so it gets the same guards: no unauthenticated /metrics and
// an explicit decision on client addresses.
func TestChartPublicServiceTypeNeedsTheSameGuards(t *testing.T) {
	for _, typ := range []string{"LoadBalancer", "NodePort"} {
		if renderChartErr(t, "--set", "service.type="+typ) == "" {
			t.Errorf("service.type=%s rendered with an open /metrics and no clientIP decision", typ)
		}
		if msg := renderChartErr(t, "--set", "service.type="+typ, "--set", "metrics.token.existingSecret=mt", "--set", "clientIP.allowSharedBucket=true"); msg != "" {
			t.Errorf("service.type=%s with a metrics token must render: %s", typ, msg)
		}
	}
}

// A release installed from the former ligus-relay chart upgrades with
// nameOverride=ligus-relay: the resource names and the immutable selector
// labels stay what that chart rendered (README, "Renamed from ligus-relay").
func TestChartNameOverrideKeepsFormerNames(t *testing.T) {
	out := renderChart(t, "--set", "nameOverride=ligus-relay")
	var d string
	for _, doc := range docs(out) {
		if strings.Contains(doc, "kind: Deployment\n") {
			d = doc
		}
	}
	if !strings.Contains(d, "name: t-ligus-relay\n") || !strings.Contains(d, "app.kubernetes.io/name: ligus-relay") {
		t.Fatalf("nameOverride must keep the former names and selector labels:\n%s", d)
	}
	if strings.Contains(out, "app.kubernetes.io/name: langstroth-relay") {
		t.Fatal("a former name must not leave a langstroth-relay selector behind")
	}
	if d := docOfKind(renderChart(t), "Deployment", ""); !strings.Contains(d, "app.kubernetes.io/name: langstroth-relay") {
		t.Fatalf("default name:\n%s", d)
	}
}

// Limits render as their LANGSTROTH_RELAY_* variables (all off by default),
// and the tenancy config is a Secret mounted as a file into every relay pod,
// never an environment value.
func TestChartLimitsAndTenancy(t *testing.T) {
	out := renderChart(t)
	if cm := docOfKind(out, "ConfigMap", ""); strings.Contains(cm, "LANGSTROTH_RELAY_ROOM_") || strings.Contains(cm, "LANGSTROTH_RELAY_IP_RATE") {
		t.Fatalf("default install must keep the limits off:\n%s", cm)
	}
	if strings.Contains(out, "TENANCY") {
		t.Fatal("tenancy rendered without tenancy.existingSecret")
	}
	base := []string{"--set", "postgres.enabled=true", "--set", "postgres.existingSecret=pg", "--set", "tunnel.mode=open"}
	out = renderChart(t, append(base, "--set", "limits.roomMaxBytes=67108864", "--set", "limits.ipRate=20",
		"--set", "limits.roomRetentionDays=180", "--set", "limits.tunnelPushPerDay=500", "--set", "tenancy.existingSecret=relay-tenancy",
		"--set", "metrics.token.existingSecret=relay-metrics")...)
	cm := docOfKind(out, "ConfigMap", "")
	for _, want := range []string{
		`LANGSTROTH_RELAY_ROOM_MAX_BYTES: "67108864"`, `LANGSTROTH_RELAY_IP_RATE: "20"`,
		`LANGSTROTH_RELAY_ROOM_RETENTION_DAYS: "180"`, `LANGSTROTH_RELAY_TUNNEL_PUSH_PER_DAY: "500"`,
	} {
		if !strings.Contains(cm, want) {
			t.Errorf("missing %s in:\n%s", want, cm)
		}
	}
	if strings.Contains(cm, "TENANCY") {
		t.Fatal("the tenancy config reached the ConfigMap")
	}
	for _, suffix := range []string{"-sync", "-tunnel"} {
		d := docOfKind(out, "Deployment", suffix)
		if d == "" {
			t.Fatalf("no Deployment%s", suffix)
		}
		if !strings.Contains(d, "LANGSTROTH_RELAY_TENANCY_FILE") || !strings.Contains(d, "secretName: relay-tenancy") {
			t.Errorf("Deployment%s doesn't mount the tenancy file:\n%s", suffix, d)
		}
	}
	if msg := renderChartErr(t, append(base, "--set", "config.env.LANGSTROTH_RELAY_TENANCY=x")...); !strings.Contains(msg, "tenancy.existingSecret") {
		t.Fatalf("tenancy through config.env must fail, got %q", msg)
	}
	// Tenancy without a metrics token would publish every tenant's usage.
	if msg := renderChartErr(t, append(base, "--set", "tenancy.existingSecret=relay-tenancy")...); !strings.Contains(msg, "metrics token") {
		t.Fatalf("tenancy without a metrics token must fail, got %q", msg)
	}
}

// The blob channel: on by default with the binary's defaults (no variables
// rendered), values map to LANGSTROTH_RELAY_BLOB_*, enabled=false turns the
// routes off, and the ingress body limit follows the blob size so a proxy
// doesn't refuse attachments the relay accepts.
func TestChartBlobs(t *testing.T) {
	pub := []string{"--set", "externalDatabase.url=postgres://u:p@db/r", "--set", "ingress.enabled=true",
		"--set", "ingress.tls.secretName=relay-tls", "--set", "clientIP.trustedProxies[0]=10.0.0.5/32",
		"--set", "metrics.token.existingSecret=mt"}
	ingressOf := func(out string) string {
		for _, d := range docs(out) {
			if strings.Contains(d, "kind: Ingress\n") {
				return d
			}
		}
		return ""
	}
	out := renderChart(t, pub...)
	if cm := docOfKind(out, "ConfigMap", ""); strings.Contains(cm, "LANGSTROTH_RELAY_BLOB") {
		t.Fatalf("default install must keep the binary's blob defaults:\n%s", cm)
	}
	if ing := ingressOf(out); !strings.Contains(ing, `proxy-body-size: "26214400"`) {
		t.Fatalf("ingress body limit must match the default blob size:\n%s", ing)
	}
	out = renderChart(t, append(pub, "--set", "blobs.maxBytes=1048576", "--set", "blobs.roomMaxCount=50",
		"--set", "blobs.writerMaxBytes=10485760", "--set", "blobs.retentionDays=7", "--set", "blobs.rate=0.5",
		"--set", "blobs.totalMaxBytes=0", "--set", "blobs.maxInflight=8", "--set", "blobs.writerInflight=2",
		"--set", "blobs.downloadRate=0.25", "--set", "blobs.clientDownloadBurst=30")...)
	cm := docOfKind(out, "ConfigMap", "")
	for _, want := range []string{`LANGSTROTH_RELAY_BLOB_MAX_BYTES: "1048576"`, `LANGSTROTH_RELAY_BLOB_ROOM_MAX_COUNT: "50"`,
		`LANGSTROTH_RELAY_BLOB_WRITER_MAX_BYTES: "10485760"`, `LANGSTROTH_RELAY_BLOB_RETENTION_DAYS: "7"`,
		`LANGSTROTH_RELAY_BLOB_RATE: "0.5"`, `LANGSTROTH_RELAY_BLOB_TOTAL_MAX_BYTES: "0"`,
		`LANGSTROTH_RELAY_BLOB_MAX_INFLIGHT: "8"`, `LANGSTROTH_RELAY_BLOB_WRITER_INFLIGHT: "2"`,
		`LANGSTROTH_RELAY_BLOB_DOWNLOAD_RATE: "0.25"`, `LANGSTROTH_RELAY_BLOB_CLIENT_DOWNLOAD_BURST: "30"`} {
		if !strings.Contains(cm, want) {
			t.Errorf("missing %s in:\n%s", want, cm)
		}
	}
	if strings.Contains(cm, "LANGSTROTH_RELAY_BLOBS:") {
		t.Fatal("blobs on must not render LANGSTROTH_RELAY_BLOBS")
	}
	if ing := ingressOf(out); !strings.Contains(ing, `proxy-body-size: "1048576"`) {
		t.Fatalf("ingress body limit must follow blobs.maxBytes:\n%s", ing)
	}
	out = renderChart(t, append(pub, "--set", "blobs.enabled=false")...)
	if cm := docOfKind(out, "ConfigMap", ""); !strings.Contains(cm, `LANGSTROTH_RELAY_BLOBS: "off"`) {
		t.Fatalf("blobs.enabled=false must turn the routes off:\n%s", cm)
	}
	if ing := ingressOf(out); strings.Contains(ing, "proxy-body-size") {
		t.Fatalf("no body-size override with blobs off:\n%s", ing)
	}
}
