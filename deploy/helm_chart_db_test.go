package deploy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// The database choice (database.mode): external, cnpg (CloudNativePG) and
// bundled (one hardened Postgres pod), plus the deprecated aliases.

var (
	cnpgArgs = []string{"--api-versions", "postgresql.cnpg.io/v1", "--set", "database.mode=cnpg",
		"--set", "database.cnpg.backups.barmanObjectStore.destinationPath=s3://b/relay"}
	bundledArgs = []string{"--set", "database.mode=bundled", "--set", "database.bundled.auth.existingSecret=pga",
		"--set", "database.bundled.tls.existingSecret=pgtls"}
	externalArgs = []string{"--set", "database.mode=external", "--set", "database.external.existingSecret=db",
		"--set", "database.external.cidrs[0]=10.20.0.15/32"}
)

func with(base []string, more ...string) []string {
	return append(append([]string{}, base...), more...)
}

// docNamed returns the rendered document of kind with exactly this name.
func docNamed(out, kind, name string) string {
	for _, d := range docs(out) {
		if strings.Contains(d, "kind: "+kind+"\n") && strings.Contains(d, "\n  name: "+name+"\n") {
			return d
		}
	}
	return ""
}

// The relay's egress policy (the first NetworkPolicy, named after the release).
func relayEgress(t *testing.T, out string) string {
	t.Helper()
	np := docNamed(out, "NetworkPolicy", "t-langstroth-relay")
	i := strings.Index(np, "  egress:\n")
	if i < 0 {
		t.Fatalf("relay NetworkPolicy has no egress:\n%s", np)
	}
	return np[i:]
}

// No secret reaches a container through the environment, in any mode.
func assertNoEnvSecrets(t *testing.T, mode, out string) {
	t.Helper()
	if strings.Contains(out, "secretKeyRef") || strings.Contains(out, "secretRef:") {
		t.Errorf("%s: a Secret reaches a container through env or envFrom", mode)
	}
	if regexp.MustCompile(`(?i)name: (PGPASSWORD|POSTGRES_PASSWORD|DATABASE_URL)\b`).MatchString(out) {
		t.Errorf("%s: a password or DSN variable in the environment", mode)
	}
	if regexp.MustCompile(`(?m)^kind: Secret$`).MatchString(out) {
		t.Errorf("%s: the chart rendered (generated) a Secret", mode)
	}
}

func TestChartDatabaseCNPG(t *testing.T) {
	out := renderChart(t, with(cnpgArgs, "--set", "tunnel.mode=open")...)
	assertNoEnvSecrets(t, "cnpg", out)
	cluster := docNamed(out, "Cluster", "t-langstroth-relay-db")
	for _, want := range []string{"apiVersion: postgresql.cnpg.io/v1", "instances: 1", "database: relay", "owner: relay",
		"- hostnossl all all all reject", "destinationPath: s3://b/relay", "retentionPolicy: \"30d\""} {
		if !strings.Contains(cluster, want) {
			t.Errorf("Cluster lacks %q:\n%s", want, cluster)
		}
	}
	sb := docNamed(out, "ScheduledBackup", "t-langstroth-relay-db")
	if !strings.Contains(sb, "method: barmanObjectStore") || !strings.Contains(sb, `schedule: "0 0 3 * * *"`) {
		t.Errorf("ScheduledBackup:\n%s", sb)
	}
	// The DSN has no password and verifies the server against the operator's CA.
	cm := docNamed(out, "ConfigMap", "t-langstroth-relay-dsn")
	want := `DATABASE_URL: "postgres://relay@t-langstroth-relay-db-rw:5432/relay?sslmode=verify-full&sslrootcert=/etc/langstroth-relay/db/ca.crt&passfile=/etc/langstroth-relay/db/pgpass"`
	if !strings.Contains(cm, want) {
		t.Fatalf("DSN ConfigMap:\n%s", cm)
	}
	for _, suffix := range []string{"-sync", "-tunnel"} {
		d := docOfKind(out, "Deployment", suffix)
		if !strings.Contains(d, "value: /etc/langstroth-relay/db/DATABASE_URL") {
			t.Errorf("%s: DATABASE_URL_FILE missing", suffix)
		}
		// Only pgpass and ca.crt are projected from the operator's Secrets:
		// never the CA's private key, never the bare password.
		for _, w := range []string{"name: t-langstroth-relay-db-app", "{ key: pgpass, path: pgpass }", "name: t-langstroth-relay-db-ca", "{ key: ca.crt, path: ca.crt }", "defaultMode: 0400"} {
			if !strings.Contains(d, w) {
				t.Errorf("%s: db volume lacks %q", suffix, w)
			}
		}
		if strings.Contains(d, "ca.key") || strings.Contains(d, "key: password") || strings.Contains(d, "key: uri") {
			t.Errorf("%s: mounts more of the operator's Secrets than pgpass and ca.crt", suffix)
		}
	}
	eg := relayEgress(t, out)
	if !strings.Contains(eg, "cnpg.io/cluster: t-langstroth-relay-db") || strings.Contains(eg, "ipBlock") {
		t.Errorf("relay egress must go to the cluster's pods only:\n%s", eg)
	}
	np := docNamed(out, "NetworkPolicy", "t-langstroth-relay-db")
	for _, w := range []string{"kubernetes.io/metadata.name: cnpg-system", "port: 8000", "values:\n              - relay\n              - sync\n              - tunnel"} {
		if !strings.Contains(np, w) {
			t.Errorf("cluster NetworkPolicy lacks %q:\n%s", w, np)
		}
	}
	// HA, plugin backups and a PodMonitor.
	out = renderChart(t, "--api-versions", "postgresql.cnpg.io/v1", "--api-versions", "monitoring.coreos.com/v1",
		"--set", "database.mode=cnpg", "--set", "database.cnpg.instances=3", "--set", "database.cnpg.backups.method=plugin",
		"--set", "database.cnpg.backups.plugin.parameters.barmanObjectName=store", "--set", "database.cnpg.podMonitor.enabled=true")
	cluster = docNamed(out, "Cluster", "t-langstroth-relay-db")
	if !strings.Contains(cluster, "instances: 3") || !strings.Contains(cluster, "isWALArchiver: true") || strings.Contains(cluster, "barmanObjectStore") {
		t.Errorf("HA plugin Cluster:\n%s", cluster)
	}
	if !strings.Contains(docNamed(out, "ScheduledBackup", "t-langstroth-relay-db"), "method: plugin") || docNamed(out, "PodMonitor", "t-langstroth-relay-db") == "" {
		t.Error("plugin ScheduledBackup or PodMonitor missing")
	}
}

func TestChartDatabaseCNPGRefusals(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		// No operator API: refuse unless rendering offline says so.
		{[]string{"--set", "database.mode=cnpg"}, "skipCapabilityCheck"},
		{[]string{"--set", "database.mode=cnpg", "--set", "database.skipCapabilityCheck=true"}, "barmanObjectStore"},
		{with(cnpgArgs, "--set", "database.cnpg.backups.enabled=false"), "acknowledgeNoBackups"},
		{with(cnpgArgs, "--set", "database.cnpg.backups.method=plugin"), "plugin.name and parameters"},
		{with(cnpgArgs, "--set", "database.cnpg.instances=0"), "at least 1"},
		{with(cnpgArgs, "--set", "database.cnpg.podMonitor.enabled=true"), "monitoring.coreos.com"},
	}
	for _, c := range cases {
		if msg := renderChartErr(t, c.args...); !strings.Contains(msg, c.want) {
			t.Errorf("%v: want a refusal mentioning %q, got %q", c.args, c.want, msg)
		}
	}
	for _, ok := range [][]string{
		{"--set", "database.mode=cnpg", "--set", "database.skipCapabilityCheck=true", "--set", "database.cnpg.backups.enabled=false", "--set", "database.cnpg.backups.acknowledgeNoBackups=true"},
		with(cnpgArgs, "--set", "database.cnpg.backups.enabled=false", "--set", "database.cnpg.backups.acknowledgeNoBackups=true"),
	} {
		if msg := renderChartErr(t, ok...); msg != "" {
			t.Errorf("%v must render: %s", ok, msg)
		}
	}
}

func TestChartDatabaseBundled(t *testing.T) {
	out := renderChart(t, with(bundledArgs, "--set", "tunnel.mode=open")...)
	assertNoEnvSecrets(t, "bundled", out)
	sts := docNamed(out, "StatefulSet", "t-langstroth-relay-postgres")
	for _, w := range []string{
		"@sha256:", "- ReadWriteOncePod", "runAsNonRoot: true", "readOnlyRootFilesystem: true", "drop: [\"ALL\"]", "type: RuntimeDefault",
		"- ssl=on", "- hba_file=/etc/postgres-conf/pg_hba.conf", "- password_encryption=scram-sha-256",
		"value: postgres", "POSTGRES_PASSWORD_FILE", "automountServiceAccountToken: false",
		"{ key: tls.key, path: tls.key }",
	} {
		if !strings.Contains(sts, w) {
			t.Errorf("StatefulSet lacks %q", w)
		}
	}
	if strings.Contains(sts, "key: ca.key") {
		t.Error("StatefulSet mounts a CA private key")
	}
	// A renewed certificate is picked up without a restart.
	if !strings.Contains(sts, "name: tls-reload") || !strings.Contains(sts, "SELECT pg_reload_conf()") {
		t.Error("no reload of a rotated server certificate")
	}
	conf := docNamed(out, "ConfigMap", "t-langstroth-relay-postgres-conf")
	for _, w := range []string{"local     all          postgres                peer", "hostssl   relay  relay  all  scram-sha-256", "host      all          all          all        reject", "CREATE ROLE :\"role\" LOGIN"} {
		if !strings.Contains(conf, w) {
			t.Errorf("postgres conf lacks %q:\n%s", w, conf)
		}
	}
	if strings.Contains(conf, "--set=pw") || !strings.Contains(conf, "\\set pw `cat /etc/postgres-secret/password`") {
		t.Errorf("the role's password must not be on a command line:\n%s", conf)
	}
	if strings.Contains(conf, "SUPERUSER") || strings.Contains(conf, "trust") || strings.Contains(conf, "md5") {
		t.Errorf("postgres conf grants too much:\n%s", conf)
	}
	cm := docNamed(out, "ConfigMap", "t-langstroth-relay-dsn")
	if !strings.Contains(cm, `"postgres://relay@t-langstroth-relay-postgres:5432/relay?sslmode=verify-full&sslrootcert=/etc/langstroth-relay/db/ca.crt&passfile=/etc/langstroth-relay/db/pgpass"`) {
		t.Errorf("DSN:\n%s", cm)
	}
	sync := docOfKind(out, "Deployment", "-sync")
	for _, w := range []string{"name: pga", "{ key: pgpass, path: pgpass }", "name: pgtls", "{ key: ca.crt, path: ca.crt }"} {
		if !strings.Contains(sync, w) {
			t.Errorf("relay db volume lacks %q", w)
		}
	}
	if strings.Contains(sync, "tls.key") || strings.Contains(sync, "key: password") {
		t.Error("the relay mounts the server key or the bare password")
	}
	// Backups: a CronJob dumping to its own PVC, with retention.
	cj := docNamed(out, "CronJob", "t-langstroth-relay-postgres-backup")
	for _, w := range []string{"concurrencyPolicy: Forbid", "suspend: false", "pg_dump --format=custom", `name: KEEP, value: "7"`, "PGSSLMODE, value: verify-full", "claimName: backups-t-langstroth-relay-postgres-0", "app.kubernetes.io/component: postgres-backup", "topologyKey: kubernetes.io/hostname"} {
		if !strings.Contains(cj, w) {
			t.Errorf("CronJob lacks %q", w)
		}
	}
	// The dumps' volume is a claim of the StatefulSet (bound with the Postgres
	// pod, so helm --wait and GitOps health don't wait for the first backup),
	// never a standalone claim left Pending.
	if !strings.Contains(sts, "    - metadata:\n        name: backups\n") || strings.Contains(out, "kind: PersistentVolumeClaim") {
		t.Errorf("backup volume must be a volumeClaimTemplate:\n%s", sts)
	}
	// Only the relay pods and the backup job reach 5432; Postgres reaches nothing.
	np := docNamed(out, "NetworkPolicy", "t-langstroth-relay-postgres")
	for _, w := range []string{"policyTypes: [Ingress, Egress]", "egress: []", "app.kubernetes.io/component: postgres-backup", "values:\n              - relay\n              - sync\n              - tunnel", "port: 5432"} {
		if !strings.Contains(np, w) {
			t.Errorf("postgres NetworkPolicy lacks %q:\n%s", w, np)
		}
	}
	bnp := docNamed(out, "NetworkPolicy", "t-langstroth-relay-postgres-backup")
	if !strings.Contains(bnp, "k8s-app: kube-dns") || !strings.Contains(bnp, "app.kubernetes.io/component: postgres\n") || strings.Contains(bnp, "ipBlock") {
		t.Errorf("backup job egress must be DNS and Postgres only:\n%s", bnp)
	}
	eg := relayEgress(t, out)
	if !strings.Contains(eg, "app.kubernetes.io/component: postgres\n") || strings.Contains(eg, "ipBlock") {
		t.Errorf("relay egress must go to the bundled Postgres only:\n%s", eg)
	}

	// cert-manager issues the server certificate when issuerRef is set.
	out = renderChart(t, "--api-versions", "cert-manager.io/v1", "--set", "database.mode=bundled", "--set", "database.bundled.auth.existingSecret=pga",
		"--set", "database.bundled.tls.certManager.issuerRef.name=ligus-ca")
	cert := docNamed(out, "Certificate", "t-langstroth-relay-postgres")
	for _, w := range []string{"secretName: t-langstroth-relay-postgres-tls", "name: ligus-ca", "- t-langstroth-relay-postgres\n", "- t-langstroth-relay-postgres.default.svc\n"} {
		if !strings.Contains(cert, w) {
			t.Errorf("Certificate lacks %q:\n%s", w, cert)
		}
	}
	if !strings.Contains(docOfKind(out, "Deployment", "-sync"), "name: t-langstroth-relay-postgres-tls") {
		t.Error("the relay must read ca.crt from the cert-manager Secret")
	}

	// The explicit plaintext escape hatch.
	out = renderChart(t, "--set", "database.mode=bundled", "--set", "database.bundled.auth.existingSecret=pga", "--set", "database.bundled.allowPlaintextInNamespace=true")
	if !strings.Contains(docNamed(out, "ConfigMap", "t-langstroth-relay-dsn"), "sslmode=disable&passfile=") || strings.Contains(out, "ssl=on") {
		t.Error("allowPlaintextInNamespace should render sslmode=disable and no server TLS")
	}
	if !strings.Contains(docNamed(out, "ConfigMap", "t-langstroth-relay-postgres-conf"), "host      relay  relay  all  scram-sha-256") {
		t.Error("plaintext still needs scram-sha-256")
	}
}

func TestChartDatabaseBundledRefusals(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"--set", "database.mode=bundled"}, "auth.existingSecret"},
		{[]string{"--set", "database.mode=bundled", "--set", "database.bundled.auth.existingSecret=pga"}, "needs TLS"},
		{with(bundledArgs, "--set", "database.bundled.tls.certManager.issuerRef.name=ca"), "not both"},
		{[]string{"--set", "database.mode=bundled", "--set", "database.bundled.auth.existingSecret=pga", "--set", "database.bundled.tls.certManager.issuerRef.name=ca"}, "cert-manager.io/v1"},
		{with(bundledArgs, "--set", "database.bundled.image.tag=16-alpine"), "digest"},
		{with(bundledArgs, "--set", "database.bundled.backups.enabled=false"), "acknowledgeNoBackups"},
		{with(bundledArgs, "--set", "database.bundled.backups.keep=0"), "keep"},
		{with(bundledArgs, "--set", "database.bundled.backups.restore.file=../etc/passwd"), "restore.file"},
		{with(bundledArgs, "--set", "database.bundled.backups.enabled=false", "--set", "database.bundled.backups.acknowledgeNoBackups=true",
			"--set", "database.bundled.backups.restore.file=relay-1.dump"), "backup volume"},
	}
	for _, c := range cases {
		if msg := renderChartErr(t, c.args...); !strings.Contains(msg, c.want) {
			t.Errorf("%v: want a refusal mentioning %q, got %q", c.args, c.want, msg)
		}
	}
	out := renderChart(t, with(bundledArgs, "--set", "database.bundled.backups.enabled=false", "--set", "database.bundled.backups.acknowledgeNoBackups=true")...)
	if strings.Contains(out, "kind: CronJob") || docNamed(out, "NetworkPolicy", "t-langstroth-relay-postgres-backup") != "" {
		t.Error("acknowledged no-backups still renders the backup job")
	}
	if strings.Contains(docNamed(out, "NetworkPolicy", "t-langstroth-relay-postgres"), "postgres-backup") {
		t.Error("without backups the job must not be admitted to 5432")
	}
}

// A restore stops every writer: the relay runs no replicas and the CronJob
// is suspended while the Job runs.
func TestChartDatabaseBundledRestore(t *testing.T) {
	out := renderChart(t, with(bundledArgs, "--set", "tunnel.mode=open", "--set", "database.bundled.backups.restore.file=relay-20260101T031700Z.dump")...)
	for _, suffix := range []string{"-sync", "-tunnel"} {
		if !strings.Contains(docOfKind(out, "Deployment", suffix), "replicas: 0\n") {
			t.Errorf("%s must scale to zero during a restore", suffix)
		}
	}
	if !strings.Contains(docNamed(out, "CronJob", "t-langstroth-relay-postgres-backup"), "suspend: true") {
		t.Error("the backup CronJob must be suspended during a restore")
	}
	var job string
	for _, d := range docs(out) {
		if strings.Contains(d, "kind: Job\n") && strings.Contains(d, "name: t-langstroth-relay-postgres-restore-") {
			job = d
		}
	}
	for _, w := range []string{"RESTORE_FILE, value: \"relay-20260101T031700Z.dump\"", "pg_restore --clean --if-exists --no-owner --no-acl --single-transaction", "backoffLimit: 0"} {
		if !strings.Contains(job, w) {
			t.Errorf("restore Job lacks %q:\n%s", w, job)
		}
	}
	if !strings.Contains(docOfKind(renderChart(t, bundledArgs...), "Deployment", "-sync"), "replicas: 1\n") {
		t.Error("without a restore the relay runs one replica")
	}
}

func TestChartDatabaseExternal(t *testing.T) {
	out := renderChart(t, externalArgs...)
	assertNoEnvSecrets(t, "external", out)
	sync := docOfKind(out, "Deployment", "-sync")
	if !strings.Contains(sync, "secretName: db") || !strings.Contains(sync, "{ key: DATABASE_URL, path: DATABASE_URL }") {
		t.Errorf("external DSN must be mounted from its Secret:\n%s", sync)
	}
	eg := relayEgress(t, out)
	if !strings.Contains(eg, "cidr: 10.20.0.15/32") || !strings.Contains(eg, "port: 5432") {
		t.Errorf("external egress:\n%s", eg)
	}
	if strings.Contains(out, "kind: StatefulSet") || strings.Contains(out, "kind: Cluster") {
		t.Error("external mode renders no database")
	}
	// Broad or metadata-containing ranges are refused; a VPC range is fine.
	for _, cidr := range []string{"0.0.0.0/0", "128.0.0.0/1", "169.254.0.0/16", "169.254.169.254/32", "100.64.0.0/10", "100.100.100.200/32", "not-a-cidr"} {
		if renderChartErr(t, "--set", "database.mode=external", "--set", "database.external.existingSecret=db", "--set", "database.external.cidrs[0]="+cidr) == "" {
			t.Errorf("external cidr %s must be refused", cidr)
		}
	}
	for _, cidr := range []string{"10.0.0.0/8", "172.16.4.0/24", "100.128.0.0/16", "169.253.0.0/16"} {
		if msg := renderChartErr(t, "--set", "database.mode=external", "--set", "database.external.existingSecret=db", "--set", "database.external.cidrs[0]="+cidr); msg != "" {
			t.Errorf("external cidr %s must render: %s", cidr, msg)
		}
	}
	if !strings.Contains(renderChartErr(t, "--set", "database.mode=external"), "existingSecret") {
		t.Error("external without a Secret must be refused")
	}
	if !strings.Contains(renderChartErr(t, "--set", "database.mode=bogus"), "database.mode must be") {
		t.Error("an unknown mode must be refused")
	}
}

// The old keys keep working, unchanged, as aliases; mixing them with
// database.mode is refused.
func TestChartDatabaseDeprecatedAliases(t *testing.T) {
	legacy := renderChart(t, "--set", "postgres.enabled=true", "--set", "postgres.existingSecret=pg")
	sts := docNamed(legacy, "StatefulSet", "t-langstroth-relay-postgres")
	// Same StatefulSet identity and volume claim as before (both immutable),
	// and the old development behaviour.
	for _, w := range []string{"serviceName: t-langstroth-relay-postgres", "app.kubernetes.io/component: postgres", "- ReadWriteOnce\n", "storage: 1Gi", "name: POSTGRES_USER\n              value: \"relay\""} {
		if !strings.Contains(sts, w) {
			t.Errorf("legacy StatefulSet lacks %q", w)
		}
	}
	if strings.Contains(sts, "ssl=on") || strings.Contains(legacy, "kind: CronJob") {
		t.Error("postgres.enabled must keep the old pod (no TLS, no backups)")
	}
	if !strings.Contains(docOfKind(legacy, "Deployment", "-sync"), "{ key: DATABASE_URL, path: DATABASE_URL }") {
		t.Error("postgres.enabled must keep reading DATABASE_URL from its Secret")
	}
	ext := renderChart(t, "--set", "externalDatabase.url=postgres://u:p@db/r")
	if !strings.Contains(ext, "kind: Secret") || !strings.Contains(docOfKind(ext, "Deployment", "-sync"), "secretName: t-langstroth-relay-db") {
		t.Error("externalDatabase.url must still render its Secret")
	}
	ext = renderChart(t, "--set", "externalDatabase.existingSecret=mine", "--set", "externalDatabase.existingSecretKey=dsn")
	if !strings.Contains(docOfKind(ext, "Deployment", "-sync"), "{ key: dsn, path: DATABASE_URL }") {
		t.Error("externalDatabase.existingSecret must still be honored")
	}
	for _, mix := range [][]string{
		{"--set", "database.mode=external", "--set", "database.external.existingSecret=db", "--set", "externalDatabase.url=postgres://x"},
		with(bundledArgs, "--set", "postgres.enabled=true", "--set", "postgres.existingSecret=pg"),
		{"--set", "postgres.enabled=true", "--set", "postgres.existingSecret=pg", "--set", "externalDatabase.url=postgres://x"},
	} {
		if renderChartErr(t, mix...) == "" {
			t.Errorf("%v must be refused", mix)
		}
	}
	// The deprecation is noted at install (NOTES.txt; helm template skips it,
	// and a client-side dry run assumes Kubernetes 1.20, below kubeVersion).
	if notes := installNotes(t, "--set", "postgres.enabled=true", "--set", "postgres.existingSecret=pg"); !strings.Contains(notes, "DEPRECATED: postgres.enabled is deprecated") {
		t.Errorf("install notes must flag postgres.enabled:\n%s", notes)
	}
	if notes := installNotes(t, "--set", "externalDatabase.existingSecret=x"); !strings.Contains(notes, "DEPRECATED: externalDatabase.* is deprecated") {
		t.Errorf("install notes must flag externalDatabase:\n%s", notes)
	}
}

// installNotes renders the install notes of a copy of the chart without its
// kubeVersion constraint.
func installNotes(t *testing.T, args ...string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "langstroth-relay")
	if out, err := exec.Command("cp", "-RL", "deploy/helm/langstroth-relay", dir).CombinedOutput(); err != nil {
		t.Fatalf("copy chart: %v %s", err, out)
	}
	chart, err := os.ReadFile(filepath.Join(dir, "Chart.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	chart = regexp.MustCompile(`(?m)^kubeVersion:.*$`).ReplaceAll(chart, nil)
	if err := os.WriteFile(filepath.Join(dir, "Chart.yaml"), chart, 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("helm", append([]string{"install", "t", dir, "--dry-run=client"}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("helm install --dry-run: %v\n%s", err, out)
	}
	return string(out)
}

// An upgrade with --reuse-values from a release that predates database.*
// carries values without it: the chart must still render, unchanged.
func TestChartDatabaseDefaultsWithoutDatabaseValues(t *testing.T) {
	null := filepath.Join(t.TempDir(), "null.yaml")
	if err := os.WriteFile(null, []byte("database: null\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--set", "postgres.enabled=true", "--set", "postgres.existingSecret=pg"},
		{"--set", "externalDatabase.url=postgres://u:p@db/r"},
		{},
	} {
		if a, b := renderChart(t, args...), renderChart(t, with([]string{"-f", null}, args...)...); a != b {
			t.Errorf("%v renders differently without database.* values", args)
		}
	}
	// The library's defaults are values.yaml's database block: the same keys
	// (and, for the relay, the same values but name and user).
	lib := defaultsBlock(t, "deploy/helm/langstroth-postgres/templates/_defaults.tpl", "{{- define \"langstroth-postgres.defaults\" -}}\n", "\n{{- end -}}", 0)
	relayDB := defaultsBlock(t, "deploy/helm/langstroth-relay/values.yaml", "\ndatabase:\n", "\n# DEPRECATED", 2)
	relayDB = strings.Replace(strings.Replace(relayDB, "name: relay\n", "name: \"\"\n", 1), "user: relay\n", "user: \"\"\n", 1)
	if lib != relayDB {
		t.Errorf("langstroth-postgres defaults differ from langstroth-relay values.yaml database.*:\n--- library\n%s\n--- values\n%s", lib, relayDB)
	}
	authDB := defaultsBlock(t, "deploy/helm/langstroth-auth/values.yaml", "\ndatabase:\n", "\npersistence:", 2)
	if keysOnly(lib) != keysOnly(authDB) {
		t.Errorf("langstroth-auth values.yaml database.* keys differ from the library defaults:\n%s\n---\n%s", keysOnly(lib), keysOnly(authDB))
	}
	if out, err := renderAuth(t, "-f", null); err != nil {
		t.Errorf("langstroth-auth without database values: %v\n%s", err, out)
	}
}

// pgx (relay and langstroth-auth) reads the password from the passfile named in
// the chart's DSN and verifies the server name against the mounted CA, so
// the DSN itself carries no secret.
func TestChartDSNPassfileAndVerifyFull(t *testing.T) {
	out := renderChart(t, cnpgArgs...)
	m := regexp.MustCompile(`DATABASE_URL: "([^"]+)"`).FindStringSubmatch(docNamed(out, "ConfigMap", "t-langstroth-relay-dsn"))
	if m == nil {
		t.Fatal("no DSN")
	}
	dir := t.TempDir()
	dsn := strings.ReplaceAll(m[1], "/etc/langstroth-relay/db", dir)
	if err := os.WriteFile(filepath.Join(dir, "pgpass"), []byte("t-langstroth-relay-db-rw:5432:relay:relay:s3cret\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), selfSignedCA(t), 0o440); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cc := cfg.ConnConfig
	if cc.Password != "s3cret" || cc.User != "relay" || cc.Database != "relay" {
		t.Fatalf("passfile not used: user=%q db=%q password set=%v", cc.User, cc.Database, cc.Password != "")
	}
	if cc.TLSConfig == nil || cc.TLSConfig.ServerName != "t-langstroth-relay-db-rw" || cc.TLSConfig.RootCAs == nil {
		t.Fatalf("not verify-full: %+v", cc.TLSConfig)
	}
	for _, fb := range cc.Fallbacks {
		if fb.TLSConfig == nil {
			t.Fatal("a plaintext fallback: sslmode must not allow one")
		}
	}
}

func selfSignedCA(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// langstroth-auth: the same three modes, through the shared library.
func TestAuthChartDatabaseModes(t *testing.T) {
	cases := map[string][]string{
		"cnpg":     {"--set", "database.mode=cnpg", "--set", "database.skipCapabilityCheck=true", "--set", "database.cnpg.backups.barmanObjectStore.destinationPath=s3://b/a"},
		"bundled":  {"--set", "database.mode=bundled", "--set", "database.bundled.auth.existingSecret=pga", "--set", "database.bundled.tls.existingSecret=pgtls"},
		"external": {"--set", "database.mode=external", "--set", "database.external.existingSecret=db", "--set", "database.external.cidrs[0]=10.20.0.16/32"},
		"legacy":   {"--set", "store.driver=postgres", "--set", "store.databaseUrl.existingSecret=db"},
	}
	for mode, args := range cases {
		out, err := renderAuth(t, args...)
		if err != nil {
			t.Fatalf("%s: %v\n%s", mode, err, out)
		}
		assertNoEnvSecrets(t, "langstroth-auth "+mode, out)
		if !strings.Contains(out, `"driver": "postgres"`) || !strings.Contains(out, "value: /etc/langstroth-auth/db/database-url") {
			t.Errorf("%s: store must be postgres with the DSN file", mode)
		}
		if strings.Contains(out, "kind: PersistentVolumeClaim\nmetadata:\n  name: t-langstroth-auth\n") {
			t.Errorf("%s: the file-store volume must not render with Postgres", mode)
		}
		var np string
		for _, d := range docs(out) {
			if strings.Contains(d, "kind: NetworkPolicy\n") && strings.Contains(d, "\n  name: t-langstroth-auth\n") {
				np = d
			}
		}
		switch mode {
		case "cnpg":
			if !strings.Contains(np, "cnpg.io/cluster: t-langstroth-auth-db") {
				t.Errorf("cnpg egress:\n%s", np)
			}
		case "bundled":
			if !strings.Contains(np, "app.kubernetes.io/name: langstroth-auth-postgres") {
				t.Errorf("bundled egress:\n%s", np)
			}
			// The Postgres pods must not match langstroth-auth's own selector
			// (its Service and NetworkPolicy select name+instance).
			sts := docNamed(out, "StatefulSet", "t-langstroth-auth-postgres")
			if !strings.Contains(sts, "matchLabels:\n      app.kubernetes.io/name: langstroth-auth-postgres") {
				t.Errorf("bundled Postgres pods share langstroth-auth's labels:\n%s", sts)
			}
		case "external":
			if !strings.Contains(np, "cidr: 10.20.0.16/32") {
				t.Errorf("external egress:\n%s", np)
			}
		}
	}
	for _, refuse := range [][]string{
		{"--set", "store.driver=postgres"},
		{"--set", "database.mode=external", "--set", "database.external.existingSecret=db", "--set", "store.databaseUrl.existingSecret=x"},
		{"--set", "database.mode=bundled", "--set", "database.bundled.auth.existingSecret=pga"},
		{"--set", "database.mode=cnpg"},
	} {
		if out, err := renderAuth(t, refuse...); err == nil {
			t.Errorf("langstroth-auth rendered with %v:\n%.300s", refuse, out)
		}
	}
	out, err := renderAuth(t, "--set", "database.mode=bundled", "--set", "database.bundled.auth.existingSecret=pga", "--set", "database.bundled.tls.existingSecret=pgtls",
		"--set", "database.bundled.backups.restore.file=ligus_auth-20260101T000000Z.dump")
	if err != nil || !strings.Contains(out, "replicas: 0\n") {
		t.Errorf("langstroth-auth must scale to zero during a restore: %v", err)
	}
}

// defaultsBlock returns the text between start and end in file, without
// comments or blank lines, dedented by indent.
func defaultsBlock(t *testing.T, file, start, end string, indent int) string {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, start)
	if i < 0 {
		t.Fatalf("%s: no %q", file, start)
	}
	s = s[i+len(start):]
	if j := strings.Index(s, end); j >= 0 {
		s = s[:j]
	}
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if tl := strings.TrimSpace(l); tl == "" || strings.HasPrefix(tl, "#") {
			continue
		}
		if len(l) >= indent {
			l = l[indent:]
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

func keysOnly(block string) string {
	var out []string
	for _, l := range strings.Split(block, "\n") {
		if k, _, ok := strings.Cut(l, ":"); ok {
			out = append(out, k)
		}
	}
	return strings.Join(out, "\n")
}
