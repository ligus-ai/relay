package deploy

import (
	"strings"
	"testing"
)

// Adversarial review of database.mode (k8s/postgres).

// R-1: the external-mode CIDR checks only looked at IPv4 text. IPv6 had the
// same /8 floor as IPv4 (an IPv6 /8 is 2^120 addresses), and an IPv4-mapped
// or IPv6 metadata address was accepted.
func TestChartDatabaseExternalCIDRRefusesIPv6Bypasses(t *testing.T) {
	for _, cidr := range []string{
		"::/0",
		"::/8",
		"2001:db8::/16",
		"::ffff:169.254.169.254/128",
		"::ffff:a9fe:a9fe/128",
		"::ffff:0:0/96",
		"0:0:0:0:0:ffff:a9fe:a9fe/128",
		"::169.254.169.254/128",
		"64:ff9b::a9fe:a9fe/128",
		"fd00:ec2::254/128",
		"FD00:0EC2:0000::/48",
	} {
		msg := renderChartErr(t, "--set", "database.mode=external", "--set", "database.external.existingSecret=db",
			"--set", "database.external.cidrs[0]="+cidr)
		if msg == "" {
			t.Errorf("cidr %s rendered; want a refusal", cidr)
		}
	}
	for _, ok := range []string{"2001:db8:1:2::15/128", "2001:db8:1::/48", "10.20.0.15/32"} {
		if msg := renderChartErr(t, "--set", "database.mode=external", "--set", "database.external.existingSecret=db",
			"--set", "database.external.cidrs[0]="+ok); msg != "" {
			t.Errorf("cidr %s must render: %s", ok, msg)
		}
	}
}

// R-2: database.bundled.parameters came after the chart's own -c settings, so
// a value could turn TLS off, swap the pg_hba file or weaken the password
// hashing without any refusal.
func TestChartDatabaseBundledParametersCannotOverrideSecurity(t *testing.T) {
	for _, kv := range []string{
		"ssl=off", "hba_file=/var/lib/postgresql/data/pgdata/pg_hba.conf", "password_encryption=md5",
		"ssl_min_protocol_version=TLSv1", "ssl_cert_file=/x", "ssl_key_file=/x", "ssl_ca_file=/x",
		"listen_addresses=*", "SSL=off", "ident_file=/x",
	} {
		k, v, _ := strings.Cut(kv, "=")
		msg := renderChartErr(t, with(bundledArgs, "--set-string", "database.bundled.parameters."+k+"="+v)...)
		if msg == "" {
			t.Errorf("parameters.%s rendered; want a refusal", kv)
		}
	}
	if msg := renderChartErr(t, with(bundledArgs, "--set-string", "database.bundled.parameters.max_connections=50")...); msg != "" {
		t.Errorf("an ordinary parameter must render: %s", msg)
	}
}

// R-3: the init script interpolates the role password into CREATE ROLE, so
// any statement logging (a parameter, or an error) would write it to the pod
// log. The session must turn statement logging off first.
func TestChartDatabaseBundledInitDoesNotLogPassword(t *testing.T) {
	out := renderChart(t, bundledArgs...)
	cm := docNamed(out, "ConfigMap", "t-langstroth-relay-postgres-conf")
	create := strings.Index(cm, "CREATE ROLE")
	for _, want := range []string{"SET log_statement = 'none'", "SET log_min_error_statement = 'panic'", "SET log_min_duration_statement = -1"} {
		i := strings.Index(cm, want)
		if i < 0 || i > create {
			t.Errorf("init script must %q before CREATE ROLE:\n%s", want, cm)
		}
	}
}

// R-4: the restore Job starts while the old app pods are still terminating;
// it must wait for the application role's other sessions to end so nothing
// writes into the database during or right after the restore.
func TestChartDatabaseBundledRestoreWaitsForAppSessions(t *testing.T) {
	out := renderChart(t, with(bundledArgs, "--set", "database.bundled.backups.restore.file=relay-20260101T031700Z.dump")...)
	var job string
	for _, d := range docs(out) {
		if strings.Contains(d, "kind: Job\n") && strings.Contains(d, "postgres-restore-") {
			job = d
		}
	}
	w := strings.Index(job, "pg_stat_activity")
	r := strings.Index(job, "pg_restore --clean")
	if w < 0 || w > r {
		t.Errorf("restore must wait on pg_stat_activity before pg_restore --clean:\n%s", job)
	}
}
