# encoding: utf-8
#
=begin
-----------------
Benchmark: PostgreSQL 9.x Security Technical Implementation Guide
Status: Accepted

This Security Technical Implementation Guide is published as a tool to improve
the security of Department of Defense (DoD) information systems. The
requirements are derived from the National Institute of Standards and
Technology (NIST) 800-53 and related documents. Comments or proposed revisions
to this document should be sent via email to the following address:
disa.stig_spt@mail.mil.

Release Date: 2017-01-20
Version: 1
Publisher: DISA
Source: STIG.DOD.MIL
uri: http://iase.disa.mil
-----------------
=end

PG_OWNER = attribute(
  'pg_owner',
  description: "The system user of the postgres process",
  default: 'postgres'
)

PG_GROUP = attribute(
  'pg_owner',
  description: "The system user of the postgres process",
  default: 'postgres'
)

PG_VER = attribute(
  'pg_ver',
  description: "The version of postgres that is running",
  default: postgres.version
)

PG_DATA_DIR = attribute(
  'pg_data_dir',
  description: 'the postgres data dir',
  default: postgres.data_dir
)

PG_SHARED_DIRS = attribute(
  'pg_shared_dirs',
  description: 'the postgres shared_libraries directories',
  default: [
    "/usr/pgsql-#{postgres.version}",
    "/usr/pgsql-#{postgres.version}/bin",
    "/usr/pgsql-#{postgres.version}/include",
    "/usr/pgsql-#{postgres.version}/lib",
    "/usr/pgsql-#{postgres.version}/share"
    ]
)

control "V-73043" do
  title "PostgreSQL must protect its audit features from unauthorized removal."
  desc  "Protecting audit data also includes identifying and protecting the tools
used to view and manipulate log data. Therefore, protecting audit tools is necessary
to prevent unauthorized operation on audit data.

Applications providing tools to interface with audit data will leverage user
permissions and roles identifying the user accessing the tools and the corresponding
rights the user enjoys in order make access decisions regarding the deletion of
audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit
tools needed to successfully view and manipulate audit information system activity
and records. Audit tools include custom queries and report generators."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000123-DB-000204"
  tag "gid": "V-73043"
  tag "rid": "SV-87695r1_rule"
  tag "stig_id": "PGS9-00-011200"
  tag "cci": "CCI-001495"
  tag "nist": ["AU-9", "Rev_4"]
  tag "check": "As the database administrator (shown here as \"postgres\"), verify
the permissions of PGDATA:

$ sudo su - postgres
$ ls -la ${PGDATA?}

If PGDATA is not owned by postgres:postgres or if files can be accessed by others,
this is a finding.

As the system administrator, verify the permissions of pgsql shared objects and
compiled binaries:

$ ls -la /usr/pgsql-9.5/bin/
$ ls -la /usr/pgsql-9.5/share/
$ ls -la /usr/pgsql-9.5/include/

If any of these are not owned by root:root, this is a finding."

  tag "fix": "As the system administrator, change the permissions of PGDATA:

$ sudo chown -R postgres:postgres ${PGDATA?}
$ sudo chmod 700 ${PGDATA?}

As the system administrator, change the permissions of pgsql:

$ sudo chown -R root:root /usr/pgsql-9.5/share/contrib/"

# @todo should the permissions of stig-postgresql.conf, pg_ident and pg_hba be '0600'

  describe directory(PG_DATA_DIR) do
    it { should be_owned_by PG_OWNER }
    it { should be_grouped_into PG_GROUP }
  end

  describe command("find #{PG_DATA_DIR} ! -user #{PG_OWNER} | wc -l") do
    its('stdout') { should cmp 0 }
  end

  describe command("find #{PG_DATA_DIR} ! -group #{PG_GROUP} | wc -l") do
    its('stdout') { should cmp 0 }
  end

  # note this accounts for stig-postgresql.conf, hba_conf, pg_ident
  describe command("find /var/lib/pgsql/9.5/data/ ! -perm 600 -type f | wc -l") do
    its('stdout.strip') { should be <= '3' }
  end

  describe command("find /var/lib/pgsql/9.5/data/ ! -perm 700 -type d | wc -l") do
    its('stdout.strip') { should cmp "0" }
  end

  PG_SHARED_DIRS.each do |dir|
    next unless directory(dir).exist?
    describe directory(dir) do
      it { should be_owned_by 'root' }
      it { should be_grouped_into 'root' }
    end
  end

  describe directory("/usr/pgsql-#{postgres.version}/share/contrib") do
    # only_if { directory("/usr/pgsql-#{PG_VER}/share/contrib").exist? }
    it { should be_grouped_into 'root' }
    it { should be_owned_by 'root' }
  end
end
