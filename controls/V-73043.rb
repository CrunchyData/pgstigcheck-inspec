pg_owner = input('pg_owner')

pg_group = input('pg_owner')

pg_ver = input('pg_ver')

pg_data_dir = input('pg_data_dir')

pg_shared_dirs = input(
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
  desc  "Protecting audit data also includes identifying and protecting the
  tools used to view and manipulate log data. Therefore, protecting audit tools
  is necessary to prevent unauthorized operation on audit data.

  Applications providing tools to interface with audit data will leverage
  user permissions and roles identifying the user accessing the tools and the
  corresponding rights the user enjoys in order make access decisions regarding
  the deletion of audit tools.

  Audit tools include, but are not limited to, vendor-provided and open
  source audit tools needed to successfully view and manipulate audit information
  system activity and records. Audit tools include custom queries and report
  generators."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000123-DB-000204"
  tag "gid": "V-73043"
  tag "rid": "SV-87695r2_rule"
  tag "stig_id": "PGS9-00-011200"
  tag "fix_id": "F-79489r2_fix"
  tag "cci": ["CCI-001495"]
  tag "nist": ["AU-9", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  desc "check", "Note: The following instructions use the PGDATA and PGVER
  environment variables. See supplementary content APPENDIX-F for instructions on
  configuring PGDATA and APPENDIX-H for PGVER.

  As the database administrator (shown here as \"postgres\"), verify the
  permissions of PGDATA:

  $ sudo su - postgres
  $ ls -la ${PGDATA?}

  If PGDATA is not owned by postgres:postgres or if files can be accessed by
  others, this is a finding.

  As the system administrator, verify the permissions of pgsql shared objects and
  compiled binaries:

  $ ls -la /usr/pgsql-${PGVER?}/bin
  $ ls -la /usr/pgsql-${PGVER?}/include
  $ ls -la /usr/pgsql-${PGVER?}/lib
  $ ls -la /usr/pgsql-${PGVER?}/share

  If any of these are not owned by root:root, this is a finding."
  
  desc "fix", "Note: The following instructions use the PGDATA and PGVER
  environment variables. See supplementary content APPENDIX-F for instructions on
  configuring PGDATA and APPENDIX-H for PGVER.

  As the system administrator, change the permissions of PGDATA:

  $ sudo chown -R postgres:postgres ${PGDATA?}
  $ sudo chmod 700 ${PGDATA?}

  As the system administrator, change the permissions of pgsql:

  $ sudo chown -R root:root /usr/pgsql-${PGVER?}"

# @todo should the permissions of stig-postgresql.conf, pg_ident and pg_hba be '0600'

  describe directory(pg_data_dir) do
    it { should be_owned_by pg_owner }
    it { should be_grouped_into pg_group }
  end

  describe command("find #{pg_data_dir} ! -user #{pg_owner} | wc -l") do
    its('stdout') { should cmp 0 }
  end

  describe command("find #{pg_data_dir} ! -group #{pg_group} | wc -l") do
    its('stdout') { should cmp 0 }
  end

  # note this accounts for stig-postgresql.conf, hba_conf, pg_ident
  describe command("find /var/lib/pgsql/9.5/data/ ! -perm 600 -type f | wc -l") do
    its('stdout.strip') { should be <= '3' }
  end

  describe command("find /var/lib/pgsql/9.5/data/ ! -perm 700 -type d | wc -l") do
    its('stdout.strip') { should cmp "0" }
  end

  pg_shared_dirs.each do |dir|
    next unless directory(dir).exist?
    describe directory(dir) do
      it { should be_owned_by 'root' }
      it { should be_grouped_into 'root' }
    end
  end

end
