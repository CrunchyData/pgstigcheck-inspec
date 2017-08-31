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
)

PG_DBA = attribute(
  'pg_dba',
  description: 'The postgres DBA user to access the test database',
)

PG_DBA_PASSWORD = attribute(
  'pg_dba_password',
  description: 'The password for the postgres DBA user',
)

PG_DB = attribute(
  'pg_db',
  description: 'The database used for tests',
)

PG_HOST = attribute(
  'pg_host',
  description: 'The hostname or IP address used to connect to the database',
)

PG_DATA_DIR = attribute(
  'pg_data_dir',
  description: 'The postgres data directory',
)

PG_SUPERUSERS = attribute(
  'pg_superusers',
  description: 'Authorized superuser accounts',
)

control "V-72891" do

  title "PostgreSQL must allow only the ISSM (or individuals or roles appointed
  by the ISSM) to select which auditable events are to be audited."
  desc  "Without the capability to restrict which roles and individuals can
  select which events are audited, unauthorized personnel may be able to prevent
  or interfere with the auditing of critical events.

  Suppression of auditing could permit an adversary to evade detection.

  Misconfigured audits can degrade the system's performance by overwhelming the
  audit log. Misconfigured audits may also make it more difficult to establish,
  correlate, and investigate the events relating to an incident or identify those
  responsible for one."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000090-DB-000065"
  tag "gid": "V-72891"
  tag "rid": "SV-87543r1_rule"
  tag "stig_id": "PGS9-00-002600"
  tag "cci": "CCI-000171"
  tag "nist": ["AU-12 b", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.
  Check PostgreSQL settings and documentation to determine whether designated
  personnel are able to select which auditable events are being audited.
  As the database administrator (shown here as \"postgres\"), verify the
  permissions for PGDATA:
  $ ls -la ${PGDATA?}
  If anything in PGDATA is not owned by the database administrator, this is a
  finding.
  Next, as the database administrator, run the following SQL:
  $ sudo su - postgres
  $ psql -c \"\\du\"
  Review the role permissions, if any role is listed as superuser but should not
  have that access, this is a finding."
  tag "fix": "Configure PostgreSQL's settings to allow designated personnel to
  select which auditable events are audited.
  Using pgaudit allows administrators the flexibility to choose what they log.
  For an overview of the capabilities of pgaudit, see
  https://github.com/pgaudit/pgaudit.
  See supplementary content APPENDIX-B for documentation on installing pgaudit.
  See supplementary content APPENDIX-C for instructions on enabling logging.
  Only administrators/superuser can change PostgreSQL configurations. Access to
  the database administrator must be limited to designated personnel only.
  To ensure that postgresql.conf is owned by the database owner:
  $ chown postgres:postgres ${PGDATA?}/postgresql.conf
  $ chmod 600 ${PGDATA?}/postgresql.conf"

  describe directory(PG_DATA_DIR) do
    it { should be_directory }
    it { should be_owned_by PG_OWNER }
    its('mode') { should cmp '0700' }
  end

  sql = postgres_session(PG_DBA, PG_DBA_PASSWORD, PG_HOST)

  roles_sql = 'SELECT r.rolname FROM pg_catalog.pg_roles r;'
  roles_query = sql.query(roles_sql, [PG_DB])
  roles = roles_query.lines

  roles.each do |role|
    unless PG_SUPERUSERS.include?(role)
      superuser_sql = "SELECT r.rolsuper FROM pg_catalog.pg_roles r "\
        "WHERE r.rolname = '#{role}';"

      describe sql.query(superuser_sql, [PG_DB]) do
        its('output') { should_not eq 't' }
      end
    end
  end
end
