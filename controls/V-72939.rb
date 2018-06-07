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

PG_VER = attribute(
  'pg_version',
  description: "The version of the PostgreSQL process which is being inspected (tested)",
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

PG_LOG_DIR = attribute(
  'pg_log_dir',
  description: 'define path for the postgreql log directory',
  default: '/var/lib/pgsql/9.5/data/pg_log'
)

PG_AUDIT_LOG_DIR = attribute(
  'pg_audit_log_dir',
  description: 'define path for the postgreql audit log directory',
  default: '/var/lib/pgsql/9.5/data/pg_log'
)

control "V-72939" do
  title "PostgreSQL must generate audit records when security objects are
  deleted."
  desc  "The removal of security objects from the database/PostgreSQL would
  seriously degrade a system's information assurance posture. If such an event
  occurs, it must be logged."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000501-DB-000336"
  tag "gid": "V-72939"
  tag "rid": "SV-87591r1_rule"
  tag "stig_id": "PGS9-00-005200"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.
  First, as the database administrator (shown here as \"postgres\"), create a
  test table stig_test, enable row level security, and create a policy by
  running the following SQL:
  $ sudo su - postgres
  $ psql -c \"CREATE TABLE stig_test(id INT)\"
  $ psql -c \"ALTER TABLE stig_test ENABLE ROW LEVEL SECURITY\"
  $ psql -c \"CREATE POLICY lock_table ON stig_test USING ('postgres' =
  current_user)\"
  Next, drop the policy and disable row level security:
  $ psql -c \"DROP POLICY lock_table ON stig_test\"
  $ psql -c \"ALTER TABLE stig_test DISABLE ROW LEVEL SECURITY\"
  Now, as the database administrator (shown here as \"postgres\"), verify the
  security objects deletions were logged:
  $ cat ${PGDATA?}/pg_log/<latest_log>
  2016-03-30 14:54:18.991 EDT postgres postgres LOG: AUDIT:
  SESSION,11,1,DDL,DROP POLICY,,,DROP POLICY lock_table ON stig_test;,<none>
  2016-03-30 14:54:42.373 EDT postgres postgres LOG: AUDIT:
  SESSION,12,1,DDL,ALTER TABLE,,,ALTER TABLE stig_test DISABLE ROW LEVEL
  SECURITY;,<none>
  If audit records are not produced when security objects are dropped, this is a
  finding."
  tag "fix": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.
  Using pgaudit PostgreSQL can be configured to audit these requests. See
  supplementary content APPENDIX-B for documentation on installing pgaudit.
  With pgaudit installed the following configurations can be made:
  $ sudo su - postgres
  $ vi ${PGDATA?}/postgresql.conf
  Add the following parameters (or edit existing parameters):
  pgaudit.log = 'ddl'
  Now, as the system administrator, reload the server with the new configuration:
  # SYSTEMD SERVER ONLY
  $ sudo systemctl reload postgresql-9.5
  # INITD SERVER ONLY
  $ sudo service postgresql-9.5 reload"

  describe command("PGPASSWORD='#{PG_DBA_PASSWORD}' psql -U #{PG_DBA} -d #{PG_DB} -h #{PG_HOST} -A -t -c \"CREATE TABLE stig_test(id INT); ALTER TABLE stig_test ENABLE ROW LEVEL SECURITY; CREATE POLICY lock_table ON stig_test USING ('postgres' = current_user); DROP POLICY lock_table ON stig_test; ALTER TABLE stig_test DISABLE ROW LEVEL SECURITY; DROP TABLE stig_test;\"") do
    its('stdout') { should match // }
  end

  describe command("cat `find #{PG_AUDIT_LOG_DIR} -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d\" \"` | grep \"AUDIT: SESSION\"") do
    its('stdout') { should match /^.*CREATE TABLE,TABLE,public.stig_test.*$/ }
  end

  describe command("cat `find #{PG_AUDIT_LOG_DIR} -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d\" \"` | grep \"AUDIT: SESSION\"") do
    its('stdout') { should match /^.*ALTER TABLE stig_test ENABLE ROW LEVEL SECURITY.*$/ }
  end

  describe command("cat `find #{PG_AUDIT_LOG_DIR} -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d\" \"` | grep \"AUDIT: SESSION\"") do
    its('stdout') { should match /^.*CREATE POLICY,POLICY,lock_table.*$/ }
  end

  describe command("cat `find #{PG_AUDIT_LOG_DIR} -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d\" \"` | grep \"AUDIT: SESSION\"") do
    its('stdout') { should match /^.*DROP POLICY lock_table ON stig_test.*$/ }
  end

  describe command("cat `find #{PG_AUDIT_LOG_DIR} -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d\" \"` | grep \"AUDIT: SESSION\"") do
    its('stdout') { should match /^.*ALTER TABLE stig_test DISABLE ROW LEVEL SECURITY.*$/ }
  end

  describe command("cat `find #{PG_AUDIT_LOG_DIR} -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d\" \"` | grep \"AUDIT: SESSION\"") do
    its('stdout') { should match /^.*DROP TABLE stig_test.*$/ }
  end

end
