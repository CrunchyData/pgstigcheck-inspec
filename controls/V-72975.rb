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


control "V-72975" do
  title "PostgreSQL must generate audit records when unsuccessful attempts to
  modify privileges/permissions occur."
  desc  "Failed attempts to change the permissions, privileges, and roles
  granted to users and roles must be tracked. Without an audit trail,
  unauthorized attempts to elevate or restrict privileges could go undetected.
  Modifying permissions is done via the GRANT and REVOKE commands.
  To aid in diagnosis, it is necessary to keep track of failed attempts in
  addition to the successful ones."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000495-DB-000329"
  tag "gid": "V-72975"
  tag "rid": "SV-87627r1_rule"
  tag "stig_id": "PGS9-00-006800"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "First, as the database administrator (shown here as
  \"postgres\"), create a role 'bob' and a test table by running the following
  SQL:
  $ sudo su - postgres
  $ psql -c \"CREATE ROLE bob; CREATE TABLE test(id INT)\"
  Next, set current role to bob and attempt to modify privileges:
  $ psql -c \"SET ROLE bob; GRANT ALL PRIVILEGES ON test TO bob;\"
  $ psql -c \"SET ROLE bob; REVOKE ALL PRIVILEGES ON test FROM bob\"
  Now, as the database administrator (shown here as \"postgres\"), verify the
  unsuccessful attempt was logged:
  $ sudo su - postgres
  $ cat ${PGDATA?}/pg_log/<latest_log>
  2016-07-14 18:12:23.208 EDT postgres postgres ERROR: permission denied for
  relation test
  2016-07-14 18:12:23.208 EDT postgres postgres STATEMENT: GRANT ALL PRIVILEGES
  ON test TO bob;
  2016-07-14 18:14:52.895 EDT postgres postgres ERROR: permission denied for
  relation test
  2016-07-14 18:14:52.895 EDT postgres postgres STATEMENT: REVOKE ALL PRIVILEGES
  ON test FROM bob;
  If audit logs are not generated when unsuccessful attempts to modify
  privileges/permissions occur, this is a finding."
  tag "fix": "Configure PostgreSQL to produce audit records when unsuccessful
  attempts to modify privileges occur.
  All denials are logged by default if logging is enabled. To ensure that
  logging is enabled, review supplementary content APPENDIX-C for instructions
  on enabling logging."
 
  describe command("PGPASSWORD='#{PG_DBA_PASSWORD}' psql -U #{PG_DBA} -d #{PG_DB} -h #{PG_HOST} -A -t -c \"CREATE ROLE fooaudit; CREATE TABLE fooaudittest (id int); SET ROLE fooaudit; GRANT ALL PRIVILEGES ON fooaudittest TO fooaudit; DROP TABLE IF EXISTS fooaudittest;\"") do
    its('stdout') { should match // }
  end

  describe command("cat `find #{PG_AUDIT_LOG_DIR} -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d\" \"` | grep \"permission denied for relation\"") do
    its('stdout') { should match /^.*fooaudittest.*$/ }
  end   
end
