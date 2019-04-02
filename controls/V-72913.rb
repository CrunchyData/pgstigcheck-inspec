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

control "V-72913" do
  title "PostgreSQL must produce audit records of its enforcement of access
  restrictions associated with changes to the configuration of PostgreSQL or
  database(s)."
  desc  "Without auditing the enforcement of access restrictions against changes
  to configuration, it would be difficult to identify attempted attacks and an
  audit trail would not be available for forensic investigation for
  after-the-fact actions.
  Enforcement actions are the methods or mechanisms used to prevent unauthorized
  changes to configuration settings. Enforcement action methods may be as simple
  as denying access to a file based on the application of file permissions
  (access restriction). Audit items may consist of lists of actions blocked by
  access restrictions or changes identified after the fact."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000381-DB-000361"
  tag "gid": "V-72913"
  tag "rid": "SV-87565r1_rule"
  tag "stig_id": "PGS9-00-004100"
  tag "cci": "CCI-001814"
  tag "nist": ["CM-5 (1)", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.
  To verify that system denies are logged when unprivileged users attempt to
  change database configuration, as the database administrator (shown here as
  \"postgres\"), run the following commands:
  $ sudo su - postgres
  $ psql
  Next, create a role with no privileges, change the current role to that user
  and attempt to change a configuration by running the following SQL:
  CREATE ROLE bob;
  SET ROLE bob;
  SET pgaudit.role='test';
  Now check pg_log (use the latest log):
  $ cat ${PGDATA?}/pg_log/postgresql-Thu.log
  < 2016-01-28 17:57:34.092 UTC bob postgres: >ERROR: permission denied to set
  parameter \"pgaudit.role\"
  < 2016-01-28 17:57:34.092 UTC bob postgres: >STATEMENT: SET pgaudit.role='test';
  If the denial is not logged, this is a finding.
  By default PostgreSQL configuration files are owned by the postgres user and
  cannot be edited by non-privileged users:
  $ ls -la ${PGDATA?} | grep postgresql.conf
  -rw-------. 1 postgres postgres 21758 Jan 22 10:27 postgresql.conf
  If postgresql.conf is not owned by the database owner and does not have read
  and write permissions for the owner, this is a finding."
  tag "fix": "Enable logging.
  All denials are logged by default if logging is enabled. To ensure that
  logging is enabled, review supplementary content APPENDIX-C for instructions
  on enabling logging."

  #Execute an incorrectly-formed SQL statement with bad syntax, to prompt log ouput

  describe command("PGPASSWORD='#{PG_DBA_PASSWORD}' psql -U #{PG_DBA} -d #{PG_DB} -h #{PG_HOST} -A -t -c \"CREATE ROLE pgauditrolefailuretest; SET ROLE pgauditrolefailuretest; SET pgaudit.role='test'; SET ROLE postgres; DROP ROLE IF EXISTS pgauditrolefailuretest;\"") do
    its('stdout') { should match // }
  end

  #Find the most recently modified log file in the pg_audit_log_dir, grep for the syntax error statement, and then
  #test to validate the output matches the regex.

  describe command("cat `find #{PG_AUDIT_LOG_DIR} -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d\" \"` | grep \"permission denied to set parameter\"") do
    its('stdout') { should match /^.*permission denied to set parameter .pgaudit.role..*$/ }
  end

end
