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

control "V-72945" do
  title "PostgreSQL must generate audit records when unsuccessful attempts to
  delete privileges/permissions occur."
  desc  "Failed attempts to change the permissions, privileges, and roles
  granted to users and roles must be tracked. Without an audit trail,
  unauthorized attempts to elevate or restrict privileges could go undetected.
  In an SQL environment, deleting permissions is typically done via the REVOKE
  command.
  To aid in diagnosis, it is necessary to keep track of failed attempts in
  addition to the successful ones."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000499-DB-000331"
  tag "gid": "V-72945"
  tag "rid": "SV-87597r1_rule"
  tag "stig_id": "PGS9-00-005400"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.
  First, as the database administrator (shown here as \"postgres\"), create the
  roles joe and bob with LOGIN by running the following SQL:
  $ sudo su - postgres
  $ psql -c \"CREATE ROLE joe LOGIN\"
  $ psql -c \"CREATE ROLE bob LOGIN\"
  Next, set current role to bob and attempt to alter the role joe:
  $ psql -c \"SET ROLE bob; ALTER ROLE joe NOLOGIN\"
  Now, as the database administrator (shown here as \"postgres\"), verify the
  denials are logged:
  $ sudo su - postgres
  $ cat ${PGDATA?}/pg_log/<latest_log>
  < 2016-03-17 11:28:10.004 EDT bob 56eacd05.cda postgres: >ERROR: permission
  denied to drop role
  < 2016-03-17 11:28:10.004 EDT bob 56eacd05.cda postgres:
  >STATEMENT: DROP ROLE joe;
  If audit logs are not generated when unsuccessful attempts to delete
  privileges/permissions occur, this is a finding."
  tag "fix": "Configure PostgreSQL to produce audit records when unsuccessful
  attempts to delete privileges occur.
  All denials are logged if logging is enabled. To ensure that logging is
  enabled, review supplementary content APPENDIX-C for instructions on enabling
  logging."

  describe command("PGPASSWORD='#{PG_DBA_PASSWORD}' psql -U #{PG_DBA} -d #{PG_DB} -h #{PG_HOST} -A -t -c \"CREATE ROLE pgauditrolefailuretest; SET ROLE pgauditrolefailuretest; DROP ROLE postgres; SET ROLE postgres; DROP ROLE pgauditrolefailuretest;\"") do
    its('stdout') { should match // }
  end

 describe command("cat `find #{PG_AUDIT_LOG_DIR} -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d\" \"` | grep \"permission denied to drop role\"") do
   its('stdout') { should match /^.*permission denied to drop role.*$/ }
 end

end
