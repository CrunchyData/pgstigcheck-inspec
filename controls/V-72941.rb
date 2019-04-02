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

control "V-72941" do
  title "PostgreSQL must generate audit records when unsuccessful attempts to
  retrieve privileges/permissions occur."
  desc  "Under some circumstances, it may be useful to monitor who/what is
  reading privilege/permission/role information. Therefore, it must be possible
  to configure auditing to do this. PostgreSQLs typically make such information
  available through views or functions.
  This requirement addresses explicit requests for privilege/permission/role
  membership information. It does not refer to the implicit retrieval of
  privileges/permissions/role memberships that PostgreSQL continually performs
  to determine if any and every action on the database is permitted.
  To aid in diagnosis, it is necessary to keep track of failed attempts in
  addition to the successful ones."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000091-DB-000325"
  tag "gid": "V-72941"
  tag "rid": "SV-87593r1_rule"
  tag "stig_id": "PGS9-00-005300"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.
  First, as the database administrator (shown here as \"postgres\"), create a
  role 'bob' by running the following SQL:
  $ sudo su - postgres
  $ psql -c \"CREATE ROLE bob\"
  Next, attempt to retrieve information from the pg_authid table:
  $ psql -c \"SET ROLE bob; SELECT * FROM pg_authid\"
  Now, as the database administrator (shown here as \"postgres\"), verify the
  event was logged in pg_log:
  $ sudo su - postgres
  $ cat ${PGDATA?}/pg_log/<latest_log>
  < 2016-07-13 16:49:58.864 EDT postgres postgres ERROR: > permission denied for
  relation pg_authid
  < 2016-07-13 16:49:58.864 EDT postgres postgres STATEMENT: >
  SELECT * FROM pg_authid;
  If the above steps cannot verify that audit records are produced when
  PostgreSQL denies retrieval of privileges/permissions/role memberships, this
  is a finding."
  tag "fix": "Configure PostgreSQL to produce audit records when unsuccessful
  attempts to access privileges occur.
  All denials are logged if logging is enabled. To ensure that logging is
  enabled, review supplementary content APPENDIX-C for instructions on enabling
  logging."

  describe command("PGPASSWORD='#{PG_DBA_PASSWORD}' psql -U #{PG_DBA} -d #{PG_DB} -h #{PG_HOST} -A -t -c \"CREATE ROLE fooaudit; SET ROLE fooaudit; SELECT * FROM pg_authid; SET ROLE postgres; DROP ROLE fooaudit;\"") do
    its('stdout') { should match // }
  end

 describe command("cat `find #{PG_AUDIT_LOG_DIR} -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d\" \"` | grep \"permission denied for relation\"") do
   its('stdout') { should match /^.*pg_authid.*$/ }
 end

end
