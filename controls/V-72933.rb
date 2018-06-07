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

control "V-72933" do
  title "PostgreSQL must generate audit records when successful logons or
  connections occur."
  desc  "For completeness of forensic analysis, it is necessary to track
  who/what (a user or other principal) logs on to PostgreSQL."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000503-DB-000350"
  tag "gid": "V-72933"
  tag "rid": "SV-87585r1_rule"
  tag "stig_id": "PGS9-00-005100"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.
  First, as the database administrator (shown here as \"postgres\"), check if
  log_connections is enabled by running the following SQL:
  $ sudo su - postgres
  $ psql -c \"SHOW log_connections\"
  If log_connections is off, this is a finding.
  Next, verify the logs that the previous connection to the database was logged:
  $ sudo su - postgres
  $ cat ${PGDATA?}/pg_log/<latest_log>
  < 2016-02-16 15:54:03.934 EST postgres postgres 56c64b8b.aeb: >LOG: connection
  authorized: user=postgres database=postgres
  If an audit record is not generated each time a user (or other principal) logs
  on or connects to PostgreSQL, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.
  To ensure that logging is enabled, review supplementary content APPENDIX-C for
  instructions on enabling logging.
  If logging is enabled the following configurations must be made to log
  connections, date/time, username, and session identifier.
  First, as the database administrator (shown here as \"postgres\"), edit
  postgresql.conf:
  $ sudo su - postgres
  $ vi ${PGDATA?}/postgresql.conf
  Edit the following parameters as such:
  log_connections = on
  log_line_prefix = '< %m %u %d %c: >'
  Where:
  * %m is the time and date
  * %u is the username
  * %d is the database
  * %c is the session ID for the connection
  Now, as the system administrator, reload the server with the new configuration:
  # SYSTEMD SERVER ONLY
  $ sudo systemctl reload postgresql-9.5
  # INITD SERVER ONLY
  $ sudo service postgresql-9.5 reload"

 describe command("PGPASSWORD='#{PG_DBA_PASSWORD}' psql -U #{PG_DBA} -d #{PG_DB} -h #{PG_HOST} -A -t -c \"SHOW log_connections\"") do
   its('stdout') { should match /on/ }
 end

  describe command("cat `find #{PG_AUDIT_LOG_DIR} -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d\" \"` | grep \"connection authorized\"") do
    its('stdout') { should match /^.*user=postgres.*$/ }
  end

end
