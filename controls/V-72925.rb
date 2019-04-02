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

control "V-72925" do
  title "PostgreSQL must generate audit records showing starting and ending time
  for user access to the database(s)."
  desc  "For completeness of forensic analysis, it is necessary to know how long
  a user's (or other principal's) connection to PostgreSQL lasts. This can be
  achieved by recording disconnections, in addition to logons/connections, in
  the audit logs.
  Disconnection may be initiated by the user or forced by the system (as in a
  timeout) or result from a system or network failure. To the greatest extent
  possible, all disconnections must be logged."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000505-DB-000352"
  tag "gid": "V-72925"
  tag "rid": "SV-87577r1_rule"
  tag "stig_id": "PGS9-00-004700"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.
  First, log into the database with the postgres user by running the following
  commands:
  $ sudo su - postgres
  $ psql -U postgres
  Next, as the database administrator, verify the log for a connection audit trail:
  $ sudo su - postgres
  $ cat ${PGDATA?}/pg_log/postgresql-Tue.log
  < 2016-02-23 20:25:39.931 EST postgres 56cfa993.7a72 postgres: >LOG: connection
  authorized: user=postgres database=postgres
  < 2016-02-23 20:27:45.428 EST postgres 56cfa993.7a72 postgres: >LOG:
  AUDIT: SESSION,1,1,READ,SELECT,,,SELECT current_user;,<none>
  < 2016-02-23 20:27:47.988 EST postgres 56cfa993.7a72 postgres: >LOG:
  disconnection: session time: 0:00:08.057 user=postgres database=postgres
  host=[local]
  If connections are not logged, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.
  To ensure that logging is enabled, review supplementary content APPENDIX-C for
  instructions on enabling logging.
  If logging is enabled the following configurations must be made to log
  connections, date/time, username, and session identifier.
  First, as the database administrator (shown here as \"postgres\"), edit
  postgresql.conf by running the following:
  $ sudo su - postgres
  $ vi ${PGDATA?}/postgresql.conf
  Edit the following parameters:
  log_connections = on
  log_disconnections = on
  log_line_prefix = '< %m %u %c: >'
  Where:
  * %m is the time and date
  * %u is the username
  * %c is the session ID for the connection
  Now, as the system administrator, reload the server with the new configuration:
  # SYSTEMD SERVER ONLY
  $ sudo systemctl reload postgresql-9.5
  # INITD SERVER ONLY
  $ sudo service postgresql-9.5 reload"

  describe command("cat `find #{PG_AUDIT_LOG_DIR} -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d\" \"` | grep \"connection authorized\"") do
    its('stdout') { should match /^.*user=postgres.*$/ }
  end

end
