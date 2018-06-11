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

control "V-72923" do
  title "PostgreSQL must generate audit records when unsuccessful logons or
  connection attempts occur."
  desc  "For completeness of forensic analysis, it is necessary to track failed
  attempts to log on to PostgreSQL. While positive identification may not be
  possible in a case of failed authentication, as much information as possible
  about the incident must be captured."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000503-DB-000351"
  tag "gid": "V-72923"
  tag "rid": "SV-87575r1_rule"
  tag "stig_id": "PGS9-00-004600"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.
  In this example the user joe will log into the Postgres database unsuccessfully:
  $ psql -d postgres -U joe
  As the database administrator (shown here as \"postgres\"), check pg_log for a
  FATAL connection audit trail:
  $ sudo su - postgres
  $ cat ${PGDATA?}/pg_log/postgresql-Tue.log
  < 2016-02-16 16:18:13.027 EST joe 56c65135.b5f postgres: >LOG: connection
  authorized: user=joe database=postgres
  < 2016-02-16 16:18:13.027 EST joe 56c65135.b5f postgres: >FATAL: role \"joe\"
  does not exist
  If an audit record is not generated each time a user (or other principal)
  attempts, but fails to log on or connect to PostgreSQL (including attempts
  where the user ID is invalid/unknown), this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.
  To ensure that logging is enabled, review supplementary content APPENDIX-C for
  instructions on enabling logging.
  If logging is enabled the following configurations must be made to log
  unsuccessful connections, date/time, username, and session identifier.
  First, as the database administrator (shown here as \"postgres\"), edit
  postgresql.conf:
  $ sudo su - postgres
  $ vi ${PGDATA?}/postgresql.conf
  Edit the following parameters:
  log_connections = on
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

  describe command("PGPASSWORD='#{PG_DBA_PASSWORD}' psql -U #{PG_DBA} -d #{PG_DB} -h #{PG_HOST} -A -t -c \"SET ROLE pgauditrolefailuretest;\"") do
    its('stdout') { should match // }
  end

  describe command("cat `find #{PG_AUDIT_LOG_DIR} -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d\" \"` | grep \"does not exist\"") do
    its('stdout') { should match /^.*role .foo. does not exist.*$/ }
  end

end
