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
  'pg_ver',
  description: "The version of the postgres process",
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

PG_TIMEZONE = attribute(
  'pg_timezone',
  description: 'PostgreSQL timezone',
)

control "V-72887" do
  title "PostgreSQL must record time stamps, in audit records and application
  data, that can be mapped to Coordinated Universal Time (UTC, formerly GMT)."
  desc  "If time stamps are not consistently applied and there is no common time
  reference, it is difficult to perform forensic analysis.
  Time stamps generated by PostgreSQL must include date and time. Time is
  commonly expressed in Coordinated Universal Time (UTC), a modern continuation
  of Greenwich Mean Time (GMT), or local time with an offset from UTC."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000374-DB-000322"
  tag "gid": "V-72887"
  tag "rid": "SV-87539r1_rule"
  tag "stig_id": "PGS9-00-002400"
  tag "cci": ["CCI-001890"]
  tag "nist": ["AU-8 b", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.
  When a PostgreSQL cluster is initialized using initdb, the PostgreSQL cluster
  will be configured to use the same time zone as the target server.
  As the database administrator (shown here as \"postgres\"), check the current
  log_timezone setting by running the following SQL:
  $ sudo su - postgres
  $ psql -c \"SHOW log_timezone\"
  log_timezone
  --------------
  UTC
  (1 row)
  If log_timezone is not set to the desired time zone, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.
  To change log_timezone in postgresql.conf to use a different time zone for
  logs, as the database administrator (shown here as \"postgres\"), run the
  following:
  $ sudo su - postgres
  $ vi ${PGDATA?}/postgresql.conf
  log_timezone='UTC'
  Next, restart the database:
  # SYSTEMD SERVER ONLY
  $ sudo systemctl restart postgresql-PG_VER
  # INITD SERVER ONLY
  $ sudo service postgresql-PG_VER restart"

  sql = postgres_session(PG_DBA, PG_DBA_PASSWORD, PG_HOST)

  describe sql.query('SHOW log_timezone;', [PG_DB]) do
    its('output') { should eq PG_TIMEZONE }
  end
end
