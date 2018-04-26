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

control "V-72963" do
  title "PostgreSQL must generate audit records when unsuccessful attempts to
  delete security objects occur."
  desc  "The removal of security objects from the database/PostgreSQL would
  seriously degrade a system's information assurance posture. If such an action
  is attempted, it must be logged.
  To aid in diagnosis, it is necessary to keep track of failed attempts in
  addition to the successful ones."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000501-DB-000337"
  tag "gid": "V-72963"
  tag "rid": "SV-87615r1_rule"
  tag "stig_id": "PGS9-00-006300"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.
  First, as the database administrator, verify pgaudit is enabled by running the
  following SQL:
  $ sudo su - postgres
  $ psql -c \"SHOW shared_preload_libraries\"
  If the output does not contain pgaudit, this is a finding.
  Next, verify that role, read, write, and ddl auditing are enabled:
  $ psql -c \"SHOW pgaudit.log\"
  If the output does not contain role, read, write, and ddl, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.
  Configure PostgreSQL to produce audit records when unsuccessful attempts to
  delete security objects occur.
  All errors and denials are logged if logging is enabled. To ensure that
  logging is enabled, review supplementary content APPENDIX-C for instructions
  on enabling logging.
  With pgaudit installed the following configurations can be made:
  $ sudo su - postgres
  $ vi ${PGDATA?}/postgresql.conf
  Add the following parameters (or edit existing parameters):
  pgaudit.log='ddl, role, read, write'
  Now, as the system administrator, reload the server with the new configuration:
  # SYSTEMD SERVER ONLY
  $ sudo systemctl reload postgresql-PG_VER
  # INITD SERVER ONLY
  $ sudo service postgresql-PG_VER reload"

  sql = postgres_session(PG_DBA, PG_DBA_PASSWORD, PG_HOST)

  describe sql.query('SHOW shared_preload_libraries;', [PG_DB]) do
    its('output') { should include 'pgaudit' }
  end

  pgaudit_types = %w(ddl read role write)

  pgaudit_types.each do |type|
    describe sql.query('SHOW pgaudit.log;', [PG_DB]) do
      its('output') { should include type }
    end
  end
end
