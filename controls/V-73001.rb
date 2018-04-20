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

control "V-73001" do
  title "PostgreSQL must initiate session auditing upon startup."
  desc  "Session auditing is for use when a user's activities are under
  investigation. To be sure of capturing all activity during those periods when
  session auditing is in use, it needs to be in operation for the whole time
  PostgreSQL is running."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000092-DB-000208"
  tag "gid": "V-73001"
  tag "rid": "SV-87653r1_rule"
  tag "stig_id": "PGS9-00-008600"
  tag "cci": ["CCI-001464"]
  tag "nist": ["AU-14 (1)", "Rev_4"]

  tag "check": "As the database administrator (shown here as \"postgres\"), check
the current settings by running the following SQL:

$ sudo su - postgres
$ psql -c \"SHOW shared_preload_libraries\"

If pgaudit is not in the current setting, this is a finding.

As the database administrator (shown here as \"postgres\"), check the current
settings by running the following SQL:

$ psql -c \"SHOW logging_destination\"

If stderr or syslog are not in the current setting, this is a finding."
  tag "fix": "Configure PostgreSQL to enable auditing.

To ensure that logging is enabled, review supplementary content APPENDIX-C for
instructions on enabling logging.

For session logging we suggest using pgaudit. For instructions on how to setup
pgaudit, see supplementary content APPENDIX-B."

  sql = postgres_session(PG_DBA, PG_DBA_PASSWORD, PG_HOST)

  describe sql.query('SHOW shared_preload_libraries;', [PG_DB]) do
    its('output') { should include 'pgaudit' }
  end

  describe sql.query('SHOW log_destination;', [PG_DB]) do
    its('output') { should match /stderr|syslog/i }
  end
end
