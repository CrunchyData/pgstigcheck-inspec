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

control "V-73069" do
  title "PostgreSQL must generate audit records for all direct access to the
        database(s)."
  desc  "In this context, direct access is any query, command, or call to the
        DBMS that comes from any source other than the application(s) that it
        supports. Examples would be the command line or a database management
        utility program. The intent is to capture all activity from administrative
        and non-standard sources."
  impact 0.5
  tag "severity": "medium"

  tag "gtitle": "SRG-APP-000508-DB-000358"
  tag "gid": "V-73069"
  tag "rid": "SV-87721r1_rule"
  tag "stig_id": "PGS9-00-012700"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]

  tag "check": "As the database administrator, verify pgaudit is enabled by running
      the following SQL:

      $ sudo su - postgres
      $ psql -c \"SHOW shared_preload_libraries\"

      If the output does not contain \"pgaudit\", this is a finding.

      Verify that connections and disconnections are being logged by
      running the following SQL:

      $ sudo su - postgres
      $ psql -c \"SHOW log_connections\"
      $ psql -c \"SHOW log_disconnections\"

      If the output does not contain \"on\",

      pgaudit.log='ddl, role, read, write'
      log_connections='on'
      log_disconnections='on'

      this is a finding."

  tag "fix": "Note: The following instructions use the PGDATA environment
      variable. See supplementary content APPENDIX-F for instructions on
      configuring PGDATA.

      To ensure that logging is enabled, review supplementary content APPENDIX-C
      for instructions on enabling logging.

      Using pgaudit PostgreSQL can be configured to audit these requests. See
      supplementary content APPENDIX-B for documentation on installing pgaudit.

      With pgaudit installed the following configurations should be made:

      $ sudo su - postgres
      $ vi ${PGDATA?}/postgresql.conf

      Add the following parameters (or edit existing parameters):

      pgaudit.log='ddl, role, read, write'
      log_connections='on'
      log_disconnections='on'

      Now, as the system administrator, reload the server with the new configuration:

      # SYSTEMD SERVER ONLY
      $ sudo systemctl reload postgresql-${PG_VER}

      # INITD SERVER ONLY
      $ sudo service postgresql-${PG_VER} reload"

  sql = postgres_session(PG_DBA, PG_DBA_PASSWORD, PG_HOST)

  describe sql.query('SHOW shared_preload_libraries;', [PG_DB]) do
    its('output') { should include 'pgaudit' }
  end

  describe sql.query('SHOW log_connections;', [PG_DB]) do
    its('output') { should match /on|true/i }
  end

  describe sql.query('SHOW log_disconnections;', [PG_DB]) do
    its('output') { should match /on|true/i }
  end
end
