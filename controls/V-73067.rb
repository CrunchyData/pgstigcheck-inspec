pg_dba = attribute('pg_dba')
pg_dba_password = attribute('pg_dba_password')
pg_db = attribute('pg_db')
pg_host = attribute('pg_host')

control 'V-73067' do
  title "PostgreSQL must generate audit records when successful accesses to
        objects occur."
  desc  "Without tracking all or selected types of access to all or selected
        objects (tables, views, procedures, functions, etc.), it would be
        difficult to establish, correlate, and investigate the events relating
        to an incident, or identify those responsible for one.

        In an SQL environment, types of access include, but are not necessarily
        limited to:

        SELECT
        INSERT
        UPDATE
        DELETE
        EXECUT."

  impact 0.5

  tag "gtitle": 'SRG-APP-000507-DB-000356'
  tag "gid": 'V-73067'
  tag "rid": 'SV-87719r1_rule'
  tag "stig_id": 'PGS9-00-012600'
  tag "cci": ['CCI-000172']
  tag "nist": ['AU-12 c', 'Rev_4']

  tag "check": "As the database administrator, verify pgaudit is enabled by
      running the following SQL:

      $ sudo su - postgres
      $ psql -c \"SHOW shared_preload_libraries\"

      If the output does not contain \"pgaudit\", this is a finding.

      Verify that role, read, write, and ddl auditing are enabled:

      $ psql -c \"SHOW pgaudit.log\"

      If the output does not contain read and write, this is a finding."

  tag "fix": "Note: The following instructions use the PGDATA environment variable.
      See supplementary content APPENDIX-F for instructions on configuring PGDATA.

      To ensure that logging is enabled, review supplementary content APPENDIX-C
      for instructions on enabling logging.

      If logging is enabled the following configurations must be made to log
      unsuccessful connections, date/time, username and session identifier.

      As the database administrator (shown here as \"postgres\"),
      edit postgresql.conf:

      $ sudo su - postgres
      $ vi ${PGDATA?}/postgresql.conf

      Edit the following parameters:

      log_connections = on
      log_line_prefix = '< %m %u %c: >'
      pgaudit.log = 'read, write'

      Where:
      * %m is the time and date
      * %u is the username
      * %c is the session ID for the connection

      Now, as the system administrator, reload the server with the new
      configuration:

      # SYSTEMD SERVER ONLY
      $ sudo systemctl reload postgresql-9.5

      # INITD SERVER ONLY
      $ sudo service postgresql-9.5 reload"

  sql = postgres_session(pg_dba, pg_dba_password, pg_host)

  describe sql.query('SHOW shared_preload_libraries;', [pg_db]) do
    its('output') { should include 'pgaudit' }
  end

  pgaudit_types = %w{read write}

  pgaudit_types.each do |type|
    describe sql.query('SHOW pgaudit.log;', [pg_db]) do
      its('output') { should include type }
    end
  end
end
