# encoding: utf-8

pg_dba = attribute('pg_dba')
pg_dba_password = attribute('pg_dba_password')
pg_db = attribute('pg_db')
pg_host = attribute('pg_host')

control "V-72957" do
  title "PostgreSQL must be able to generate audit records when security objects
  are accessed."
  desc  "Changes to the security configuration must be tracked.
  This requirement applies to situations where security data is retrieved or
  modified via data manipulation operations, as opposed to via specialized
  security functionality.
  In an SQL environment, types of access include, but are not necessarily
  limited to:
  CREATE
  SELECT
  INSERT
  UPDATE
  DELETE
  PREPARE
  EXECUTE
  ALTER
  DRO."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000492-DB-000332"
  tag "gid": "V-72957"
  tag "rid": "SV-87609r1_rule"
  tag "stig_id": "PGS9-00-006000"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "First, as the database administrator, verify pgaudit is enabled
  by running the following SQL:
  $ sudo su - postgres
  $ psql -c \"SHOW shared_preload_libraries\"
  If the output does not contain pgaudit, this is a finding.
  Next, verify that role, read, write, and ddl auditing are enabled:
  $ psql -c \"SHOW pgaudit.log\"
  If the output does not contain role, read, write, and ddl, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.
  Using pgaudit PostgreSQL can be configured to audit these requests. See
  supplementary content APPENDIX-B for documentation on installing pgaudit.
  With pgaudit installed the following configurations can be made:
  $ sudo su - postgres
  $ vi ${PGDATA?}/postgresql.conf
  Add the following parameters (or edit existing parameters):
  pgaudit.log='ddl, role, read, write'
  Now, as the system administrator, reload the server with the new configuration:
  # SYSTEMD SERVER ONLY
  $ sudo systemctl reload postgresql-9.5
  # INITD SERVER ONLY
  $ sudo service postgresql-9.5 reload"

  sql = postgres_session(pg_dba, pg_dba_password, pg_host)

  describe sql.query('SHOW shared_preload_libraries;', [pg_db]) do
    its('output') { should include 'pgaudit' }
  end

  pgaudit_types = %w(ddl read role write)

  pgaudit_types.each do |type|
    describe sql.query('SHOW pgaudit.log;', [pg_db]) do
      its('output') { should include type }
    end
  end
end
