pg_dba = attribute('pg_dba')
pg_dba_password = attribute('pg_dba_password')
pg_db = attribute('pg_db')
pg_host = attribute('pg_host')

control 'V-72919' do
  title "PostgreSQL must generate audit records when categorized information
  (e.g., classification levels/security levels) is accessed."
  desc "Changes in categorized information must be tracked. Without an audit
  trail, unauthorized access to protected data could go undetected.
  For detailed information on categorizing information, refer to FIPS
  Publication 199, Standards for Security Categorization of Federal Information
  and Information Systems, and FIPS Publication 200, Minimum Security
  Requirements for Federal Information and Information Systems."
  impact 0.5

  tag "gtitle": 'SRG-APP-000494-DB-000344'
  tag "gid": 'V-72919'
  tag "rid": 'SV-87571r1_rule'
  tag "stig_id": 'PGS9-00-004400'
  tag "cci": ['CCI-000172']
  tag "nist": ['AU-12 c', 'Rev_4']
  tag "check": "As the database administrator (shown here as \"postgres\"), run
  the following SQL:
  $ sudo su - postgres
  $ psql -c \"SHOW pgaudit.log\"
  If pgaudit.log does not contain, \"ddl, write, role\", this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.
  Using `pgaudit` the DBMS (PostgreSQL) can be configured to audit these
  requests. See supplementary content `APPENDIX-B` for documentation on
  installing `pgaudit`.
  With `pgaudit` installed the following configurations can be made:
  $ sudo su - postgres
  $ vi ${PGDATA?}/postgresql.conf
  Add the following parameters (or edit existing parameters):
  pgaudit.log = 'ddl, write, role'
  Now, as the system administrator, reload the server with the new configuration:
  # SYSTEMD SERVER ONLY
  $ sudo systemctl reload postgresql-9.5
  # INITD SERVER ONLY
  $ sudo service postgresql-9.5 reload"

  sql = postgres_session(pg_dba, pg_dba_password, pg_host)

  pgaudit_types = %w{ddl role write}

  pgaudit_types.each do |type|
    describe sql.query('SHOW pgaudit.log;', [pg_db]) do
      its('output') { should include type }
    end
  end
end
