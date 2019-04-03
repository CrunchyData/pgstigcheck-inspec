# encoding: utf-8

pg_dba = attribute('pg_dba')
pg_dba_password = attribute('pg_dba_password')
pg_db = attribute('pg_db')
pg_host = attribute('pg_host')

control "V-72971" do
  title "PostgreSQL must generate audit records when security objects are
  modified."
  desc  "Changes in the database objects (tables, views, procedures, functions)
  that record and control permissions, privileges, and roles granted to users
  and roles must be tracked. Without an audit trail, unauthorized changes to the
  security subsystem could go undetected. The database could be severely
  compromised or rendered inoperative."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000496-DB-000334"
  tag "gid": "V-72971"
  tag "rid": "SV-87623r1_rule"
  tag "stig_id": "PGS9-00-006600"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "First, as the database administrator, verify pgaudit is enabled
  by running the following SQL:
  $ sudo su - postgres
  $ psql -c \"SHOW shared_preload_libraries\"
  If the results does not contain `pgaudit`, this is a finding.
  Next, verify that role, read, write, and ddl auditing are enabled:
  $ psql -c \"SHOW pgaudit.log\"
  If the output does not contain `role`, `read`, `write`, and `ddl`, this is a
  finding.
  Next, verify that accessing the catalog is audited by running the following
  SQL:
  $ psql -c \"SHOW pgaudit.log_catalog\"
  If log_catalog is not `on`, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.
  To ensure that logging is enabled, review supplementary content APPENDIX-C for
  instructions on enabling logging.
  Using `pgaudit` the DBMS (PostgreSQL) can be configured to audit these
  requests. See supplementary content `APPENDIX-B` for documentation on
  installing `pgaudit`.With `pgaudit` installed the following configurat
  ions can be made:
  $ sudo su - postgres
  $ vi ${PGDATA?}/postgresql.conf
  Add the following parameters (or edit existing parameters):
  pgaudit.log_catalog = 'on'
  pgaudit.log='ddl, role, read, write'
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

  pgaudit_types = %w(ddl read role write)

  pgaudit_types.each do |type|
    describe sql.query('SHOW pgaudit.log;', [pg_db]) do
      its('output') { should include type }
    end
  end

  describe sql.query('SHOW pgaudit.log_catalog;', [pg_db]) do
    its('output') { should match /on|true/i }
  end
end
