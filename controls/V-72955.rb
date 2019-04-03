# encoding: utf-8

pg_dba = attribute('pg_dba')
pg_dba_password = attribute('pg_dba_password')
pg_db = attribute('pg_db')
pg_host = attribute('pg_host')

control "V-72955" do
  title "PostgreSQL must generate audit records when unsuccessful attempts to
  access categorized information (e.g., classification levels/security levels)
  occur."
  desc  "Changes in categorized information must be tracked. Without an audit
  trail, unauthorized access to protected data could go undetected.
  To aid in diagnosis, it is necessary to keep track of failed attempts in
  addition to the successful ones.
  For detailed information on categorizing information, refer to FIPS
  Publication 199, Standards for Security Categorization of Federal Information
  and Information Systems, and FIPS Publication 200, Minimum Security
  Requirements for Federal Information and Information Systems."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000494-DB-000345"
  tag "gid": "V-72955"
  tag "rid": "SV-87607r1_rule"
  tag "stig_id": "PGS9-00-005900"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "First, as the database administrator (shown here as
  \"postgres\"), run the following SQL:
  $ sudo su - postgres
  $ psql -c \"SHOW pgaudit.log\"
  If pgaudit.log does not contain, \"ddl, write, role\", this is a finding."
  tag "fix": "Configure PostgreSQL to produce audit records when unsuccessful
  attempts to access categories of information.
  All denials are logged if logging is enabled. To ensure that logging is
  enabled, review supplementary content APPENDIX-C for instructions on enabling
  logging.
  With `pgaudit` installed the following configurations can be made:
  $ sudo su - postgres
  $ vi ${PGDATA?}/postgresql.conf
  Add the following parameters (or edit existing parameters):
  pgaudit.log = 'ddl, write, role'
  Now, as the system administrator, reload the server with the new configuration:
  # SYSTEMD SERVER ONLY
  $ sudo systemctl reload postgresql-$9.5
  # INITD SERVER ONLY
  $ sudo service postgresql-9.5 reload"

  sql = postgres_session(pg_dba, pg_dba_password, pg_host)

  pgaudit_types = %w(ddl role write)

  pgaudit_types.each do |type|
    describe sql.query('SHOW pgaudit.log;', [pg_db]) do
      its('output') { should include type }
    end
  end
end
