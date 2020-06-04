pg_owner = input('pg_owner')

pg_dba = input('pg_dba')

pg_dba_password = input('pg_dba_password')

pg_db = input('pg_db')

pg_host = input('pg_host')

control "V-73021" do
  title "PostgreSQL must provide the capability for authorized users
  to capture, record, and log all content related to a user session."
  desc  "Without the capability to capture, record, and log all content related to a user session, 
  investigations into suspicious user activity would be hampered. Typically, this PostgreSQL capability 
  would be used in conjunction with comparable monitoring of a user's online session, involving other software 
  components such as operating systems, web servers and front-end user applications. The current requirement, 
  however, deals specifically with PostgreSQL."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000359-DB-000319"
  tag "gid": "V-73021"
  tag "rid": "SV-87673r1_rule"
  tag "stig_id": "PGS9-00-009900"
  tag "fix_id": "F-79469r2_fix"
  tag "cci": ["CCI-001855"]
  tag "nist": ["AU-5 (1)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  desc "check", "First, as the database administrator 
  (shown here as \"postgres\"), verify pgaudit is installed by running the following SQL:
  $ sudo su - postgres
  $ psql -c \"SHOW shared_preload_libraries\"

  If shared_preload_libraries does not contain pgaudit, this is a finding.

  Next, to verify connections and disconnections are logged, run the following SQL:

  $ psql -c \"SHOW log_connections\"
  $ psql -c \"SHOW log_disconnections\"

  If log_connections and log_disconnections are off, this is a finding.

  Now, to verify that pgaudit is configured to log, run the following SQL:

  $ psql -c \"SHOW pgaudit.log\"

  If pgaudit.log does not contain ddl, role, read, write, this is a finding."
  
  desc "fix", "Configure the database capture, record, and log all content related 
  to a user session.

  To ensure that logging is enabled, review supplementary content APPENDIX-C for 
  instructions on enabling logging.

  With logging enabled, as the database administrator (shown here as \"postgres\"), 
  enable log_connections and log_disconnections:

  $ sudo su - postgres
  $ vi ${PGDATA?}/postgresql.conf
  log_connections = on
  log_disconnections = on

  Using pgaudit PostgreSQL can be configured to audit activity. See supplementary content 
  APPENDIX-B for documentation on installing pgaudit.

  With pgaudit installed, as a database administrator (shown here as \"postgres\"), enable which 
  objects required for auditing a user's session:

  $ sudo su - postgres
  $ vi ${PGDATA?}/postgresql.conf
  pgaudit.log = 'write, ddl, role, read, function';
  pgaudit.log_relation = on;

  Now, as the system administrator, reload the server with the new configuration:

  # SYSTEMD SERVER ONLY
  $ sudo systemctl reload postgresql-9.5

  # INITD SERVER ONLY
  $ sudo service postgresql-9.5 reload"

  sql = postgres_session(pg_dba, pg_dba_password, pg_host)

  describe sql.query ("SHOW shared_preload_libraries") do
    its('output') { should include 'pgaudit' } 
  end

  describe sql.query ("SHOW log_connections") do
    its('output') { should_not match /off|false/i } 
  end

  describe sql.query ("SHOW log_disconnections") do
    its('output') { should_not match /off|false/i } 
  end
  
  describe sql.query ("SHOW pgaudit.log") do
    its('output') { should include 'write'}
    its('output') { should include 'ddl'}
    its('output') { should include 'role'}
    its('output') { should include 'read'}
  end
end