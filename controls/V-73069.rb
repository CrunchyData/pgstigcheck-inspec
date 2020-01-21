pg_ver = input('pg_version')

pg_dba = input('pg_dba')

pg_dba_password = input('pg_dba_password')

pg_db = input('pg_db')

pg_host = input('pg_host')

control "V-73069" do
  title "PostgreSQL must generate audit records for all direct access to the
  database(s)."
  desc  "In this context, direct access is any query, command, or call to the
  DBMS that comes from any source other than the application(s) that it supports.
  Examples would be the command line or a database management utility program.
  The intent is to capture all activity from administrative and non-standard
  sources."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000508-DB-000358"
  tag "gid": "V-73069"
  tag "rid": "SV-87721r2_rule"
  tag "stig_id": "PGS9-00-012700"
  tag "fix_id": "F-79515r2_fix"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]
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
  desc "check", "As the database administrator, verify pgaudit is enabled by
  running the following SQL:

  $ sudo su - postgres
  $ psql -c \"SHOW shared_preload_libraries\"

  If the output does not contain \"pgaudit\", this is a finding.

  Verify that connections and disconnections are being logged by running the
  following SQL:

  $ sudo su - postgres
  $ psql -c \"SHOW log_connections\"
  $ psql -c \"SHOW log_disconnections\"

  If the output does not contain \"on\", this is a finding."
  
  desc "fix", "Note: The following instructions use the PGDATA and PGVER
  environment variables. See supplementary content APPENDIX-F for instructions on
  configuring PGDATA and APPENDIX-H for PGVER.

  To ensure that logging is enabled, review supplementary content APPENDIX-C for
  instructions on enabling logging. 

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
  $ sudo systemctl reload postgresql-${PGVER?}

  # INITD SERVER ONLY 
  $ sudo service postgresql-${PGVER?} reload"

  sql = postgres_session(pg_dba, pg_dba_password, pg_host)

  describe sql.query('SHOW shared_preload_libraries;', [pg_db]) do
    its('output') { should include 'pgaudit' }
  end

  describe sql.query('SHOW log_connections;', [pg_db]) do
    its('output') { should match /on|true/i }
  end

  describe sql.query('SHOW log_disconnections;', [pg_db]) do
    its('output') { should match /on|true/i }
  end
end
