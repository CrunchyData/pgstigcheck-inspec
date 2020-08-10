pg_dba = input('pg_dba')

pg_dba_password = input('pg_dba_password')

pg_db = input('pg_db')

pg_host = input('pg_host')

pg_log_dir = input('pg_log_dir')

pg_audit_log_dir = input('pg_audit_log_dir')

control "V-72939" do
  title "PostgreSQL must generate audit records when security objects are
  deleted."
  desc  "The removal of security objects from the database/PostgreSQL would
  seriously degrade a system's information assurance posture. If such an event
  occurs, it must be logged."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000501-DB-000336"
  tag "gid": "V-72939"
  tag "rid": "SV-87591r2_rule"
  tag "stig_id": "PGS9-00-005200"
  tag "fix_id": "F-79383r2_fix"
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
  desc "check", "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.

  First, as the database administrator (shown here as \"postgres\"), create a
  test table stig_test, enable row level security, and create a policy by running
  the following SQL:

  $ sudo su - postgres
  $ psql -c \"CREATE TABLE stig_test(id INT)\"
  $ psql -c \"ALTER TABLE stig_test ENABLE ROW LEVEL SECURITY\"
  $ psql -c \"CREATE POLICY lock_table ON stig_test USING ('postgres' =
  current_user)\"

  Next, drop the policy and disable row level security:

  $ psql -c \"DROP POLICY lock_table ON stig_test\"
  $ psql -c \"ALTER TABLE stig_test DISABLE ROW LEVEL SECURITY\"

  Now, as the database administrator (shown here as \"postgres\"), verify the
  security objects deletions were logged:

  $ cat ${PGDATA?}/pg_log/<latest_log>
  2016-03-30 14:54:18.991 EDT postgres postgres LOG: AUDIT: SESSION,11,1,DDL,DROP
  POLICY,,,DROP POLICY lock_table ON stig_test;,<none>
  2016-03-30 14:54:42.373 EDT postgres postgres LOG: AUDIT:
  SESSION,12,1,DDL,ALTER TABLE,,,ALTER TABLE stig_test DISABLE ROW LEVEL
  SECURITY;,<none>

  If audit records are not produced when security objects are dropped, this is a
  finding."

  desc "fix", "Note: The following instructions use the PGDATA and PGVER
  environment variables. See supplementary content APPENDIX-F for instructions on
  configuring PGDATA and APPENDIX-H for PGVER.

  Using pgaudit PostgreSQL can be configured to audit these requests. See
  supplementary content APPENDIX-B for documentation on installing pgaudit. 

  With pgaudit installed the following configurations can be made: 

  $ sudo su - postgres 
  $ vi ${PGDATA?}/postgresql.conf 

  Add the following parameters (or edit existing parameters): 

  pgaudit.log = 'ddl' 

  Now, as the system administrator, reload the server with the new configuration: 

  # SYSTEMD SERVER ONLY 
  $ sudo systemctl reload postgresql-${PGVER?}

  # INITD SERVER ONLY 
  $ sudo service postgresql-${PGVER?} reload"

  describe command("PGPASSWORD='#{pg_dba_password}' psql -U #{pg_dba} -d #{pg_db} -h #{pg_host} -A -t -c \"CREATE TABLE stig_test(id INT); ALTER TABLE stig_test ENABLE ROW LEVEL SECURITY; CREATE POLICY lock_table ON stig_test USING ('postgres' = current_user); DROP POLICY lock_table ON stig_test; ALTER TABLE stig_test DISABLE ROW LEVEL SECURITY; DROP TABLE stig_test;\"") do
    its('stdout') { should match // }
  end

  describe command("cat `find #{pg_audit_log_dir} -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d\" \"` | grep \"AUDIT: SESSION\"") do
    its('stdout') { should match /^.*CREATE TABLE,TABLE,public.stig_test.*$/ }
  end

  describe command("cat `find #{pg_audit_log_dir} -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d\" \"` | grep \"AUDIT: SESSION\"") do
    its('stdout') { should match /^.*ALTER TABLE stig_test ENABLE ROW LEVEL SECURITY.*$/ }
  end

  describe command("cat `find #{pg_audit_log_dir} -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d\" \"` | grep \"AUDIT: SESSION\"") do
    its('stdout') { should match /^.*CREATE POLICY,POLICY,lock_table.*$/ }
  end

  describe command("cat `find #{pg_audit_log_dir} -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d\" \"` | grep \"AUDIT: SESSION\"") do
    its('stdout') { should match /^.*DROP POLICY lock_table ON stig_test.*$/ }
  end

  describe command("cat `find #{pg_audit_log_dir} -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d\" \"` | grep \"AUDIT: SESSION\"") do
    its('stdout') { should match /^.*ALTER TABLE stig_test DISABLE ROW LEVEL SECURITY.*$/ }
  end

  describe command("cat `find #{pg_audit_log_dir} -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d\" \"` | grep \"AUDIT: SESSION\"") do
    its('stdout') { should match /^.*DROP TABLE stig_test.*$/ }
  end

end
