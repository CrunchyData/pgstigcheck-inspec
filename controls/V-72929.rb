pg_ver = input('pg_version')

pg_dba = input('pg_dba')

pg_dba_password = input('pg_dba_password')

pg_db = input('pg_db')

pg_host = input('pg_host')

pg_log_dir = input('pg_log_dir')

pg_audit_log_dir = input('pg_audit_log_dir')

control "V-72929" do
  title "PostgreSQL must generate audit records when privileges/permissions are
  added."
  desc  "Changes in the permissions, privileges, and roles granted to users and
  roles must be tracked. Without an audit trail, unauthorized elevation or
  restriction of privileges could go undetected. Elevated privileges give users
  access to information and functionality that they should not have; restricted
  privileges wrongly deny access to authorized users.

  In an SQL environment, adding permissions is typically done via the GRANT
  command, or, in the negative, the REVOKE command."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000495-DB-000326"
  tag "gid": "V-72929"
  tag "rid": "SV-87581r2_rule"
  tag "stig_id": "PGS9-00-004900"
  tag "fix_id": "F-79373r2_fix"
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
  role by running the following SQL:

  Change the privileges of another user:

  $ sudo su - postgres
  $ psql -c \"CREATE ROLE bob\"

  Next, GRANT then REVOKE privileges from the role:

  $ psql -c \"GRANT CONNECT ON DATABASE postgres TO bob\"
  $ psql -c \"REVOKE CONNECT ON DATABASE postgres FROM bob\"

  postgres=# REVOKE CONNECT ON DATABASE postgres FROM bob;
  REVOKE

  postgres=# GRANT CONNECT ON DATABASE postgres TO bob;
  GRANT

  Now, as the database administrator (shown here as \"postgres\"), verify the
  events were logged:

  $ sudo su - postgres
  $ cat ${PGDATA?}/pg_log/<latest_log>
  < 2016-07-13 16:25:21.103 EDT postgres postgres LOG: > AUDIT:
  SESSION,1,1,ROLE,GRANT,,,GRANT CONNECT ON DATABASE postgres TO bob,<none>
  < 2016-07-13 16:25:25.520 EDT postgres postgres LOG: > AUDIT:
  SESSION,1,1,ROLE,REVOKE,,,REVOKE CONNECT ON DATABASE postgres FROM bob,<none>

  If the above steps cannot verify that audit records are produced when
  privileges/permissions/role memberships are added, this is a finding."
    
  desc "fix", "Note: The following instructions use the PGDATA and PGVER
  environment variables. See supplementary content APPENDIX-F for instructions on
  configuring PGDATA and APPENDIX-H for PGVER.

  Using pgaudit PostgreSQL can be configured to audit these requests. See
  supplementary content APPENDIX-B for documentation on installing pgaudit. 

  With pgaudit installed the following configurations can be made: 

  $ sudo su - postgres 
  $ vi ${PGDATA?}/postgresql.conf 

  Add the following parameters (or edit existing parameters): 

  pgaudit.log = 'role' 

  Now, as the system administrator, reload the server with the new configuration: 

  # SYSTEMD SERVER ONLY 
  $ sudo systemctl reload postgresql-${PGVER?}

  # INITD SERVER ONLY 
  $ sudo service postgresql-${PGVER?} reload"

  describe command("PGPASSWORD='#{pg_dba_password}' psql -U #{pg_dba} -d #{pg_db} -h #{pg_host} -A -t -c \"CREATE ROLE fooaudit; GRANT CONNECT ON DATABASE postgres TO fooaudit; REVOKE CONNECT ON DATABASE postgres FROM fooaudit;\"") do
    its('stdout') { should match // }
  end

  describe command("cat `find #{pg_audit_log_dir} -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d\" \"` | grep \"GRANT CONNECT ON DATABASE postgres TO\"") do
    its('stdout') { should match /^.*fooaudit.*$/ }
  end

  describe command("cat `find #{pg_audit_log_dir} -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d\" \"` | grep \"REVOKE CONNECT ON DATABASE postgres FROM\"") do
    its('stdout') { should match /^.*fooaudit.*$/ }
  end

end
