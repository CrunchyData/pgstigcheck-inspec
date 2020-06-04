pg_ver = input('pg_version')

pg_dba = input('pg_dba')

pg_dba_password = input('pg_dba_password')

pg_db = input('pg_db')

pg_host = input('pg_host')

pg_log_dir = input('pg_log_dir')

pg_audit_log_dir = input('pg_audit_log_dir')

control "V-72947" do
  title "PostgreSQL must be able to generate audit records when
  privileges/permissions are retrieved."
  desc  "Under some circumstances, it may be useful to monitor who/what is
  reading privilege/permission/role information. Therefore, it must be possible
  to configure auditing to do this. PostgreSQLs typically make such information
  available through views or functions.

  This requirement addresses explicit requests for privilege/permission/role
  membership information. It does not refer to the implicit retrieval of
  privileges/permissions/role memberships that PostgreSQL continually performs to
  determine if any and every action on the database is permitted."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000091-DB-000066"
  tag "gid": "V-72947"
  tag "rid": "SV-87599r2_rule"
  tag "stig_id": "PGS9-00-005500"
  tag "fix_id": "F-79393r3_fix"
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

  First, as the database administrator (shown here as \"postgres\"), check if
  pgaudit is enabled by running the following SQL:

  $ sudo su - postgres
  $ psql -c \"SHOW shared_preload_libraries\"

  If pgaudit is not found in the results, this is a finding.

  Next, as the database administrator (shown here as \"postgres\"), list all role
  memberships for the database:

  $ sudo su - postgres
  $ psql -c \"\\du\"

  Next, verify the query was logged:

  $ sudo su - postgres
  $ cat ${PGDATA?}/pg_log/<latest_log>
  < 2016-01-28 19:43:12.126 UTC postgres postgres: >LOG: AUDIT:
  SESSION,1,1,READ,SELECT,,,\"SELECT r.rolname, r.rolsuper, r.rolinherit,
  r.rolcreaterole, r.rolcreatedb, r.rolcanlogin,
  r.rolconnlimit, r.rolvaliduntil,
  ARRAY(SELECT b.rolname
  FROM pg_catalog.pg_auth_members m
  JOIN pg_catalog.pg_roles b ON (m.roleid = b.oid)
  WHERE m.member = r.oid) as memberof
  , r.rolreplication
  , r.rolbypassrls
  FROM pg_catalog.pg_roles r
  ORDER BY 1;\",<none>

  If audit records are not produced, this is a finding."
  
  desc "fix", "Note: The following instructions use the PGDATA and PGVER
  environment variables. See supplementary content APPENDIX-F for instructions on
  configuring PGDATA and APPENDIX-H for PGVER.

  Using pgaudit PostgreSQL can be configured to audit these requests. See
  supplementary content APPENDIX-B for documentation on installing pgaudit. 

  With pgaudit installed the following configurations can be made: 

  $ sudo su - postgres 
  $ vi ${PGDATA?}/postgresql.conf 

  Add the following parameters (or edit existing parameters): 

  pgaudit.log_catalog = 'on' 
  pgaudit.log = 'read' 

  Now, as the system administrator, reload the server with the new configuration: 

  # SYSTEMD SERVER ONLY 
  $ sudo systemctl reload postgresql-${PGVER?}
    
  # INITD SERVER ONLY 
  $ sudo service postgresql-${PGVER?} reload"

 describe command("PGPASSWORD='#{pg_dba_password}' psql -U #{pg_dba} -d #{pg_db} -h #{pg_host} -A -t -c \"\\du\"") do
   its('stdout') { should match // }
 end

 describe command("cat `find #{pg_audit_log_dir} -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d\" \"` | grep \"AUDIT\"") do
   its('stdout') { should match /^.*pg_catalog.pg_roles.*$/ }
 end

end
