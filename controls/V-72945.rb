pg_dba = input('pg_dba')

pg_dba_password = input('pg_dba_password')

pg_db = input('pg_db')

pg_host = input('pg_host')

pg_log_dir = input('pg_log_dir')

pg_audit_log_dir = input('pg_audit_log_dir')

control "V-72945" do
  title "PostgreSQL must generate audit records when unsuccessful attempts to
  delete privileges/permissions occur."
  desc  "Failed attempts to change the permissions, privileges, and roles
  granted to users and roles must be tracked. Without an audit trail,
  unauthorized attempts to elevate or restrict privileges could go undetected.

  In an SQL environment, deleting permissions is typically done via the
  REVOKE command.

  To aid in diagnosis, it is necessary to keep track of failed attempts in
  addition to the successful ones."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000499-DB-000331"
  tag "gid": "V-72945"
  tag "rid": "SV-87597r2_rule"
  tag "stig_id": "PGS9-00-005400"
  tag "fix_id": "F-79391r1_fix"
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

  First, as the database administrator (shown here as \"postgres\"), create the
  roles joe and bob with LOGIN by running the following SQL: 

  $ sudo su - postgres 
  $ psql -c \"CREATE ROLE joe LOGIN\" 
  $ psql -c \"CREATE ROLE bob LOGIN\" 

  Next, set current role to bob and attempt to alter the role joe: 

  $ psql -c \"SET ROLE bob; ALTER ROLE joe NOLOGIN;\" 

  Now, as the database administrator (shown here as \"postgres\"), verify the
  denials are logged: 

  $ sudo su - postgres 
  $ cat ${PGDATA?}/pg_log/<latest_log> 
  < 2016-03-17 11:28:10.004 EDT bob 56eacd05.cda postgres: >ERROR: permission
  denied to alter role 
  < 2016-03-17 11:28:10.004 EDT bob 56eacd05.cda postgres: >STATEMENT: ALTER ROLE
  joe; 

  If audit logs are not generated when unsuccessful attempts to delete
  privileges/permissions occur, this is a finding."

  desc "fix", "Configure PostgreSQL to produce audit records when unsuccessful
  attempts to delete privileges occur.

  All denials are logged if logging is enabled. To ensure that logging is
  enabled, review supplementary content APPENDIX-C for instructions on enabling
  logging."

  describe command("PGPASSWORD='#{pg_dba_password}' psql -U #{pg_dba} -d #{pg_db} -h #{pg_host} -A -t -c \"CREATE ROLE pgauditrolefailuretest; SET ROLE pgauditrolefailuretest; DROP ROLE postgres; SET ROLE postgres; DROP ROLE pgauditrolefailuretest;\"") do
    its('stdout') { should match // }
  end

 describe command("cat `find #{pg_audit_log_dir} -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d\" \"` | grep \"permission denied to drop role\"") do
   its('stdout') { should match /^.*permission denied to drop role.*$/ }
 end

end
