pg_ver = input('pg_version')

pg_dba = input('pg_dba')

pg_dba_password = input('pg_dba_password')

pg_db = input('pg_db')

pg_host = input('pg_host')

pg_log_dir = input('pg_log_dir')

pg_audit_log_dir = input('pg_audit_log_dir')

control "V-72927" do
  title "PostgreSQL must generate audit records when unsuccessful attempts to
  modify security objects occur."
  desc  "Changes in the database objects (tables, views, procedures, functions)
  that record and control permissions, privileges, and roles granted to users and
  roles must be tracked. Without an audit trail, unauthorized changes to the
  security subsystem could go undetected. The database could be severely
  compromised or rendered inoperative.

  To aid in diagnosis, it is necessary to keep track of failed attempts in
  addition to the successful ones."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000496-DB-000335"
  tag "gid": "V-72927"
  tag "rid": "SV-87579r1_rule"
  tag "stig_id": "PGS9-00-004800"
  tag "fix_id": "F-79371r1_fix"
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

  As the database administrator (shown here as \"postgres\"), create a test role
  by running the following SQL:

  $ sudo su - postgres
  $ psql -c \"CREATE ROLE bob\"

  Next, to test if audit records are generated from unsuccessful attempts at
  modifying security objects, run the following SQL:

  $ sudo su - postgres
  $ psql -c \"SET ROLE bob; UPDATE pg_authid SET rolsuper = 't' WHERE rolname =
  'bob';\"

  Next, as the database administrator (shown here as \"postgres\"), verify that
  the denials were logged:

  $ sudo su - postgres
  $ cat ${PGDATA?}/pg_log/<latest_log>
  < 2016-03-17 10:34:00.017 EDT bob 56eabf52.b62 postgres: >ERROR: permission
  denied for relation pg_authid
  < 2016-03-17 10:34:00.017 EDT bob 56eabf52.b62 postgres: >STATEMENT: UPDATE
  pg_authid SET rolsuper = 't' WHERE rolname = 'bob';

  If denials are not logged, this is a finding."
  
  desc "fix", "Configure PostgreSQL to produce audit records when unsuccessful
  attempts to modify security objects occur.

  Unsuccessful attempts to modifying security objects can be logged if logging is
  enabled. To ensure that logging is enabled, review supplementary content
  APPENDIX-C for instructions on enabling logging."

  
  describe command("PGPASSWORD='#{pg_dba_password}' psql -U #{pg_dba} -d #{pg_db} -h #{pg_host} -A -t -c \"CREATE ROLE permdeniedtest; SET ROLE permdeniedtest; UPDATE pg_authid SET rolsuper = 't' WHERE rolname = 'permdeniedtest'; DROP ROLE IF EXISTS permdeniedtest;\"") do
    its('stdout') { should match // }
  end

  describe command("cat `find #{pg_audit_log_dir} -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d\" \"` | grep \"permission denied for relation pg_authid\"") do
    its('stdout') { should match /^.*permission denied for relation pg_authid.*$/ }
  end

end
