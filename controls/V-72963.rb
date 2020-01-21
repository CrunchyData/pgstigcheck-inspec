pg_ver = input('pg_version')

pg_dba = input('pg_dba')

pg_dba_password = input('pg_dba_password')

pg_db = input('pg_db')

pg_host = input('pg_host')

control "V-72963" do
  title "PostgreSQL must generate audit records when unsuccessful attempts to
  delete security objects occur."
  desc  "The removal of security objects from the database/PostgreSQL would
  seriously degrade a system's information assurance posture. If such an action
  is attempted, it must be logged.

  To aid in diagnosis, it is necessary to keep track of failed attempts in
  addition to the successful ones."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000501-DB-000337"
  tag "gid": "V-72963"
  tag "rid": "SV-87615r2_rule"
  tag "stig_id": "PGS9-00-006300"
  tag "fix_id": "F-79409r3_fix"
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
  desc "check", "First, as the database administrator, verify pgaudit is enabled
  by running the following SQL: 

  $ sudo su - postgres 
  $ psql -c \"SHOW shared_preload_libraries\" 

  If the output does not contain pgaudit, this is a finding. 

  Next, verify that role, read, write, and ddl auditing are enabled: 

  $ psql -c \"SHOW pgaudit.log\" 

  If the output does not contain role, read, write, and ddl, this is a finding."
    
  desc "fix", "Note: The following instructions use the PGDATA and PGVER
  environment variables. See supplementary content APPENDIX-F for instructions on
  configuring PGDATA and APPENDIX-H for PGVER.

  Configure PostgreSQL to produce audit records when unsuccessful attempts to
  delete security objects occur. 

  All errors and denials are logged if logging is enabled. To ensure that logging
  is enabled, review supplementary content APPENDIX-C for instructions on
  enabling logging. 

  With pgaudit installed the following configurations can be made: 

  $ sudo su - postgres 
  $ vi ${PGDATA?}/postgresql.conf 

  Add the following parameters (or edit existing parameters): 

  pgaudit.log='ddl, role, read, write' 

  Now, as the system administrator, reload the server with the new configuration: 

  # SYSTEMD SERVER ONLY 
  $ sudo systemctl reload postgresql-${PGVER?}

  # INITD SERVER ONLY 
  $ sudo service postgresql-${PGVER?} reload"

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
end
