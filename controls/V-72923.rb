pg_dba = input('pg_dba')

pg_dba_password = input('pg_dba_password')

pg_db = input('pg_db')

pg_host = input('pg_host')

pg_log_dir = input('pg_log_dir')

pg_audit_log_dir = input('pg_audit_log_dir')

control "V-72923" do
  title "PostgreSQL must generate audit records when unsuccessful logons or
  connection attempts occur."
  desc  "For completeness of forensic analysis, it is necessary to track failed
  attempts to log on to PostgreSQL. While positive identification may not be
  possible in a case of failed authentication, as much information as possible
  about the incident must be captured."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000503-DB-000351"
  tag "gid": "V-72923"
  tag "rid": "SV-87575r2_rule"
  tag "stig_id": "PGS9-00-004600"
  tag "fix_id": "F-79367r2_fix"
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

  In this example the user joe will log into the Postgres database unsuccessfully:

  $ psql -d postgres -U joe

  As the database administrator (shown here as \"postgres\"), check pg_log for a
  FATAL connection audit trail:

  $ sudo su - postgres
  $ cat ${PGDATA?}/pg_log/postgresql-Tue.log
  < 2016-02-16 16:18:13.027 EST joe 56c65135.b5f postgres: >LOG: connection
  authorized: user=joe database=postgres
  < 2016-02-16 16:18:13.027 EST joe 56c65135.b5f postgres: >FATAL: role \"joe\"
  does not exist

  If an audit record is not generated each time a user (or other principal)
  attempts, but fails to log on or connect to PostgreSQL (including attempts
  where the user ID is invalid/unknown), this is a finding."
  
  desc "fix", "Note: The following instructions use the PGDATA and PGVER
  environment variables. See supplementary content APPENDIX-F for instructions on
  configuring PGDATA and APPENDIX-H for PGVER.

  To ensure that logging is enabled, review supplementary content APPENDIX-C for
  instructions on enabling logging. 

  If logging is enabled the following configurations must be made to log
  unsuccessful connections, date/time, username, and session identifier. 

  First, as the database administrator (shown here as \"postgres\"), edit
  postgresql.conf: 

  $ sudo su - postgres 
  $ vi ${PGDATA?}/postgresql.conf 

  Edit the following parameters: 

  log_connections = on 
  log_line_prefix = '< %m %u %c: >'  

  Where: 
  * %m is the time and date 
  * %u is the username 
  * %c is the session ID for the connection 

  Now, as the system administrator, reload the server with the new configuration: 

  # SYSTEMD SERVER ONLY 
  $ sudo systemctl reload postgresql-${PGVER?}

  # INITD SERVER ONLY 
  $ sudo service postgresql-${PGVER?} reload"


  describe command("PGPASSWORD='#{pg_dba_password}' psql -U #{pg_dba} -d #{pg_db} -h #{pg_host} -A -t -c \"SET ROLE pgauditrolefailuretest;\"") do
    its('stdout') { should match // }
  end

  describe command("cat `find #{pg_audit_log_dir} -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d\" \"` | grep \"does not exist\"") do
    its('stdout') { should match /^.*role \"pgauditrolefailuretest\" does not exist.*$/ }
  end
end
