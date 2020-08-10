pg_dba = input('pg_dba')

pg_dba_password = input('pg_dba_password')

pg_db = input('pg_db')

pg_host = input('pg_host')

control "V-72961" do
  title "PostgreSQL must generate audit records when concurrent
  logons/connections by the same user from different workstations occur."
  desc  "For completeness of forensic analysis, it is necessary to track who
  logs on to PostgreSQL.

  Concurrent connections by the same user from multiple workstations may be
  valid use of the system; or such connections may be due to improper
  circumvention of the requirement to use the CAC for authentication; or they may
  indicate unauthorized account sharing; or they may be because an account has
  been compromised.

  (If the fact of multiple, concurrent logons by a given user can be reliably
  reconstructed from the log entries for other events (logons/connections;
  voluntary and involuntary disconnections), then it is not mandatory to create
  additional log entries specifically for this.)"

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000506-DB-000353"
  tag "gid": "V-72961"
  tag "rid": "SV-87613r2_rule"
  tag "stig_id": "PGS9-00-006200"
  tag "fix_id": "F-79407r2_fix"
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
  desc "check", "First, as the database administrator, verify that log_connections
  and log_disconnections are enabled by running the following SQL:

  $ sudo su - postgres
  $ psql -c \"SHOW log_connections\"
  $ psql -c \"SHOW log_disconnections\"

  If either is off, this is a finding.

  Next, verify that log_line_prefix contains sufficient information by running
  the following SQL:

  $ sudo su - postgres
  $ psql -c \"SHOW log_line_prefix\"

  If log_line_prefix does not contain at least %m %u %d %c, this is a finding."
    
  desc "fix", "Note: The following instructions use the PGDATA and PGVER
  environment variables. See supplementary content APPENDIX-F for instructions on
  configuring PGDATA and APPENDIX-H for PGVER.

  To ensure that logging is enabled, review supplementary content APPENDIX-C for
  instructions on enabling logging. 

  First, as the database administrator (shown here as \"postgres\"), edit
  postgresql.conf: 

  $ sudo su - postgres 
  $ vi ${PGDATA?}/postgresql.conf 

  Edit the following parameters as such: 

  log_connections = on 
  log_disconnections = on 
  log_line_prefix = '< %m %u %d %c: >' 

  Where: 
  * %m is the time and date 
  * %u is the username 
  * %d is the database 
  * %c is the session ID for the connection 

  Now, as the system administrator, reload the server with the new configuration: 

  # SYSTEMD SERVER ONLY 
  $ sudo systemctl reload postgresql-${PGVER?}

  # INITD SERVER ONLY 
  $ sudo service postgresql-${PGVER?} reload"


  sql = postgres_session(pg_dba, pg_dba_password, pg_host)

  describe sql.query('SHOW log_connections;', [pg_db]) do
    its('output') { should_not match /off|false/i }
  end

  describe sql.query('SHOW log_disconnections;', [pg_db]) do
    its('output') { should_not match /off|false/i }
  end

  log_line_prefix_escapes = %w(%m %u %d %c)

  log_line_prefix_escapes.each do |escape|
    describe sql.query('SHOW log_line_prefix;', [pg_db]) do
      its('output') { should include escape }
    end
  end
end
