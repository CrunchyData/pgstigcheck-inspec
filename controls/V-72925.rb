pg_ver = input('pg_version')

pg_dba = input('pg_dba')

pg_dba_password = input('pg_dba_password')

pg_db = input('pg_db')

pg_host = input('pg_host')

pg_log_dir = input('pg_log_dir')

pg_audit_log_dir = input('pg_audit_log_dir')

control "V-72925" do
  title "PostgreSQL must generate audit records showing starting and ending
time for user access to the database(s)."
  desc  "For completeness of forensic analysis, it is necessary to know how
long a user's (or other principal's) connection to PostgreSQL lasts. This can
be achieved by recording disconnections, in addition to logons/connections, in
the audit logs.

    Disconnection may be initiated by the user or forced by the system (as in a
timeout) or result from a system or network failure. To the greatest extent
possible, all disconnections must be logged."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000505-DB-000352"
  tag "gid": "V-72925"
  tag "rid": "SV-87577r2_rule"
  tag "stig_id": "PGS9-00-004700"
  tag "fix_id": "F-79369r2_fix"
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

  First, log into the database with the postgres user by running the following
  commands:

  $ sudo su - postgres
  $ psql -U postgres

  Next, as the database administrator, verify the log for a connection audit
  trail:

  $ sudo su - postgres
  $ cat ${PGDATA?}/pg_log/postgresql-Tue.log
  < 2016-02-23 20:25:39.931 EST postgres 56cfa993.7a72 postgres: >LOG: connection
  authorized: user=postgres database=postgres
  < 2016-02-23 20:27:45.428 EST postgres 56cfa993.7a72 postgres: >LOG: AUDIT:
  SESSION,1,1,READ,SELECT,,,SELECT current_user;,<none>
  < 2016-02-23 20:27:47.988 EST postgres 56cfa993.7a72 postgres: >LOG:
  disconnection: session time: 0:00:08.057 user=postgres database=postgres
  host=[local]

  If connections are not logged, this is a finding."

  desc "fix", "Note: The following instructions use the PGDATA and PGVER
  environment variables. See supplementary content APPENDIX-F for instructions on
  configuring PGDATA and APPENDIX-H for PGVER.

  To ensure that logging is enabled, review supplementary content APPENDIX-C for
  instructions on enabling logging. 

  If logging is enabled the following configurations must be made to log
  connections, date/time, username, and session identifier. 

  First, as the database administrator (shown here as \"postgres\"), edit
  postgresql.conf by running the following: 

  $ sudo su - postgres 
  $ vi ${PGDATA?}/postgresql.conf 

  Edit the following parameters: 

  log_connections = on 
  log_disconnections = on 
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

  describe command("cat `find #{pg_audit_log_dir} -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d\" \"` | grep \"connection authorized\"") do
    its('stdout') { should match /^.*user=postgres.*$/ }
  end

end
