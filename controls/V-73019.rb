pg_ver = input('pg_version')

pg_dba = input('pg_dba')

pg_dba_password = input('pg_dba_password')

pg_db = input('pg_db')

pg_host = input('pg_host')

control "V-73019" do
  title "PostgreSQL must protect against a user falsely repudiating having
  performed organization-defined actions."
  desc  "Non-repudiation of actions taken is required in order to maintain data
  integrity. Examples of particular actions taken by individuals include creating
  information, sending a message, approving information (e.g., indicating
  concurrence or signing a contract), and receiving a message.

  Non-repudiation protects against later claims by a user of not having
  created, modified, or deleted a particular data item or collection of data in
  the database.

  In designing a database, the organization must define the types of data and
  the user actions that must be protected from repudiation. The implementation
  must then include building audit features into the application data tables, and
  configuring PostgreSQL' audit tools to capture the necessary audit trail.
  Design and implementation also must ensure that applications pass individual
  user identification to PostgreSQL, even where the application connects to
  PostgreSQL with a standard, shared account."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000080-DB-000063"
  tag "gid": "V-73019"
  tag "rid": "SV-87671r2_rule"
  tag "stig_id": "PGS9-00-009700"
  tag "fix_id": "F-79465r2_fix"
  tag "cci": ["CCI-000166"]
  tag "nist": ["AU-10", "Rev_4"]
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
  desc "check", "First, as the database administrator, review the current
  log_line_prefix settings by running the following SQL: 

  $ sudo su - postgres 
  $ psql -c \"SHOW log_line_prefix\" 

  If log_line_prefix does not contain at least '< %m %a %u %d %r %p %m >', this
  is a finding. 

  Next, review the current shared_preload_libraries settings by running the
  following SQL: 

  $ psql -c \"SHOW shared_preload_libraries\" 

  If shared_preload_libraries does not contain \"pgaudit\", this is a finding."
  
  desc "fix", "Note: The following instructions use the PGDATA and PGVER
  environment variables. See supplementary content APPENDIX-F for instructions on
  configuring PGDATA and APPENDIX-H for PGVER.

  Configure the database to supply additional auditing information to protect
  against a user falsely repudiating having performed organization-defined
  actions. 

  Using pgaudit PostgreSQL can be configured to audit these requests. See
  supplementary content APPENDIX-B for documentation on installing pgaudit. 

  To ensure that logging is enabled, review supplementary content APPENDIX-C for
  instructions on enabling logging. 

  Modify the configuration of audit logs to include details identifying the
  individual user: 

  First, as the database administrator (shown here as \"postgres\"), edit
  postgresql.conf: 

  $ sudo su - postgres 
  $ vi ${PGDATA?}/postgresql.conf 

  Extra parameters can be added to the setting log_line_prefix to identify the
  user: 

  log_line_prefix = '< %m %a %u %d %r %p %m >' 

  Now, as the system administrator, reload the server with the new configuration: 

  # SYSTEMD SERVER ONLY 
  $ sudo systemctl reload postgresql-${PGVER?}

  # INITD SERVER ONLY 
  $ sudo service postgresql-${PGVER?} reload 

  Use accounts assigned to individual users. Where the application connects to
  PostgreSQL using a standard, shared account, ensure that it also captures the
  individual user identification and passes it to PostgreSQL."


  sql = postgres_session(pg_dba, pg_dba_password, pg_host)

  log_line_prefix_escapes = %w(%m %u %d %p %r %a)

  log_line_prefix_escapes.each do |escape|
    describe sql.query('SHOW log_line_prefix;', [pg_db]) do
      its('output') { should include escape }
    end
  end

  describe sql.query('SHOW shared_preload_libraries;', [pg_db]) do
    its('output') { should include 'pgaudit' }
  end
end
