pg_dba = input('pg_dba')

pg_dba_password = input('pg_dba_password')

pg_db = input('pg_db')

pg_host = input('pg_host')

control "V-73045" do
  title "PostgreSQL must off-load audit data to a separate log management
  facility; this must be continuous and in near real time for systems with a
  network connection to the storage facility and weekly or more often for
  stand-alone systems."
  desc  "Information stored in one location is vulnerable to accidental or
  incidental deletion or alteration.

  Off-loading is a common process in information systems with limited audit
  storage capacity.

  PostgreSQL may write audit records to database tables, to files in the file
  system, to other kinds of local repository, or directly to a centralized log
  management system. Whatever the method used, it must be compatible with
  off-loading the records to the centralized system."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000515-DB-000318"
  tag "gid": "V-73045"
  tag "rid": "SV-87697r2_rule"
  tag "stig_id": "PGS9-00-011300"
  tag "fix_id": "F-79491r2_fix"
  tag "cci": ["CCI-001851"]
  tag "nist": ["AU-4 (1)", "Rev_4"]
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
  desc "check", "First, as the database administrator (shown here as
  \"postgres\"), ensure PostgreSQL uses syslog by running the following SQL:

  $ sudo su - postgres
  $ psql -c \"SHOW log_destination\"

  If log_destination is not syslog, this is a finding.

  Next, as the database administrator, check which log facility is configured by

  $ psql -c \"SHOW syslog_facility\"

  Check with the organization to see how syslog facilities are defined in their
  organization.

  If the wrong facility is configured, this is a finding.

  If PostgreSQL does not have a continuous network connection to the centralized
  log management system, and PostgreSQL audit records are not transferred to the
  centralized log management system weekly or more often, this is a finding."
  
  desc "fix", "Note: The following instructions use the PGDATA and PGVER
  environment variables. See supplementary content APPENDIX-F for instructions on
  configuring PGDATA and APPENDIX-H for PGVER.

  Configure PostgreSQL or deploy and configure software tools to transfer audit
  records to a centralized log management system, continuously and in near-real
  time where a continuous network connection to the log management system exists,
  or at least weekly in the absence of such a connection. 

  To ensure that logging is enabled, review supplementary content APPENDIX-C for
  instructions on enabling logging. 

  With logging enabled, as the database administrator (shown here as
  \"postgres\"), configure the follow parameters in postgresql.conf (the example
  uses the default values - tailor for environment): 

  Note: Consult the organization on how syslog facilities are defined in the
  syslog daemon configuration. 

  $ sudo su - postgres 
  $ vi ${PGDATA?}/postgresql.conf 
  log_destination = 'syslog' 
  syslog_facility = 'LOCAL0' 
  syslog_ident = 'postgres' 

  Now, as the system administrator, reload the server with the new configuration: 

  # SYSTEMD SERVER ONLY 
  $ sudo systemctl reload postgresql-${PGVER?}

  # INITD SERVER ONLY 
  $ sudo service postgresql-${PGVER?} reload"

    sql = postgres_session(pg_dba, pg_dba_password, pg_host)

  describe sql.query('SHOW log_destination;', [pg_db]) do
    its('output') { should cmp 'syslog'}
  end

  
  #Change comparison value based on organizational syslog defintions
  describe sql.query('SHOW syslog_facility;', [pg_db]) do
    its('output') { should cmp 'local0'}
  end  

  describe "Configure PostgreSQL or deploy and configure software tools to transfer audit records to a centralized log management system" do
    skip "If continuous network connection to the log management system does not exist, or at least weekly in the absence of such a connection. This is a finding"
  end
end
