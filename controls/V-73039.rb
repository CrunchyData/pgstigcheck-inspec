pg_data_dir = input('pg_data_dir')

pg_group = input('pg_group')

pg_owner = input('pg_owner')

pg_log_dir = input('pg_log_dir')

pg_superusers = input('pg_superusers')

pgaudit_installation = input('pgaudit_installation')

control "V-73039" do
  title "PostgreSQL must protect its audit features from unauthorized access."
  desc  "Protecting audit data also includes identifying and protecting the
  tools used to view and manipulate log data.

  Depending upon the log format and application, system and application log
  tools may provide the only means to manipulate and manage application and
  system log data. It is, therefore, imperative that access to audit tools be
  controlled and protected from unauthorized access.

  Applications providing tools to interface with audit data will leverage
  user permissions and roles identifying the user accessing the tools and the
  corresponding rights the user enjoys in order make access decisions regarding
  the access to audit tools.

  Audit tools include, but are not limited to, OS-provided audit tools,
  vendor-provided audit tools, and open source audit tools needed to successfully
  view and manipulate audit information system activity and records.

  If an attacker were to gain access to audit tools, he could analyze audit
  logs for system weaknesses or weaknesses in the auditing itself. An attacker
  could also manipulate logs to hide evidence of malicious activity."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000121-DB-000202"
  tag "gid": "V-73039"
  tag "rid": "SV-87691r2_rule"
  tag "stig_id": "PGS9-00-010700"
  tag "fix_id": "F-79485r2_fix"
  tag "cci": ["CCI-001493"]
  tag "nist": ["AU-9", "Rev_4"]
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
  desc "check", "Note: The following instructions use the PGDATA and PGVER
  environment variables. See supplementary content APPENDIX-F for instructions on
  configuring PGDATA and APPENDIX-H for PGVER. Only the database owner and
  superuser can alter configuration of PostgreSQL. 

  Make sure the pg_log directory are owned by postgres user and group: 

  $ sudo su - postgres 
  $ ls -la ${PGDATA?}/pg_log 

  If pg_log is not owned by the database owner, this is a finding. 

  Make sure the data directory are owned by postgres user and group. 

  $ sudo su - postgres 
  $ ls -la ${PGDATA?} 

  If PGDATA is not owned by the database owner, this is a finding. 

  Make sure pgaudit installation is owned by root: 

  $ sudo su - postgres 
  $ ls -la /usr/pgsql-${PGVER?}/share/contrib/pgaudit 

  If pgaudit installation is not owned by root, this is a finding. 

  Next, as the database administrator (shown here as \"postgres\"), run the
  following SQL to list all roles and their privileges: 

  $ sudo su - postgres 
  $ psql -x -c \"\\du\" 

  If any role has \"superuser\" that should not, this is a finding."
  
  desc "fix", "Note: The following instructions use the PGDATA and PGVER
  environment variables. See supplementary content APPENDIX-F for instructions on
  configuring PGDATA and APPENDIX-H for PGVER.

  If pg_log or data directory are not owned by postgres user and group, configure
  them as follows: 

  $ sudo chown -R postgres:postgres ${PGDATA?} 

  If the pgaudit installation is not owned by root user and group, configure it
  as follows: 

  $ sudo chown -R root:root /usr/pgsql-${PGVER?}/share/contrib/pgaudit

  To remove superuser from a role, as the database administrator (shown here as
  \"postgres\"), run the following SQL: 

  $ sudo su - postgres 
  $ psql -c \"ALTER ROLE <role-name> WITH NOSUPERUSER\""

  describe directory(pg_log_dir) do
    it { should be_owned_by pg_owner }
    it { should be_grouped_into pg_group }
  end 

  describe file(pgaudit_installation) do
    it { should_not be_owned_by 'root' }
  end 

  describe directory(pg_data_dir) do
    it { should be_owned_by pg_owner }
    it { should be_grouped_into pg_group }
  end 

  describe file(pgaudit_installation) do
    it { should_not be_owned_by 'root' }
  end

  #todo Needs automation of superuser check
end
