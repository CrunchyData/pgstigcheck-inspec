pg_conf_file= input('pg_conf_file')

log_line_prefix = input(
  'log_line_prefix',
  description: "The required log line elemets per the organizational guidance",
  value: ['%m','%u','%d','%s']
)

pg_host = input('pg_host')

login_user = input('login_user')

pg_dba = input('pg_dba')

pg_dba_password = input('pg_dba_password')

pg_db = input('pg_db')

approved_ext = input(
  'approved_ext',
  description: "the list of approved postgresql extensions that the database may enable",
  value: ['pgcrypto']
)

control "V-73009" do
  title "Access to external executables must be disabled or restricted."
  desc  "Information systems are capable of providing a wide variety of
  functions and services. Some of the functions and services, provided by
  default, may not be necessary to support essential organizational operations
  (e.g., key missions, functions).

  It is detrimental for applications to provide, or install by default,
  functionality exceeding requirements or mission objectives.

  Applications must adhere to the principles of least functionality by
  providing only essential capabilities.

  PostgreSQLs may spawn additional external processes to execute procedures
  that are defined in PostgreSQL but stored in external host files (external
  procedures). The spawned process used to execute the external procedure may
  operate within a different OS security context than PostgreSQL and provide
  unauthorized access to the host system."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000141-DB-000093"
  tag "gid": "V-73009"
  tag "rid": "SV-87661r1_rule"
  tag "stig_id": "PGS9-00-009100"
  tag "fix_id": "F-79455r1_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
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
  desc "check", "PostgreSQL’s Copy command can interact with the underlying OS.
  Only superuser has access to this command.

  First, as the database administrator (shown here as \"postgres\"), run the
  following SQL to list all roles and their privileges:

  $ sudo su - postgres
  $ psql -x -c \"\\du\"

  If any role has \"superuser\" that should not, this is a finding.

  It is possible for an extension to contain code that could access external
  executables via SQL. To list all installed extensions, as the database
  administrator (shown here as \"postgres\"), run the following SQL:

  $ sudo su - postgres
  $ psql -x -c \"SELECT * FROM pg_available_extensions WHERE installed_version IS
  NOT NULL\"

  If any extensions are installed that are not approved, this is a finding."
    
  desc "fix", "To remove superuser from a role, as the database administrator
  (shown here as \"postgres\"), run the following SQL:

  $ sudo su - postgres
  $ psql -c \"ALTER ROLE <role-name> WITH NOSUPERUSER\"

  To remove extensions from PostgreSQL, as the database administrator (shown here
  as \"postgres\"), run the following SQL:

  $ sudo su - postgres
  $ psql -c \"DROP EXTENSION extension_name\""


dbs = nil
db = nil

if !("#{pg_db}".to_s.empty?)
  db = ["#{pg_db}"]
  dbs = db.map { |x| "-d #{x}" }.join(' ')
end

# @todo fix stdout, SSP roles should states which ones SHOULD have superuser, others should not? need datafile to test against the DB.

  describe command("PGPASSWORD='#{pg_dba_password}' psql -U #{pg_dba} -d #{pg_db} -h #{pg_host} -A -t -c \"select * from pg_shadow where usename <> 'postgres' and usesuper = 't';") do
    its('stdout.strip') { should match '' }
  end

# @todo how do I check to see if any extensions are installed that are not approved?  fix stdout value?

  describe.one do
    approved_ext.each do |extension|
      describe command("PGPASSWORD='#{pg_dba_password}' psql -U #{pg_dba} -d #{pg_db} -h #{pg_host} -A -t -c \"SELECT * FROM pg_available_extensions WHERE installed_version IS NOT NULL\"") do
        its('stdout.strip') { should match extension }
      end
    end
  end
end  
#describe command("PGPASSWORD='#{pg_dba_password}' psql -U #{pg_dba} -d #{pg_db} -h #{pg_host} -A -t -c \"SELECT * FROM pg_available_extensions WHERE installed_version IS NOT NULL\"") do
#    its('stdout.strip') { should match 'error' }
#  end
#end
