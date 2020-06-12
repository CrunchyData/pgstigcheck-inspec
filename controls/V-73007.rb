pg_conf_file= input('pg_conf_file')

pg_host = input('pg_host')

login_user = input('login_user')

pg_dba = input('pg_dba')

pg_dba_password = input('pg_dba_password')

pg_db = input('pg_db')

approved_ext = input('approved_ext')

control "V-73007" do
  title "Unused database components, PostgreSQL software, and database objects
  must be removed."
  desc  "Information systems are capable of providing a wide variety of
  functions and services. Some of the functions and services, provided by
  default, may not be necessary to support essential organizational operations
  (e.g., key missions, functions). 

  It is detrimental for software products to provide, or install by default,
  functionality exceeding requirements or mission objectives.  

  PostgreSQL must adhere to the principles of least functionality by
  providing only essential capabilities."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000141-DB-000091"
  tag "gid": "V-73007"
  tag "rid": "SV-87659r2_rule"
  tag "stig_id": "PGS9-00-008900"
  tag "fix_id": "F-79453r2_fix"
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
  desc "check", "To get a list of all extensions installed, use the following
  commands: 

  $ sudo su - postgres 
  $ psql -c \"select * from pg_extension where extname != 'plpgsql'\" 

  If any extensions exist that are not approved, this is a finding."
  
  desc "fix", "To remove extensions, use the following commands:

  $ sudo su - postgres
  $ psql -c \"DROP EXTENSION <extension_name>\"

  Note: It is recommended that plpgsql not be removed."

# @todo executed the SELECT statement in psql, got no output, psql not hardended? fix the stdout code, as needed.

dbs = nil
db = nil

if !("#{pg_db}".to_s.empty?)
  db = ["#{pg_db}"]
  dbs = db.map { |x| "-d #{x}" }.join(' ')
end

# @todo need SSP data to compare that no extensions are present that are not approved?

  describe.one do
    approved_ext.each do |extension|
      describe command("PGPASSWORD='#{pg_dba_password}' psql -U #{pg_dba} -d #{pg_db} -h #{pg_host} -A -t -c \"SELECT * from pg_extension where extname != 'plpgsql';\" | cut -d'|' -f 1") do
        its('stdout.strip') { should match extension }
      end
    end
    describe command("PGPASSWORD='#{pg_dba_password}' psql -U #{pg_dba} -d #{pg_db} -h #{pg_host} -A -t -c \"SELECT * from pg_extension where extname != 'plpgsql';\"") do
      its('stdout.strip') { should be "" }
    end
  end
end
