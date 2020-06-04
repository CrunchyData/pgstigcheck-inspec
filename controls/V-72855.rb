pg_owner = input('pg_owner')

pg_conf_file = input('pg_conf_file')

pg_hba_conf_file = input('pg_hba_conf_file')

pg_ident_conf_file = input('pg_ident_conf_file')

pg_dba = input('pg_dba')

pg_dba_password = input('pg_dba_password')

pg_db = input('pg_db')

pg_port = input('pg_port')

pg_host = input('pg_host')

control "V-72855" do
  title "PostgreSQL must limit privileges to change functions and triggers, and
  links to software external to PostgreSQL."
  desc  "If the system were to allow any user to make changes to software
  libraries, those changes might be implemented without undergoing the
  appropriate testing and approvals that are part of a robust change management
  process.

  Accordingly, only qualified and authorized individuals must be allowed to
  obtain access to information system components for purposes of initiating
  changes, including upgrades and modifications.

  Unmanaged changes that occur to the database code can lead to unauthorized
  or compromised installations."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000133-DB-000179"
  tag "gid": "V-72855"
  tag "rid": "SV-87507r1_rule"
  tag "stig_id": "PGS9-00-000710"
  tag "fix_id": "F-79297r1_fix"
  tag "cci": ["CCI-001499"]
  tag "nist": ["CM-5 (6)", "Rev_4"]
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
  desc "check", "Only owners of objects can change them. To view all functions,
  triggers, and trigger procedures, their ownership and source, as the database
  administrator (shown here as \"postgres\") run the following SQL:

  $ sudo su - postgres
  $ psql -x -c \"\\df+\"

  Only the OS database owner user (shown here as \"postgres\") or a PostgreSQL
  superuser can change links to external software. As the database administrator
  (shown here as \"postgres\"), check the permissions of configuration files for
  the database:

  $ sudo su - postgres
  $ ls -la ${PGDATA?}

  If any files are not owned by the database owner or have permissions allowing
  others to modify (write) configuration files, this is a finding."
    
  desc "fix", "To change ownership of an object, as the database administrator
  (shown here as \"postgres\"), run the following SQL:

  $ sudo su – postgres
  $ psql -c \"ALTER FUNCTION function_name OWNER TO new_role_name\"

  To change ownership of postgresql.conf, as the database administrator (shown
  here as \"postgres\"), run the following commands:

  $ sudo su - postgres
  $ chown postgres:postgres ${PGDATA?}/postgresql.conf
  $ chmod 0600 ${PGDATA?}/postgresql.conf

  To remove superuser from a role, as the database administrator (shown here as
  \"postgres\"), run the following SQL:

  $ sudo su - postgres
  $ psql -c \"ALTER ROLE rolename WITH NOSUPERUSER\""

# @todo draft code below, how do we test for manual checks?

  describe file(pg_conf_file) do
    it { should be_owned_by pg_owner }
    its('mode') { should cmp '0600' }
  end

  describe file(pg_hba_conf_file) do
    it { should be_owned_by pg_owner }
    its('mode') { should cmp '0600' }
  end

  describe file(pg_ident_conf_file) do
    it { should be_owned_by pg_owner }
    its('mode') { should cmp '0600' }
  end  

  if !("#{pg_db}".to_s.empty?)
    db = ["#{pg_db}"]
    dbs = db.map { |x| "-d #{x}" }.join(' ')
  end

  sql = postgres_session(pg_dba, pg_dba_password, pg_host)
  
  describe sql.query ("SELECT n.nspname as Schema, p.proname as Name, pg_catalog.pg_get_function_result(p.oid) as ResultDataType, pg_catalog.pg_get_function_arguments(p.oid) as ArgumentDataTypes, pg_catalog.pg_get_userbyid(p.proowner) as Owner, CASE WHEN prosecdef THEN 'definer' ELSE 'invoker' END AS Security, pg_catalog.array_to_string(p.proacl, E'\n') AS AccessPrivileges FROM pg_catalog.pg_proc p LEFT JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace LEFT JOIN pg_catalog.pg_language l ON l.oid = p.prolang WHERE pg_catalog.pg_function_is_visible(p.oid) AND n.nspname <> 'pg_catalog' AND n.nspname <> 'information_schema' AND pg_catalog.pg_get_userbyid(p.proowner) <> 'postgres';") do
    its('output') { should eq '' } 
  end
end
