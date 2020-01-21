pg_owner = input('pg_owner')

pg_dba = input('pg_dba')

pg_dba_password = input('pg_dba_password')

pg_db = input('pg_db')

pg_host = input('pg_host')

pg_superusers = input('pg_superusers')

control "V-72883" do
  title "PostgreSQL must enforce discretionary access control policies, as
  defined by the data owner, over defined subjects and objects."
  desc  "Discretionary Access Control (DAC) is based on the notion that
  individual users are \"owners\" of objects and therefore have discretion over
  who should be authorized to access the object and in which mode (e.g., read or
  write). Ownership is usually acquired as a consequence of creating the object
  or via specified ownership assignment. DAC allows the owner to determine who
  will have access to objects they control. An example of DAC includes
  user-controlled table permissions.

  When discretionary access control policies are implemented, subjects are
  not constrained with regard to what actions they can take with information for
  which they have already been granted access. Thus, subjects that have been
  granted access to information are not prevented from passing (i.e., the
  subjects have the discretion to pass) the information to other subjects or
  objects.

  A subject that is constrained in its operation by Mandatory Access Control
  policies is still able to operate under the less rigorous constraints of this
  requirement. Thus, while Mandatory Access Control imposes constraints
  preventing a subject from passing information to another subject operating at a
  different sensitivity level, this requirement permits the subject to pass the
  information to any subject at the same sensitivity level.

  The policy is bounded by the information system boundary. Once the
  information is passed outside of the control of the information system,
  additional means may be required to ensure the constraints remain in effect.
  While the older, more traditional definitions of discretionary access control
  require identity-based access control, that limitation is not required for this
  use of discretionary access control."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000328-DB-000301"
  tag "gid": "V-72883"
  tag "rid": "SV-87535r1_rule"
  tag "stig_id": "PGS9-00-002200"
  tag "fix_id": "F-79325r2_fix"
  tag "cci": ["CCI-002165"]
  tag "nist": ["AC-3 (4)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  desc "check", "Review system documentation to identify the required
  discretionary access control (DAC).

  Review the security configuration of the database and PostgreSQL. If
  applicable, review the security configuration of the application(s) using the
  database.

  If the discretionary access control defined in the documentation is not
  implemented in the security configuration, this is a finding.

  If any database objects are found to be owned by users not authorized to own
  database objects, this is a finding.

  To check the ownership of objects in the database, as the database
  administrator, run the following:

  $ sudo su - postgres
  $ psql -c \"\\dn *.*\"
  $ psql -c \"\\dt *.*\"
  $ psql -c \"\\ds *.*\"
  $ psql -c \"\\dv *.*\"
  $ psql -c \"\\df+ *.*\"

  If any role is given privileges to objects it should not have, this is a
  finding."
    desc "fix", "Implement the organization's DAC policy in the security
  configuration of the database and PostgreSQL, and, if applicable, the security
  configuration of the application(s) using the database.

  To GRANT privileges to roles, as the database administrator (shown here as
  \"postgres\"), run statements like the following examples:

  $ sudo su - postgres
  $ psql -c \"CREATE SCHEMA test\"
  $ psql -c \"GRANT CREATE ON SCHEMA test TO bob\"
  $ psql -c \"CREATE TABLE test.test_table(id INT)\"
  $ psql -c \"GRANT SELECT ON TABLE test.test_table TO bob\"

  To REVOKE privileges to roles, as the database administrator (shown here as
  \"postgres\"), run statements like the following examples:

  $ psql -c \"REVOKE SELECT ON TABLE test.test_table FROM bob\"
  $ psql -c \"REVOKE CREATE ON SCHEMA test FROM bob\""

  sql = postgres_session(pg_dba, pg_dba_password, pg_host)

  authorized_owners = pg_superusers

  databases_sql = "SELECT datname FROM pg_catalog.pg_database where datname = '#{pg_db}';"
  databases_query = sql.query(databases_sql, [pg_db])
  databases = databases_query.lines
  types = %w(t s v) # tables, sequences views

  databases.each do |database|
    schemas_sql = ''
    functions_sql = ''

    if database == 'postgres'
      schemas_sql = "SELECT n.nspname, pg_catalog.pg_get_userbyid(n.nspowner) "\
        "FROM pg_catalog.pg_namespace n "\
        "WHERE pg_catalog.pg_get_userbyid(n.nspowner) <> '#{pg_owner}';"
      functions_sql = "SELECT n.nspname, p.proname, "\
        "pg_catalog.pg_get_userbyid(n.nspowner) "\
        "FROM pg_catalog.pg_proc p "\
        "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "\
        "WHERE pg_catalog.pg_get_userbyid(n.nspowner) <> '#{pg_owner}';"
    else
      schemas_sql = "SELECT n.nspname, pg_catalog.pg_get_userbyid(n.nspowner) "\
        "FROM pg_catalog.pg_namespace n "\
        "WHERE pg_catalog.pg_get_userbyid(n.nspowner) "\
        "NOT IN (#{authorized_owners.map { |e| "'#{e}'" }.join(',')}) "\
        "AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema';"
      functions_sql = "SELECT n.nspname, p.proname, "\
        "pg_catalog.pg_get_userbyid(n.nspowner) "\
        "FROM pg_catalog.pg_proc p "\
        "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "\
        "WHERE pg_catalog.pg_get_userbyid(n.nspowner) "\
        "NOT IN (#{authorized_owners.map { |e| "'#{e}'" }.join(',')}) "\
        "AND n.nspname <> 'pg_catalog' AND n.nspname <> 'information_schema';"
    end

    connection_error = "FATAL:\\s+database \"#{database}\" is not currently "\
      "accepting connections"
    connection_error_regex = Regexp.new(connection_error)
    
    sql_result=sql.query(schemas_sql, [database])

    describe.one do
      describe sql_result do
        its('output') { should eq '' }
      end

      describe sql_result do
        it { should match connection_error_regex }
      end
    end

    sql_result=sql.query(functions_sql, [database])

    describe.one do
      describe sql_result do
        its('output') { should eq '' }
      end

      describe sql_result do
        it { should match connection_error_regex }
      end
    end

    types.each do |type|
      objects_sql = ''

      if database == 'postgres'
        objects_sql = "SELECT n.nspname, c.relname, c.relkind, "\
          "pg_catalog.pg_get_userbyid(n.nspowner) FROM pg_catalog.pg_class c "\
          "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "\
          "WHERE c.relkind IN ('#{type}','s','') "\
          "AND pg_catalog.pg_get_userbyid(n.nspowner) <> '#{pg_owner}' "
          "AND n.nspname !~ '^pg_toast';"
      else
        objects_sql = "SELECT n.nspname, c.relname, c.relkind, "\
          "pg_catalog.pg_get_userbyid(n.nspowner) FROM pg_catalog.pg_class c "\
          "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "\
          "WHERE c.relkind IN ('#{type}','s','') "\
          "AND pg_catalog.pg_get_userbyid(n.nspowner) "\
          "NOT IN (#{authorized_owners.map { |e| "'#{e}'" }.join(',')}) "\
          "AND n.nspname <> 'pg_catalog' AND n.nspname <> 'information_schema'"\
          " AND n.nspname !~ '^pg_toast';"
      end

      sql_result=sql.query(objects_sql, [database])

      describe.one do
        describe sql_result do
          its('output') { should eq '' }
        end

        describe sql_result do
          it { should match connection_error_regex }
        end
      end
    end
  end
end
