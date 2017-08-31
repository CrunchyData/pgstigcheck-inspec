# encoding: utf-8
#
=begin
-----------------
Benchmark: PostgreSQL 9.x Security Technical Implementation Guide
Status: Accepted

This Security Technical Implementation Guide is published as a tool to improve
the security of Department of Defense (DoD) information systems. The
requirements are derived from the National Institute of Standards and
Technology (NIST) 800-53 and related documents. Comments or proposed revisions
to this document should be sent via email to the following address:
disa.stig_spt@mail.mil.

Release Date: 2017-01-20
Version: 1
Publisher: DISA
Source: STIG.DOD.MIL
uri: http://iase.disa.mil
-----------------
=end
PG_OWNER = attribute(
  'pg_owner',
  description: "The system user of the postgres process",
)

PG_DBA = attribute(
  'pg_dba',
  description: 'The postgres DBA user to access the test database',
)

PG_DBA_PASSWORD = attribute(
  'pg_dba_password',
  description: 'The password for the postgres DBA user',
)

PG_DB = attribute(
  'pg_db',
  description: 'The database used for tests',
)

PG_HOST = attribute(
  'pg_host',
  description: 'The hostname or IP address used to connect to the database',
)

PG_SUPERUSERS = attribute(
  'pg_superusers',
  description: 'Authorized superuser accounts',
)

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
  When discretionary access control policies are implemented, subjects are not
  constrained with regard to what actions they can take with information for
  which they have already been granted access. Thus, subjects that have been
  granted access to information are not prevented from passing (i.e., the
  subjects have the discretion to pass) the information to other subjects or
  objects.
  A subject that is constrained in its operation by Mandatory Access Control
  policies is still able to operate under the less rigorous constraints of this
  requirement. Thus, while Mandatory Access Control imposes constraints
  preventing a subject from passing information to another subject operating at
  a different sensitivity level, this requirement permits the subject to pass
  the information to any subject at the same sensitivity level.
  The policy is bounded by the information system boundary. Once the information
  is passed outside of the control of the information system, additional means
  may be required to ensure the constraints remain in effect. While the older,
  more traditional definitions of discretionary access control require i
  dentity-based access control, that limitation is not required for this use of
  discretionary access control."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000328-DB-000301"
  tag "gid": "V-72883"
  tag "rid": "SV-87535r1_rule"
  tag "stig_id": "PGS9-00-002200"
  tag "cci": "CCI-002165"
  tag "nist": ["AC-3 (4)", "Rev_4"]
  tag "check": "Review system documentation to identify the required
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
  tag "fix": "Implement the organization's DAC policy in the security
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

  sql = postgres_session(PG_DBA, PG_DBA_PASSWORD, PG_HOST)

  authorized_owners = PG_SUPERUSERS

  databases_sql = "SELECT datname FROM pg_catalog.pg_database where datname = '#{PG_DB}';"
  databases_query = sql.query(databases_sql, [PG_DB])
  databases = databases_query.lines
  types = %w(t s v) # tables, sequences views

  databases.each do |database|
    schemas_sql = ''
    functions_sql = ''

    if database == 'postgres'
      schemas_sql = "SELECT n.nspname, pg_catalog.pg_get_userbyid(n.nspowner) "\
        "FROM pg_catalog.pg_namespace n "\
        "WHERE pg_catalog.pg_get_userbyid(n.nspowner) <> '#{PG_OWNER}';"
      functions_sql = "SELECT n.nspname, p.proname, "\
        "pg_catalog.pg_get_userbyid(n.nspowner) "\
        "FROM pg_catalog.pg_proc p "\
        "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "\
        "WHERE pg_catalog.pg_get_userbyid(n.nspowner) <> '#{PG_OWNER}';"
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
          "AND pg_catalog.pg_get_userbyid(n.nspowner) <> '#{PG_OWNER}' "
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
