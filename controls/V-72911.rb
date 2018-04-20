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

PG_OBJECT_GRANTED_PRIVILEGES = attribute(
  'pg_object_granted_privileges',
  description: 'Privileges that can be granted to a role for a database object',
  default: 'arwdDxt'
)

PG_OBJECT_PUBLIC_PRIVILEGES = attribute(
  'pg_object_public_privileges',
  description: 'Privileges that can be granted to public for a database object',
  default: 'r'
)

PG_OBJECT_EXCEPTIONS = attribute(
  'pg_object_exceptions',
  description: 'List of database objects that should be excepted from tests',
  default: ['pg_settings']
)

control "V-72911" do
  title "PostgreSQL must isolate security functions from non-security functions."
  desc  "An isolation boundary provides access control and protects the integrity
  of the hardware, software, and firmware that perform security functions.
  Security functions are the hardware, software, and/or firmware of the
  information system responsible for enforcing the system security policy and
  supporting the isolation of code and data on which the protection is based.
  Developers and implementers can increase the assurance in security functions
  by employing well-defined security policy models; structured, disciplined, and
  rigorous hardware and software development techniques; and sound system/security
  engineering principles.
  Database Management Systems typically separate security functionality from
  non-security functionality via separate databases or schemas. Database objects
  or code implementing security functionality should not be commingled with
  objects or code implementing application logic. When security and non-security
  functionality are commingled, users who have access to non-security
  functionality may be able to access security functionality."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000233-DB-000124"
  tag "gid": "V-72911"
  tag "rid": "SV-87563r1_rule"
  tag "stig_id": "PGS9-00-004000"
  tag "cci": ["CCI-001084"]
  tag "nist": ["SC-3", "Rev_4"]
  tag "check": "Check PostgreSQL settings to determine whether objects or code
  implementing security functionality are located in a separate security domain,
  such as a separate database or schema created specifically for security
  functionality.
  By default, all objects in pg_catalog and information_schema are owned by the
  database administrator.
  To check the access controls for those schemas, as the database administrator
  (shown here as \"postgres\"), run the following commands to review the access
  privileges granted on the data dictionary and security tables, views,
  sequences, functions and trigger procedures:
  $ sudo su - postgres
  $ psql -x -c \"\\dp pg_catalog.*\"
  $ psql -x -c \"\\dp information_schema.*\"
  Repeat the \\dp statements for any additional schemas that contain locally
  defined security objects.

Repeat using \\df+*.* to review ownership of
  PostgreSQL functions:
  $ sudo su - postgres
  $ psql -x -c \"\\df+ pg_catalog.*\"
  $ psql -x -c \"\\df+ information_schema.*\"
  Refer to the PostgreSQL online documentation for GRANT for help in
  interpreting the Access Privileges column in the output from \\du. Note that
  an entry starting with an equals sign indicates privileges granted to Public
  (all users). By default, most of the tables and views in the pg_catalog and
  information_schema schemas can be read by Public.
  If any user besides the database administrator(s) is listed in access
  privileges and not documented, this is a finding.
  If security-related database objects or code are not kept separate, this is a
  finding."
  tag "fix": "Do not locate security-related database objects with application
  tables or schema.
  Review any site-specific applications security modules built into the
  database: determine what schema they are located in and take appropriate
  action.
  Do not grant access to pg_catalog or information_schema to anyone but the
  database administrator(s). Access to the database administrator account(s)
  must not be granted to anyone without official approval."

  exceptions = "#{PG_OBJECT_EXCEPTIONS.map { |e| "'#{e}'" }.join(',')}"
  object_acl = "^(((#{PG_OWNER}=[#{PG_OBJECT_GRANTED_PRIVILEGES}]+|"\
    "=[#{PG_OBJECT_PUBLIC_PRIVILEGES}]+)\\/\\w+,?)+|)$"
  schemas = ['pg_catalog', 'information_schema']
  sql = postgres_session(PG_DBA, PG_DBA_PASSWORD, PG_HOST)

  schemas.each do |schema|
    objects_sql = "SELECT n.nspname, c.relname, c.relkind, "\
      "pg_catalog.array_to_string(c.relacl, E',') FROM pg_catalog.pg_class c "\
      "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "\
      "WHERE c.relkind IN ('r', 'v', 'm', 'S', 'f') "\
      "AND n.nspname ~ '^(#{schema})$' "\
      "AND pg_catalog.array_to_string(c.relacl, E',') !~ '#{object_acl}' "\
      "AND c.relname NOT IN (#{exceptions});"

    describe sql.query(objects_sql, [PG_DB]) do
      its('output') { should eq '' }
    end

    functions_sql = "SELECT n.nspname, p.proname, "\
      "pg_catalog.pg_get_userbyid(n.nspowner) "\
      "FROM pg_catalog.pg_proc p "\
      "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "\
      "WHERE n.nspname ~ '^(#{schema})$' "\
      "AND pg_catalog.pg_get_userbyid(n.nspowner) <> '#{PG_OWNER}';"

    describe sql.query(functions_sql, [PG_DB]) do
      its('output') { should eq '' }
    end
  end
end
