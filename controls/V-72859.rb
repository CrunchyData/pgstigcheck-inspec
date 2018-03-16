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

PG_DATA_DIR = attribute(
  'pg_data_dir',
  description: 'The postgres data directory',
)

PG_SUPERUSERS = attribute(
  'pg_superusers',
  description: 'Authorized superuser accounts',
)

PG_HBA_CONF_FILE = attribute(
  'pg_hba_conf_file',
  description: 'The postgres hba configuration file',
)

PG_REPLICAS = attribute(
  'pg_replicas',
  description: 'List of postgres replicas in CIDR notation',
)

control "V-72859" do
  title "PostgreSQL must enforce approved authorizations for logical access to
        information and system resources in accordance with applicable access
        control policies."
  desc  "Authentication with a DoD-approved PKI certificate does not necessarily
        imply authorization to access PostgreSQL. To mitigate the risk of
        unauthorized access to sensitive information by entities that have been
        issued certificates by DoD-approved PKIs, all DoD systems, including
        databases, must be properly configured to implement access control
        policies.

        Successful authentication must not automatically give an entity access
        to an asset or security boundary. Authorization procedures and controls
        must be implemented to ensure each authenticated entity also has a
        validated and current authorization. Authorization is the process of
        determining whether an entity, once authenticated, is permitted to
        access a specific asset. Information systems use access control policies
        and enforcement mechanisms to implement this requirement.

        Access control policies include identity-based policies, role-based
        policies, and attribute-based policies. Access enforcement mechanisms
        include access control lists, access control matrices, and cryptography.

        These policies and mechanisms must be employed by the application to
        control access between users (or processes acting on behalf of users)
        and objects (e.g., devices, files, records, processes, programs, and domains)
        in the information system.

        This requirement is applicable to access control enforcement applications,
        a category that includes database management systems. If PostgreSQL does
        not follow applicable policy when approving access, it may be in conflict
        with networks or other applications in the information system. This may
        result in users either gaining or being denied access inappropriately and
        in conflict with applicable policy."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000033-DB-000084"
  tag "gid": "V-72859"
  tag "rid": "SV-87511r1_rule"
  tag "stig_id": "PGS9-00-000900"
  tag "cci": "CCI-000213"
  tag "nist": ["AC-3", "Rev_4"]
  tag "check": "From the system security plan or equivalent documentation,
  determine the appropriate permissions on database objects for each kind
  (group role) of user. If this documentation is missing, this is a finding.

  First, as the database administrator (shown here as \"postgres\"),
  check the privileges of all roles in the database by running the
  following SQL:

  $ sudo su - postgres
  $ psql -c '\\du'

  Review all roles and their associated privileges. If any roles'
  privileges exceed those documented, this is a finding.

  Next, as the database administrator (shown here as \"postgres\"),
  check the configured privileges for tables and columns by running
  the following SQL:

  $ sudo su - postgres
  $ psql -c '\\dp'

  Review all access privileges and column access privileges list.
  If any roles' privileges exceed those documented, this is a finding.

  Next, as the database administrator (shown here as \"postgres\"),
  check the configured authentication settings in pg_hba.conf:

  $ sudo su - postgres
  $ cat ${PGDATA?}/pg_hba.conf

  Review all entries and their associated authentication methods.

  If any entries do not have their documented authentication requirements,
  this is a finding."

  tag "fix": "Create and/or maintain documentation of each group role's
  appropriate permissions on database objects.

  Implement these permissions in the database, and remove any permissions that
  exceed those documented.

  The following are examples of how to use role privileges in PostgreSQL to
  enforce access controls. For a complete list of privileges, see the official
  documentation: https://www.postgresql.org/docs/current/static/sql-createrole.html

  #### Roles Example 1
  The following example demonstrates how to create an admin role with CREATEDB
  and CREATEROLE privileges.

  As the database administrator (shown here as \"postgres\"), run the following
  SQL:

  $ sudo su - postgres
  $ psql -c \"CREATE ROLE admin WITH CREATEDB CREATEROLE\"

  #### Roles Example 2
  The following example demonstrates how to create a role with a password that
  expires and makes the role a member of the \"admin\" group.

  As the database administrator (shown here as \"postgres\"), run the following SQL:

  $ sudo su - postgres
  $ psql -c \"CREATE ROLE joe LOGIN ENCRYPTED PASSWORD 'stig2016!' VALID UNTIL
'2016-09-20' IN ROLE admin\"

  #### Roles Example 3
  The following demonstrates how to revoke privileges from a role using REVOKE.

  As the database administrator (shown here as \"postgres\"), run the following SQL:

  $ sudo su - postgres
$ psql -c \"REVOKE admin FROM joe\"

  #### Roles Example 4
  The following demonstrates how to alter privileges in a role using ALTER.

  As the database administrator (shown here as \"postgres\"), run the following SQL:

  $ sudo su - postgres
$ psql -c \"ALTER ROLE joe NOLOGIN\"

  The following are examples of how to use grant privileges in PostgreSQL to
  enforce access controls on objects. For a complete list of privileges, see the
  official documentation:
https://www.postgresql.org/docs/current/static/sql-grant.html

  #### Grant Example 1
  The following example demonstrates how to grant INSERT on a table to a role.

  As the database administrator (shown here as \"postgres\"), run the following SQL:

  $ sudo su - postgres
  $ psql -c \"GRANT SELECT ON stig_test TO joe\"

  #### Grant Example 2
  The following example demonstrates how to grant ALL PRIVILEGES on a table to a
  role.

  As the database administrator (shown here as \"postgres\"), run the following SQL:

  $ sudo su - postgres
  $ psql -c \"GRANT ALL PRIVILEGES ON stig_test TO joe\"

  #### Grant Example 3
  The following example demonstrates how to grant a role to a role.

  As the database administrator (shown here as \"postgres\"), run the following SQL:

  $ sudo su - postgres
  $ psql -c \"GRANT admin TO joe\"

  #### Revoke Example 1
  The following example demonstrates how to revoke access from a role.

  As the database administrator (shown here as \"postgres\"), run the following SQL:

  $ sudo su - postgres
  $ psql -c \"REVOKE admin FROM joe\"

  To change authentication requirements for the database, as the database
  administrator (shown here as \"postgres\"), edit pg_hba.conf:

  $ sudo su - postgres
  $ vi ${PGDATA?}/pg_hba.conf

  Edit authentication requirements to the organizational requirements. See the
  official documentation for the complete list of options for authentication:
  http://www.postgresql.org/docs/current/static/auth-pg-hba-conf.html

  After changes to pg_hba.conf, reload the server:

  # SYSTEMD SERVER ONLY
  $ sudo systemctl reload postgresql-9.5

  # INITD SERVER ONLY
  $ sudo service postgresql-9.5 reload"

  sql = postgres_session(PG_DBA, PG_DBA_PASSWORD, PG_HOST)

  roles_sql = 'SELECT r.rolname FROM pg_catalog.pg_roles r;'
  roles_query = sql.query(roles_sql, [PG_DB])
  roles = roles_query.lines

  roles.each do |role|
    unless PG_SUPERUSERS.include?(role)
      superuser_sql = "SELECT r.rolsuper FROM pg_catalog.pg_roles r "\
        "WHERE r.rolname = '#{role}';"

      describe sql.query(superuser_sql, [PG_DB]) do
        its('output') { should_not eq 't' }
      end
    end
  end

  authorized_owners = PG_SUPERUSERS
  owners = authorized_owners.join('|')

  object_granted_privileges = 'arwdDxtU'
  object_public_privileges = 'r'
  object_acl = "^((((#{owners})=[#{object_granted_privileges}]+|"\
    "=[#{object_public_privileges}]+)\/\\w+,?)+|)\\|"
  object_acl_regex = Regexp.new(object_acl)

  objects_sql = "SELECT n.nspname, c.relname, c.relkind "\
    "FROM pg_catalog.pg_class c "\
    "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "\
    "WHERE c.relkind IN ('r', 'v', 'm', 'S', 'f') "\
    "AND n.nspname !~ '^pg_' AND pg_catalog.pg_table_is_visible(c.oid);"

  databases_sql = 'SELECT datname FROM pg_catalog.pg_database where not datistemplate;'
  databases_query = sql.query(databases_sql, [PG_DB])
  databases = databases_query.lines

  databases.each do |database|
    rows = sql.query(objects_sql, [database])
    if rows.methods.include?(:output) # Handle connection disabled on database
      objects = rows.lines

      objects.each do |obj|
        schema, object, type = obj.split('|')
        relacl_sql = "SELECT pg_catalog.array_to_string(c.relacl, E','), "\
          "n.nspname, c.relname, c.relkind FROM pg_catalog.pg_class c "\
          "LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "\
          "WHERE n.nspname = '#{schema}' AND c.relname = '#{object}' "\
          "AND c.relkind = '#{type}';"

        describe sql.query(relacl_sql, [database]) do
          its('output') { should match object_acl_regex }
        end
        # TODO: Add test for column acl
      end
    end
  end

  describe postgres_hba_conf(PG_HBA_CONF_FILE).where { type == 'local' } do
    its('user.uniq') { should cmp PG_OWNER }
    its('auth_method.uniq') { should_not cmp 'trust'}
  end

  describe.one do
    describe postgres_hba_conf(PG_HBA_CONF_FILE).where { database == 'replication' } do
      its('type.uniq') { should cmp 'host' }
      its('address.uniq.sort') { should cmp PG_REPLICAS.sort }
      its('user.uniq') { should cmp 'replication' }
      its('auth_method.uniq') { should cmp 'md5' }
    end
    describe postgres_hba_conf(PG_HBA_CONF_FILE).where { database == 'replication' } do
      its('type.uniq') { should cmp 'hostssl' }
      its('address.uniq.sort') { should cmp PG_REPLICAS.sort }
      its('user.uniq') { should cmp 'replication' }
      its('auth_method.uniq') { should cmp 'md5' }
    end
  end
  describe postgres_hba_conf(PG_HBA_CONF_FILE).where { type == 'host' } do
    its('auth_method.uniq') { should cmp 'md5'}
  end
end
