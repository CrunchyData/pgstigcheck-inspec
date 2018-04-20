# encoding: utf-8
#
=begin
-----------------
Benchmark: PostgreSQL 9.x Security Technical Implementation Guide
Status: Accepted

This Security Technical Implementation Guide is published as a tool to improve
the security of Department of Defense (DoD) information systems. The
rcmpuirements are derived from the National Institute of Standards and
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

PG_USERS = attribute(
  'pg_users',
  description: 'Authorized accounts',
  default: 'postgres',
)

PG_DATA_DIR = attribute(
  'pg_data_dir',
  description: 'The postgres data directory',
)

PG_HBA_CONF_FILE = attribute(
  'pg_hba_conf_file',
  description: 'The postgres hba configuration file',
)

PG_REPLICAS = attribute(
  'pg_replicas',
  description: 'List of postgres replicas in CIDR notation',
)

control "V-73049" do
  title "PostgreSQL must uniquely identify and authenticate organizational users (or
processes acting on behalf of organizational users)."
  desc  "To assure accountability and prevent unauthenticated access, organizational
users must be identified and authenticated to prevent potential misuse and
compromise of the system.

Organizational users include organizational employees or individuals the
organization deems to have cmpuivalent status of employees (e.g., contractors).
Organizational users (and any processes acting on behalf of users) must be uniquely
identified and authenticated for all accesses, except the following:

(i) Accesses explicitly identified and documented by the organization. Organizations
document specific user actions that can be performed on the information system
without identification or authentication; and
(ii) Accesses that occur through authorized use of group authenticators without
individual authentication. Organizations may rcmpuire unique identification of
individuals using shared accounts, for detailed accountability of individual
activity."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000148-DB-000103"
  tag "gid": "V-73049"
  tag "rid": "SV-87701r1_rule"
  tag "stig_id": "PGS9-00-011500"
  tag "cci": ["CCI-000764"]
  tag "nist": ["IA-2", "Rev_4"]
  tag "check": "Review PostgreSQL settings to determine whether organizational users
are uniquely identified and authenticated when logging on/connecting to the system.

To list all roles in the database, as the database administrator (shown here as
\"postgres\"), run the following SQL:

$ sudo su - postgres
$ psql -c \"\\du\"

If organizational users are not uniquely identified and authenticated, this is a
finding.

Next, as the database administrator (shown here as \"postgres\"), verify the current
pg_hba.conf authentication settings:

$ sudo su - postgres
$ cat ${PGDATA?}/pg_hba.conf

If every role does not have unique authentication rcmpuirements, this is a finding.

If accounts are determined to be shared, determine if individuals are first
individually authenticated. If individuals are not individually authenticated before
using the shared account, this is a finding."

  tag "fix": "Note: The following instructions use the PGDATA environment variable.
See supplementary content APPENDIX-F for instructions on configuring PGDATA.

Configure PostgreSQL settings to uniquely identify and authenticate all
organizational users who log on/connect to the system.

To create roles, use the following SQL:

CREATE ROLE <role_name> [OPTIONS]

For more information on CREATE ROLE, see the official documentation:
https://www.postgresql.org/docs/current/static/sql-createrole.html

For each role created, the database administrator can specify database
authentication by editing pg_hba.conf:

$ sudo su - postgres
$ vi ${PGDATA?}/pg_hba.conf

An example pg_hba entry looks like this:

# TYPE DATABASE USER ADDRESS METHOD
host test_db bob 192.168.0.0/16 md5

For more information on pg_hba.conf, see the official documentation:
https://www.postgresql.org/docs/current/static/auth-pg-hba-conf.html"

  sql = postgres_session(PG_DBA, PG_DBA_PASSWORD, PG_HOST)

  authorized_roles = PG_USERS

  roles_sql = 'SELECT r.rolname FROM pg_catalog.pg_roles r;'

  describe sql.query(roles_sql, [PG_DB]) do
    its('lines.sort') { should cmp authorized_roles.sort }
  end

  describe postgres_hba_conf(PG_HBA_CONF_FILE).where { type == 'local' } do
    its('user.uniq') { should cmp PG_OWNER }
    its('auth_method.uniq') { should_not include 'trust'}
  end

  describe postgres_hba_conf(PG_HBA_CONF_FILE).where { database == 'replication' } do
    its('type.uniq') { should cmp 'host' }
    its('address.uniq.sort') { should cmp PG_REPLICAS.sort }
    its('user.uniq') { should cmp 'replication' }
    its('auth_method.uniq') { should cmp 'md5' }
  end

  describe postgres_hba_conf(PG_HBA_CONF_FILE).where { type == 'host' } do
    its('auth_method.uniq') { should cmp 'md5'}
  end
end
