pg_owner = input('pg_owner')

pg_dba = input('pg_dba')

pg_dba_password = input('pg_dba_password')

pg_db = input('pg_db')

pg_host = input('pg_host')

pg_users = input('pg_users')

pg_data_dir = input('pg_data_dir')

pg_hba_conf_file = input('pg_hba_conf_file')

pg_replicas = input('pg_replicas')

control "V-73049" do
  title "PostgreSQL must uniquely identify and authenticate organizational
  users (or processes acting on behalf of organizational users)."
  desc  "To assure accountability and prevent unauthenticated access,
  organizational users must be identified and authenticated to prevent potential
  misuse and compromise of the system.

  Organizational users include organizational employees or individuals the
  organization deems to have equivalent status of employees (e.g., contractors).
  Organizational users (and any processes acting on behalf of users) must be
  uniquely identified and authenticated for all accesses, except the following:

      (i) Accesses explicitly identified and documented by the organization.
  Organizations document specific user actions that can be performed on the
  information system without identification or authentication; and
      (ii) Accesses that occur through authorized use of group authenticators
  without individual authentication. Organizations may require unique
  identification of individuals using shared accounts, for detailed
  accountability of individual activity."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000148-DB-000103"
  tag "gid": "V-73049"
  tag "rid": "SV-87701r1_rule"
  tag "stig_id": "PGS9-00-011500"
  tag "fix_id": "F-79495r1_fix"
  tag "cci": ["CCI-000764"]
  tag "nist": ["IA-2", "Rev_4"]
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
  desc "check", "Review PostgreSQL settings to determine whether organizational
  users are uniquely identified and authenticated when logging on/connecting to
  the system.

  To list all roles in the database, as the database administrator (shown here as
  \"postgres\"), run the following SQL:

  $ sudo su - postgres
  $ psql -c \"\\du\"

  If organizational users are not uniquely identified and authenticated, this is
  a finding.

  Next, as the database administrator (shown here as \"postgres\"), verify the
  current pg_hba.conf authentication settings:

  $ sudo su - postgres
  $ cat ${PGDATA?}/pg_hba.conf

  If every role does not have unique authentication requirements, this is a
  finding.

  If accounts are determined to be shared, determine if individuals are first
  individually authenticated. If individuals are not individually authenticated
  before using the shared account, this is a finding."
  
  desc "fix", "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.

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

  sql = postgres_session(pg_dba, pg_dba_password, pg_host)

  authorized_roles = pg_users

  roles_sql = 'SELECT r.rolname FROM pg_catalog.pg_roles r;'

  describe sql.query(roles_sql, [pg_db]) do
    its('lines.sort') { should cmp authorized_roles.sort }
  end

  describe postgres_hba_conf(pg_hba_conf_file).where { type == 'local' } do
    its('user.uniq') { should cmp pg_owner }
    its('auth_method.uniq') { should_not include 'trust'}
  end

  describe postgres_hba_conf(pg_hba_conf_file).where { database == 'replication' } do
    its('type.uniq') { should cmp 'host' }
    its('address.uniq.sort') { should cmp pg_replicas.sort }
    its('user.uniq') { should cmp 'replication' }
    its('auth_method.uniq') { should cmp 'md5' }
  end

  describe postgres_hba_conf(pg_hba_conf_file).where { type == 'host' } do
    its('auth_method.uniq') { should cmp 'md5'}
  end
end
