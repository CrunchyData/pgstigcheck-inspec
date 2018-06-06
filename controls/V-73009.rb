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
PG_CONF_FILE= attribute(
  'pg_conf_file',
  description: 'define path for the postgresql configuration file',
  default: '/var/lib/pgsql/9.5/data/postgresql.conf'
)

LOG_LINE_PREFIX = attribute(
  'log_line_prefix',
  description: "The required log line elemets per the organizational guidance",
  default: ['%m','%u','%d','%s']
)

PG_HOST = attribute(
  'pg_host',
  description: "The host address that the admin user is allowed to connect from",
  default: '127.0.0.1'
)

LOGIN_USER = attribute(
  'login_user',
  description: "The admin user accout",
  default: "vagrant"
)

PG_DBA = attribute(
  'pg_dba',
  description: 'The postgres DBA user to access the database',
  default: 'stig_dba')

PG_DBA_PASSWORD = attribute(
  'pg_dba_password',
  description: "password for the postgres dba password",
  default: 'stigD@1234#')

PG_DB = attribute(
    'pg_db',
    description: "the database to run the command from",
    default: 'stig_test_db')

APPROVED_EXT = attribute(
  'approved_ext',
  description: "the list of approaved postgresql extensions that the database may enable",
  default: ['pgcrypto']
)

control "V-73009" do
  title "Access to external executables must be disabled or restricted."
  desc  "Information systems are capable of providing a wide variety of functions
and services. Some of the functions and services, provided by default, may not be
necessary to support essential organizational operations (e.g., key missions,
functions).

It is detrimental for applications to provide, or install by default, functionality
exceeding requirements or mission objectives.

Applications must adhere to the principles of least functionality by providing only
essential capabilities.

PostgreSQLs may spawn additional external processes to execute procedures that are
defined in PostgreSQL but stored in external host files (external procedures). The
spawned process used to execute the external procedure may operate within a
different OS security context than PostgreSQL and provide unauthorized access to the
host system."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000141-DB-000093"
  tag "gid": "V-73009"
  tag "rid": "SV-87661r1_rule"
  tag "stig_id": "PGS9-00-009100"
  tag "cci": "CCI-000381"
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "check": "PostgreSQL’s Copy command can interact with the underlying OS. Only
superuser has access to this command.

First, as the database administrator (shown here as \"postgres\"), run the following
SQL to list all roles and their privileges:

$ sudo su - postgres
$ psql -x -c \"\\du\"

If any role has \"superuser\" that should not, this is a finding.

It is possible for an extension to contain code that could access external
executables via SQL. To list all installed extensions, as the database administrator
(shown here as \"postgres\"), run the following SQL:

$ sudo su - postgres
$ psql -x -c \"SELECT * FROM pg_available_extensions WHERE installed_version IS NOT
NULL\"

If any extensions are installed that are not approved, this is a finding."
  tag "fix": "To remove superuser from a role, as the database administrator (shown
here as \"postgres\"), run the following SQL:

$ sudo su - postgres
$ psql -c \"ALTER ROLE <role-name> WITH NOSUPERUSER\"

To remove extensions from PostgreSQL, as the database administrator (shown here as
\"postgres\"), run the following SQL:

$ sudo su - postgres
$ psql -c \"DROP EXTENSION extension_name\""

dbs = nil
db = nil

if !("#{PG_DB}".to_s.empty?)
  db = ["#{PG_DB}"]
  dbs = db.map { |x| "-d #{x}" }.join(' ')
end

# @todo fix stdout, SSP roles should states which ones SHOULD have superuser, others should not? need datafile to test against the DB.

  describe command("PGPASSWORD='#{PG_DBA_PASSWORD}' psql -U #{PG_DBA} -d #{PG_DB} -h #{PG_HOST} -A -t -c \"select * from pg_shadow where usename <> 'postgres' and usesuper = 't';") do
    its('stdout.strip') { should match '' }
  end

# @todo how do I check to see if any extensions are installed that are not approved?  fix stdout value?

  describe.one do
    APPROVED_EXT.each do |extension|
      describe command("PGPASSWORD='#{PG_DBA_PASSWORD}' psql -U #{PG_DBA} -d #{PG_DB} -h #{PG_HOST} -A -t -c \"SELECT * FROM pg_available_extensions WHERE installed_version IS NOT NULL\"") do
        its('stdout.strip') { should match extension }
      end
    end
  end
end  
#describe command("PGPASSWORD='#{PG_DBA_PASSWORD}' psql -U #{PG_DBA} -d #{PG_DB} -h #{PG_HOST} -A -t -c \"SELECT * FROM pg_available_extensions WHERE installed_version IS NOT NULL\"") do
#    its('stdout.strip') { should match 'error' }
#  end
#end
