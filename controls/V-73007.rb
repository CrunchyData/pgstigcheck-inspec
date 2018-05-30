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
  description: "the list of approaved postgresql extentions that the database may enable",
  default: ['pgcrypto'])

control "V-73007" do
  title "Unused database components, PostgreSQL software, and database objects must be removed."
  desc  "Information systems are capable of providing a wide variety of functions
  and services. Some of the functions and services, provided by default, may not be
  necessary to support essential organizational operations (e.g., key missions,
  functions).

  It is detrimental for software products to provide, or install by default,
  functionality exceeding requirements or mission objectives.

  PostgreSQLs must adhere to the principles of least functionality by providing only
  essential capabilities."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000141-DB-000091"
  tag "gid": "V-73007"
  tag "rid": "SV-87659r1_rule"
  tag "stig_id": "PGS9-00-008900"
  tag "cci": "CCI-000381"
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "check": "To get a list of all extensions installed, use the following commands:
  $ sudo su - postgres
  $ psql -c \"select * from pg_extension where extname != 'plpgsql';\"\"

  If any extensions exist that are not approved, this is a finding."

  tag "fix": "To remove extensions, use the following commands:
  $ sudo su - postgres
  $ psql -c \"DROP EXTENSION <extension_name>\"

  Note: it is recommended that plpgsql not be removed."

# @todo executed the SELECT statement in psql, got no output, psql not hardended? fix the stdout code, as needed.

dbs = nil
db = nil

if !("#{PG_DB}".to_s.empty?)
  db = ["#{PG_DB}"]
  dbs = db.map { |x| "-d #{x}" }.join(' ')
end

# @todo need SSP data to compare that no extensions are present that are not approved?

  describe.one do
    APPROVED_EXT.each do |extention|
      describe command("PGPASSWORD='#{PG_DBA_PASSWORD}' psql -U #{PG_DBA} -d #{PG_DB} -h #{PG_HOST} -A -t -c \"SELECT * from pg_extension where extname != 'plpgsql';\" | cut -d'|' -f 1") do
        its('stdout.strip') { should match extention }
      end
    end
    describe command("PGPASSWORD='#{PG_DBA_PASSWORD}' psql -U #{PG_DBA} -d #{PG_DB} -h #{PG_HOST} -A -t -c \"SELECT * from pg_extension where extname != 'plpgsql';\"") do
      its('stdout.strip') { should be "" }
    end
  end
end
