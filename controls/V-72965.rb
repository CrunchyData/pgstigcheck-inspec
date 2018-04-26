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

PG_VER = attribute(
  'pg_ver',
  description: "The version of the postgres process",
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

control "V-72965" do
  title "PostgreSQL must generate audit records when privileges/permissions are
  modified."
  desc  "Changes in the permissions, privileges, and roles granted to users and
  roles must be tracked. Without an audit trail, unauthorized elevation or
  restriction of privileges could go undetected. Elevated privileges give users
  access to information and functionality that they should not have; restricted
  privileges wrongly deny access to authorized users.
  In an SQL environment, modifying permissions is typically done via the GRANT
  and REVOKE commands."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000495-DB-000328"
  tag "gid": "V-72965"
  tag "rid": "SV-87617r1_rule"
  tag "stig_id": "PGS9-00-006400"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "First, as the database administrator, verify pgaudit is enabled
  by running the following SQL:
  $ sudo su - postgres
  $ psql -c \"SHOW shared_preload_libraries\"
  If the output does not contain pgaudit, this is a finding.
  Next, verify that role is enabled:
  $ psql -c \"SHOW pgaudit.log\"
  If the output does not contain role, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment v
  ariable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.
  Using pgaudit PostgreSQL can be configured to audit these requests. See
  supplementary content APPENDIX-B for documentation on installing pgaudit.
  With pgaudit installed the following configurations can be made:
  $ sudo su - postgres
  $ vi ${PGDATA?}/postgresql.conf
  Add the following parameters (or edit existing parameters):
  pgaudit.log='role'
  Now, as the system administrator, reload the server with the new
  configuration:
  # SYSTEMD SERVER ONLY
  $ sudo systemctl reload postgresql-PG_VER
  # INITD SERVER ONLY
  $ sudo service postgresql-PG_VER reload"

  sql = postgres_session(PG_DBA, PG_DBA_PASSWORD, PG_HOST)

  describe sql.query('SHOW shared_preload_libraries;', [PG_DB]) do
    its('output') { should include 'pgaudit' }
  end

  pgaudit_types = ['role']

  pgaudit_types.each do |type|
    describe sql.query('SHOW pgaudit.log;', [PG_DB]) do
      its('output') { should include type }
    end
  end
end
