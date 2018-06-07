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
  'pg_version',
  description: "The version of the PostgreSQL process which is being inspected (tested)",
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

PG_LOG_DIR = attribute(
  'pg_log_dir',
  description: 'define path for the postgreql log directory',
  default: '/var/lib/pgsql/9.5/data/pg_log'
)

PG_AUDIT_LOG_DIR = attribute(
  'pg_audit_log_dir',
  description: 'define path for the postgreql audit log directory',
  default: '/var/lib/pgsql/9.5/data/pg_log'
)

control "V-72929" do
  title "PostgreSQL must generate audit records when privileges/permissions are
  added."
  desc  "Changes in the permissions, privileges, and roles granted to users and
  roles must be tracked. Without an audit trail, unauthorized elevation or
  restriction of privileges could go undetected. Elevated privileges give users
  access to information and functionality that they should not have; restricted
  privileges wrongly deny access to authorized users.
  In an SQL environment, adding permissions is typically done via the GRANT
  command, or, in the negative, the REVOKE command."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000495-DB-000326"
  tag "gid": "V-72929"
  tag "rid": "SV-87581r1_rule"
  tag "stig_id": "PGS9-00-004900"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.
  First, as the database administrator (shown here as \"postgres\"), create a
  role by running the following SQL:
  Change the privileges of another user:
  $ sudo su - postgres
  $ psql -c \"CREATE ROLE bob\"
  Next, GRANT then REVOKE privileges from the role:
  $ psql -c \"GRANT CONNECT ON DATABASE postgres TO bob\"
  $ psql -c \"REVOKE CONNECT ON DATABASE postgres FROM bob\"
  postgres=# REVOKE CONNECT ON DATABASE postgres FROM bob;
  REVOKE
  postgres=# GRANT CONNECT ON DATABASE postgres TO bob;
  GRANT
  Now, as the database administrator (shown here as \"postgres\"), verify the
  events were logged:
  $ sudo su - postgres
  $ cat ${PGDATA?}/pg_log/<latest_log>
< 2016-07-13 16:25:21.103 EDT postgres
  postgres LOG: > AUDIT: SESSION,1,1,ROLE,GRANT,,,GRANT CONNECT ON DATABASE
  postgres TO bob,<none>
  < 2016-07-13 16:25:25.520 EDT postgres postgres LOG: > AUDIT:
  SESSION,1,1,ROLE,REVOKE,,,REVOKE CONNECT ON DATABASE postgres FROM bob,<none>
  If the above steps cannot verify that audit records are produced when
  privileges/permissions/role memberships are added, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.
  Using pgaudit PostgreSQL can be configured to audit these requests. See
  supplementary content APPENDIX-B for documentation on installing pgaudit.
  With pgaudit installed the following configurations can be made:
  $ sudo su - postgres
  $ vi ${PGDATA?}/postgresql.conf
  Add the following parameters (or edit existing parameters):
  pgaudit.log = 'role'
  Now, as the system administrator, reload the server with the new configuration:
  # SYSTEMD SERVER ONLY
  $ sudo systemctl reload postgresql-9.5
  # INITD SERVER ONLY
  $ sudo service postgresql-9.5 reload"

  describe command("PGPASSWORD='#{PG_DBA_PASSWORD}' psql -U #{PG_DBA} -d #{PG_DB} -h #{PG_HOST} -A -t -c \"CREATE ROLE fooaudit; GRANT CONNECT ON DATABASE postgres TO fooaudit; REVOKE CONNECT ON DATABASE postgres FROM fooaudit;\"") do
    its('stdout') { should match // }
  end

  describe command("cat `find #{PG_AUDIT_LOG_DIR} -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d\" \"` | grep \"GRANT CONNECT ON DATABASE postgres TO\"") do
    its('stdout') { should match /^.*fooaudit.*$/ }
  end

  describe command("cat `find #{PG_AUDIT_LOG_DIR} -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d\" \"` | grep \"REVOKE CONNECT ON DATABASE postgres FROM\"") do
    its('stdout') { should match /^.*fooaudit.*$/ }
  end

end
