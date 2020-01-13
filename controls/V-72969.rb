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

control "V-72969" do
  title "PostgreSQL must generate audit records when unsuccessful attempts to
  execute privileged activities or other system-level access occur."
  desc  "Without tracking privileged activity, it would be difficult to
  establish, correlate, and investigate the events relating to an incident or
  identify those responsible for one.
  System documentation should include a definition of the functionality
  considered privileged.

  A privileged function in this context is any operation that modifies the
  structure of the database, its built-in logic, or its security settings. This
  would include all Data Definition Language (DDL) statements and all
  security-related statements. In an SQL environment, it encompasses, but is not
  necessarily limited to:

  CREATE
  ALTER
  DROP
  GRANT
  REVOKE

  Note: That it is particularly important to audit, and tightly control, any
  action that weakens the implementation of this requirement itself, since the
  objective is to have a complete audit trail of all administrative activity.
  To aid in diagnosis, it is necessary to keep track of failed attempts in
  addition to the successful ones."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000504-DB-000355"
  tag "gid": "V-72969"
  tag "rid": "SV-87621r1_rule"
  tag "stig_id": "PGS9-00-006500"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]

  tag "check": "As the database administrator (shown here as \"postgres\"),
  create the role bob by running the following SQL:
    $ sudo su - postgres
    $ psql -c \"CREATE ROLE bob\"

  Next, change the current role to bob and attempt to execute privileged activity:
    $ psql -c \"CREATE ROLE stig_test SUPERUSER\"
    $ psql -c \"CREATE ROLE stig_test CREATEDB\"
    $ psql -c \"CREATE ROLE stig_test CREATEROLE\"
    $ psql -c \"CREATE ROLE stig_test CREATEUSER\"

  Now, as the database administrator (shown here as \"postgres\"), verify that
  an audit event was produced (use the latest log):
    $ sudo su - postgres
    $ cat ${PGDATA?}/pg_log/<latest_log>

  < 2016-02-23 20:16:32.396 EST postgres 56cfa74f.79eb postgres: >ERROR: must be
  superuser to create superusers
  < 2016-02-23 20:16:32.396 EST postgres 56cfa74f.79eb postgres: >STATEMENT:
  CREATE ROLE stig_test SUPERUSER;
  < 2016-02-23 20:16:48.725 EST postgres 56cfa74f.79eb postgres: >ERROR:
  permission denied to create role
  < 2016-02-23 20:16:48.725 EST postgres 56cfa74f.79eb postgres: >STATEMENT:
  CREATE ROLE stig_test CREATEDB;
  < 2016-02-23 20:16:54.365 EST postgres 56cfa74f.79eb postgres: >ERROR: p
  ermission denied to create role
  < 2016-02-23 20:16:54.365 EST postgres 56cfa74f.79eb postgres: >STATEMENT:
  CREATE ROLE stig_test CREATEROLE;
  < 2016-02-23 20:17:05.949 EST postgres 56cfa74f.79eb postgres: >ERROR: must be
  superuser to create superusers
  < 2016-02-23 20:17:05.949 EST postgres 56cfa74f.79eb postgres: >STATEMENT:
  CREATE ROLE stig_test CREATEUSER;
  If audit records are not produced, this is a finding."

  tag "fix": "Configure PostgreSQL to produce audit records when unsuccessful
  attempts to execute privileged SQL.
  All denials are logged by default if logging is enabled. To ensure that
  logging is enabled, review supplementary content APPENDIX-C for instructions
  on enabling logging."

  describe command("PGPASSWORD='#{PG_DBA_PASSWORD}' psql -U #{PG_DBA} -d #{PG_DB} -h #{PG_HOST} -A -t -c \"CREATE ROLE fooaudit; SET ROLE fooaudit; CREATE ROLE fooauditbad SUPERUSER;\"") do
    its('stdout') { should match // }
  end

  describe command("cat `find #{PG_AUDIT_LOG_DIR} -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d\" \"` | grep \"must be superuser to create superusers\"") do
    its('stdout') { should match /^.*must be superuser to create superusers.*$/ }
  end

  describe command("PGPASSWORD='#{PG_DBA_PASSWORD}' psql -U #{PG_DBA} -d #{PG_DB} -h #{PG_HOST} -A -t -c \"CREATE ROLE fooauditbad CREATEDB; CREATE ROLE fooauditbad CREATEROLE\"") do
    its('stdout') { should match // }
  end

  describe command("cat `find #{PG_AUDIT_LOG_DIR} -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d\" \"` | grep \"permission denied to create role\"") do
    its('stdout') { should match /^.*permission denied to create role.*$/ }
  end

end
