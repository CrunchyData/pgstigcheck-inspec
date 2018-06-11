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

control "V-72927" do
  title "PostgreSQL must generate audit records when unsuccessful attempts to
  modify security objects occur."
  desc  "Changes in the database objects (tables, views, procedures, functions)
  that record and control permissions, privileges, and roles granted to users
  and roles must be tracked. Without an audit trail, unauthorized changes to the
  security subsystem could go undetected. The database could be severely
  compromised or rendered inoperative.
  To aid in diagnosis, it is necessary to keep track of failed attempts in
  addition to the successful ones."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000496-DB-000335"
  tag "gid": "V-72927"
  tag "rid": "SV-87579r1_rule"
  tag "stig_id": "PGS9-00-004800"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.
  As the database administrator (shown here as \"postgres\"), create a test role
  by running the following SQL:
  $ sudo su - postgres
  $ psql -c \"CREATE ROLE bob\"
  Next, to test if audit records are generated from unsuccessful attempts at
  modifying security objects, run the following SQL:
  $ sudo su - postgres
  $ psql -c \"SET ROLE bob; UPDATE pg_authid SET rolsuper = 't' WHERE
  rolname = 'bob';\"
  Next, as the database administrator (shown here as \"postgres\"), verify that
  the denials were logged:
  $ sudo su - postgres
  $ cat ${PGDATA?}/pg_log/<latest_log>
  < 2016-03-17 10:34:00.017 EDT bob 56eabf52.b62 postgres: >ERROR: permission
  denied for relation pg_authid
  < 2016-03-17 10:34:00.017 EDT bob 56eabf52.b62 postgres: >STATEMENT:
  UPDATE pg_authid SET rolsuper = 't' WHERE rolname = 'bob';
  If denials are not logged, this is a finding."
  tag "fix": "Configure PostgreSQL to produce audit records when unsuccessful
  attempts to modify security objects occur.
  Unsuccessful attempts to modifying security objects can be logged if logging
  is enabled. To ensure that logging is enabled, review supplementary content A
  PPENDIX-C for instructions on enabling logging."
  
  describe command("PGPASSWORD='#{PG_DBA_PASSWORD}' psql -U #{PG_DBA} -d #{PG_DB} -h #{PG_HOST} -A -t -c \"CREATE ROLE permdeniedtest; SET ROLE permdeniedtest; UPDATE pg_authid SET rolsuper = 't' WHERE rolname = 'permdeniedtest'; DROP ROLE IF EXISTS permdeniedtest;\"") do
    its('stdout') { should match // }
  end

  describe command("cat `find #{PG_AUDIT_LOG_DIR} -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d\" \"` | grep \"permission denied for relation pg_authid\"") do
    its('stdout') { should match /^.*permission denied for relation pg_authid.*$/ }
  end

end
