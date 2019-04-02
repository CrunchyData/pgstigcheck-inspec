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

control "V-72915" do
  title "The audit information produced by PostgreSQL must be protected from
  unauthorized read access."
  desc  "If audit data were to become compromised, then competent forensic
  analysis and discovery of the true source of potentially malicious system
  activity is difficult, if not impossible, to achieve. In addition, access to
  audit records provides information an attacker could potentially use to his or
  her advantage.
  To ensure the veracity of audit data, the information system and/or the
  application must protect audit information from any and all unauthorized
  access. This includes read, write, copy, etc.
  This requirement can be achieved through multiple methods which will depend
  upon system architecture and design. Some commonly employed methods include
  ensuring log files enjoy the proper file system permissions utilizing file
  system protections and limiting log data location.
  Additionally, applications with user interfaces to audit records should not
  allow for the unfettered manipulation of or access to those records via the
  application. If the application provides access to the audit data, the
  application becomes accountable for ensuring that audit information is
  protected from unauthorized access.
  Audit information includes all information (e.g., audit records, audit
  settings, and audit reports) needed to successfully audit information system
  activity."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000118-DB-000059"
  tag "gid": "V-72915"
  tag "rid": "SV-87567r1_rule"
  tag "stig_id": "PGS9-00-004200"
  tag "cci": "CCI-000162"
  tag "nist": ["AU-9", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.
  Review locations of audit logs, both internal to the database and database
  audit logs located at the operating system level.
  Verify there are appropriate controls and permissions to protect the audit
  information from unauthorized access.
  #### syslog Logging
  If PostgreSQL is configured to use syslog for logging, consult the
  organizations location and permissions for syslog log files.
  #### stderr Logging
  As the database administrator (shown here as \"postgres\"), check the current
  log_file_mode configuration by running the following:
  Note: Consult the organization's documentation on acceptable log privileges
  $ sudo su - postgres
  $ psql -c \"SHOW log_file_mode\"
  If log_file_mode is not 600, this is a finding.
  Next, check the current log_destination path by running the following SQL:
  Note: This is relative to PGDATA.
  $ psql -c \"SHOW log_destination\"
  Next, verify the log files have the set configurations in the log_destination:
  Note: Use location of logs from log_directory.
  $ ls -l ${PGDATA?}/pg_log/
  total 32
  -rw-------. 1 postgres postgres 0 Apr 8 00:00 postgresql-Fri.log
  -rw-------. 1 postgres postgres 8288 Apr 11 17:36 postgresql-Mon.log
  -rw-------. 1 postgres postgres 0 Apr 9 00:00 postgresql-Sat.log
  -rw-------. 1 postgres postgres 0 Apr 10 00:00 postgresql-Sun.log
  -rw-------. 1 postgres postgres 16212 Apr 7 17:05 postgresql-Thu.log
  -rw-------. 1 postgres postgres 1130 Apr 6 17:56 postgresql-Wed.log
  If logs with 600 permissions do not exist in log_destination, this is a
    finding."
  tag "fix": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.
  To ensure that logging is enabled, review supplementary content APPENDIX-C for
  instructions on enabling logging.
  #### syslog Logging
  If PostgreSQL is configured to use syslog for logging, consult the
  organizations location and permissions for syslog log files.
  #### stderr Logging
  If PostgreSQL is configured to use stderr for logging, permissions of the log
  files can be set in postgresql.conf.
  As the database administrator (shown here as \"postgres\"), edit the following
  settings of logs in the postgresql.conf file:
  Note: Consult the organization's documentation on acceptable log privileges
  $ sudo su - postgres
  $ vi ${PGDATA?}/postgresql.conf
  log_file_mode = 0600
  Next, as the system administrator, reload the server with the new configuration:
  # SYSTEMD SERVER ONLY
  $ sudo systemctl reload postgresql-9.5
  # INITD SERVER ONLY
  $ sudo service postgresql-9.5 reload"

  describe command("PGPASSWORD='#{PG_DBA_PASSWORD}' psql -U #{PG_DBA} -d #{PG_DB} -h #{PG_HOST} -A -t -c \"SHOW log_file_mode\"") do
   its('stdout') { should match /0600/ }
  end

  command("find #{PG_AUDIT_LOG_DIR} -type f").stdout.split.each do |logfile|
  describe file(logfile) do
    its('mode') { should cmp '0600' }
  end
  end
end
