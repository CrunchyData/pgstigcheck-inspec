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

PG_DBA = attribute(
  'pg_dba',
  description: 'The postgres DBA user to access the database',
  default: 'stig_dba'
)

PG_DBA_PASSWORD = attribute(
  'pg_dba_password',
  description: "password for the postgres dba password",
  default: 'stigD@1234#')

PG_DB = attribute(
  'pg_db',
  description: 'the default postgres database',
  default: 'stig_test_db'
)

PG_PORT = attribute(
  'pg_port',
  description: "The port that the postgres server is listening to",
  default: '5432'
)

PG_HOST = attribute(
  'pg_host',
  description: "Hostname or ip allow to connect to the database",
  default: '127.0.0.1'
)

only_if do
  command('psql').exist?
end

control "V-72885" do
  title "The audit information produced by PostgreSQL must be protected from
  unauthorized deletion."
  desc  "If audit data were to become compromised, then competent forensic
  analysis and discovery of the true source of potentially malicious system
  activity is impossible to achieve.
  To ensure the veracity of audit data, the information system and/or the
  application must protect audit information from unauthorized deletion. This
  requirement can be achieved through multiple methods which will depend upon
  system architecture and design.
  Some commonly employed methods include: ensuring log files enjoy the proper
  file system permissions utilizing file system protections; restricting access;
  and backing up log data to ensure log data is retained.
  Applications providing a user interface to audit data will leverage user
  permissions and roles identifying the user accessing the data and the
  corresponding rights the user enjoys in order make access decisions regarding
  the deletion of audit data.
  Audit information includes all information (e.g., audit records, audit
  settings, and audit reports) needed to successfully audit information system
  activity.
  Deletion of database audit data could mask the theft of, or the unauthorized
  modification of, sensitive data stored in the database."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000120-DB-000061"
  tag "gid": "V-72885"
  tag "rid": "SV-87537r1_rule"
  tag "stig_id": "PGS9-00-002300"
  tag "cci": "CCI-000164"
  tag "nist": ["AU-9", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.
  Review locations of audit logs, both internal to the database and database
  audit logs located at the operating system level.
  Verify there are appropriate controls and permissions to protect the audit
  information from unauthorized modification.
  #### stderr Logging
  If the PostgreSQL server is configured to use stderr for logging, the logs
  will be owned by the database administrator (shown here as \"postgres\") with
  a default permissions level of 0600. The permissions can be configured in
  postgresql.conf.
  To check the permissions for log files in postgresql.conf, as the database
  administrator (shown here as \"postgres\"), run the following command:

  $ sudo su - postgres
  $ grep \"log_file_mode\" ${PGDATA?}/postgresql.conf

  If the permissions are not 0600, this is a finding.

  Next, navigate to where the logs are stored. This can be found by running the
  following command against postgresql.conf as the database administrator (shown
  here as \"postgres\"):

  $ sudo su - postgres
  $ grep \"log_directory\" ${PGDATA?}/postgresql.conf

  With the log directory identified, as the database administrator (shown here
  as \"postgres\"), list the permissions of the logs:

  $ sudo su - postgres
  $ ls -la ${PGDATA?}/pg_log

  If logs are not owned by the database administrator (shown here as
  \"postgres\") and are not the same permissions as configured in
  postgresql.conf, this is a finding.
  
  #### syslog Logging
  If the PostgreSQL server is configured to use syslog for logging, consult the
  organizations syslog setting for permissions and ownership of logs."

  tag "fix": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.
  To ensure that logging is enabled, review supplementary content APPENDIX-C for
  instructions on enabling logging.
  By default, the database administrator account is not accessible by
  unauthorized users. Only grant access to this account if required for operations.
  #### stderr Logging
  By default, the database administrator account is not accessible by
  unauthorized users. Only grant access to this account if required for
  operations.
  With stderr logging enabled, as the database administrator (shown here as
  \"postgres\"), set the following parameter in postgresql.conf:
  $ sudo su - postgres
  $ vi ${PGDATA?}/postgresql.conf
  log_file_mode = 0600
  #### syslog Logging
  Check with the organization to see how syslog facilities are defined in their
  organization."

  # @todo also need to test that error logging is enabled (where?) or test if log
  # outputs to stderr? the pg_log directory should be 0700.
  # @todo we need to decide how we are going to test for error logging and what the
  # default setup will be per the CM
  # @todo this test is dupe of V-72847.

    describe directory(PG_LOG_DIR) do
      it { should be_directory }
      it { should be_owned_by PG_OWNER }
      it { should be_grouped_into PG_OWNER }
      its('mode') { should  cmp '0700' }
    end

    describe command("find #{PG_LOG_DIR} -type f -perm 600 ! -perm 600 | wc -l") do
      its('stdout.strip') { should eq '0' }
    end

end
