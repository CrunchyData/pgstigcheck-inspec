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

PG_LOG_DIR = attribute(
'pg_log_dir',
description: 'define path for the postgreql log directory',
default: '/var/lib/pgsql/9.5/data/pg_log')

PG_OWNER = attribute(
  'pg_owner',
  description: "The system user of the postgres process",
  default: 'postgres'
)

only_if do
  command('psql').exist?
end

  control "V-72847" do
  title "The audit information produced by PostgreSQL must be protected from
  unauthorized modification."
  desc  "If audit data were to become compromised, then competent forensic
  analysis and discovery of the true source of potentially malicious system
  activity is impossible to achieve. To ensure the veracity of audit data
  the information system and/or the application must protect audit information
  from unauthorized modification. This requirement can be achieved through
  multiple methods that will depend upon system architecture and design. Some
  commonly employed methods include ensuring log files enjoy the proper file
  system permissions and limiting log data locations. Applications providing
  a user interface to audit data will leverage user permissions and roles
  identifying the user accessing the data and the corresponding rights that
  the user enjoys in order to make access decisions regarding the modification
  of audit data.  Audit information includes all information (e.g., audit
  records, audit settings, and audit reports) needed to successfully audit
  information system activity. Modification of database audit data could mask
  the theft of, or the unauthorized modification of, sensitive data stored in
  the database."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000119-DB-000060"
  tag "gid": "V-72847"
  tag "rid": "SV-87499r1_rule"
  tag "stig_id": "PGS9-00-000400"
  tag "cci": "CCI-000163"
  tag "nist": ["AU-9", "Rev_4"]

  tag "check": "Review locations of audit logs, both internal to the database
  and database audit logs located at the operating system level.  Verify there
  are appropriate controls and permissions to protect the audit information from
  unauthorized modification.

  Note: The following instructions use the PGDATA environment variable. See
  supplementary content APPENDIX-F for instructions on configuring PGDATA.

  #### stderr Logging  If the PostgreSQL server is configured to use stderr for
  logging, the logs will be owned by the database owner (usually postgres user)
  with a default permissions level of 0600. The permissions can be configured in
  postgresql.conf.

  To check the permissions for log files in postgresql.conf, as the database
  owner (shown here as \"postgres\"), run the following command:

  $ sudo su - postgres
  $ grep \"log_file_mode\" ${PGDATA?}/postgresql.conf

  If the permissions are not 0600, this is a finding.

  Next, navigate to where the logs are stored. This can be found by running the
  following command against postgresql.conf as the database owner (shown here as
  \"postgres\"):

  $ sudo su - postgres
  $ grep \"log_directory\" ${PGDATA?}/postgresql.conf

  With the log directory identified, as the database owner (shown here as 
\"postgres\"),
  list the permissions of the logs:

  $ sudo su - postgres
  $ ls -la ${PGDATA?}/pg_log

  If logs are not owned by the database owner (shown here as \"postgres\") and
  are not the same permissions as configured in postgresql.conf, this is a
  finding.

  #### syslog Logging
  If the PostgreSQL server is configured to use syslog for logging, consult
  the organizations syslog setting for permissions and ownership of logs."

  tag "fix": "To ensure that logging is enabled, review supplementary content
  APPENDIX-C for instructions on enabling logging.  Note: The following
  instructions use the PGDATA environment variable. See supplementary content
  APPENDIX-F for instructions on configuring PGDATA.
  #### stderr Logging
  With stderr logging enabled, as the database owner (shown here as
  \"postgres\"), set the following parameter in postgresql.conf:

  $ vi ${PGDATA?}/postgresql.conf
  log_file_mode = 0600

  To change the owner and permissions of the log files, run the following:

  $ chown postgres:postgres ${PGDATA?}/<log directory name>
  $ chmod 0700 ${PGDATA?}/<log directory name>
  $ chmod 600 ${PGDATA?}/<log directory name>/*.log

  #### syslog Logging
  If PostgreSQL is configured to use syslog for logging, the log files must be
  configured to be owned by root with 0600 permissions.

  $ chown root:root <log directory name>/<log_filename>
  $ chmod 0700 <log directory name>
  $ chmod 0600 <log directory name>/*.log"


# @todo also need to test that error logging is enabled (where?) or test if log
# outputs to stderr? the pg_log directory should be 0700.
# @todo we need to decide how we are going to test for error logging and what the
# default setup will be per the CM

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
