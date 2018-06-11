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

PG_OWNER = attribute(
  'pg_owner',
  description: "The system user of the postgres process",
  default: 'postgres'
)

PG_GROUP = attribute(
  'pg_group',
  description: "The system user group of the postgres process",
  default: 'postgres'
)

PG_DATA_DIR = attribute(
  'pg_data_dir',
  description: "the postgres data_dir",
  default: postgres.data_dir
)

control "V-73059" do
  title "Access to database files must be limited to relevant processes and to
authorized, administrative users."
  desc  "Applications, including PostgreSQLs, must prevent unauthorized and
unintended information transfer via shared system resources. Permitting only DBMS
processes and authorized, administrative users to have access to the files where the
database resides helps ensure that those files are not shared inappropriately and
are not open to backdoor access and manipulation."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000243-DB-000374"
  tag "gid": "V-73059"
  tag "rid": "SV-87711r1_rule"
  tag "stig_id": "PGS9-00-012000"
  tag "cci": "CCI-001090"
  tag "nist": ["SC-4", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment
variable. See supplementary content APPENDIX-F for instructions on configuring
PGDATA.

Review the permissions granted to users by the operating system/file system on the
database files, database log files and database backup files.

To verify that all files are owned by the database administrator and have the
correct permissions, run the following as the database administrator (shown here as
\"postgres\"):

$ sudo su - postgres
$ ls -lR ${PGDATA?}

If any files are not owned by the database administrator or allow anyone but the
database administrator to read/write/execute, this is a finding.

If any user/role who is not an authorized system administrator with a need-to-know
or database administrator with a need-to-know, or a system account for running
PostgreSQL processes, is permitted to read/view any of these files, this is a
finding."

  tag "fix": "Note: The following instructions use the PGDATA environment variable.
See supplementary content APPENDIX-F for instructions on configuring PGDATA.

Configure the permissions granted by the operating system/file system on the
database files, database log files, and database backup files so that only relevant
system accounts and authorized system administrators and database administrators
with a need to know are permitted to read/view these files.

Any files (for example: extra configuration files) created in PGDATA must be owned
by the database administrator, with only owner permissions to read, write, and
execute."

  describe command("find PG_DATA_DIR ! -user PG_OWNER ! -group PG_GROUP -type f -readable -writable | wc -l") do
    its('stdout.strip') { should eq '0' }
  end
end
