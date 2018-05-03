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

control "V-73019" do
  title "PostgreSQL must protect against a user falsely repudiating having performed
organization-defined actions."
  desc  "Non-repudiation of actions taken is required in order to maintain data
integrity. Examples of particular actions taken by individuals include creating
information, sending a message, approving information (e.g., indicating concurrence
or signing a contract), and receiving a message.

Non-repudiation protects against later claims by a user of not having created,
modified, or deleted a particular data item or collection of data in the database.

In designing a database, the organization must define the types of data and the user
actions that must be protected from repudiation. The implementation must then
include building audit features into the application data tables, and configuring
PostgreSQL' audit tools to capture the necessary audit trail. Design and
implementation also must ensure that applications pass individual user
identification to PostgreSQL, even where the application connects to PostgreSQL with
a standard, shared account."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000080-DB-000063"
  tag "gid": "V-73019"
  tag "rid": "SV-87671r1_rule"
  tag "stig_id": "PGS9-00-009700"
  tag "cci": ["CCI-000166"]
  tag "nist": ["AU-10", "Rev_4"]
  tag "check": "First, as the database administrator, review the current
log_line_prefix settings by running the following SQL:

$ sudo su - postgres
$ psql -c \"SHOW log_line_prefix\"

If log_line_prefix does not contain at least '< %m %a %u %d %r %p %m >', this is a
finding.

Next, review the current shared_preload_libraries settings by running the following
SQL:

$ psql -c \"SHOW shared_preload_libraries\"

If shared_preload_libraries does not contain \"pgaudit\", this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable.
See supplementary content APPENDIX-F for instructions on configuring PGDATA.

Configure the database to supply additional auditing information to protect against
a user falsely repudiating having performed organization-defined actions.

Using pgaudit PostgreSQL can be configured to audit these requests. See
supplementary content APPENDIX-B for documentation on installing pgaudit.

To ensure that logging is enabled, review supplementary content APPENDIX-C for
instructions on enabling logging.

Modify the configuration of audit logs to include details identifying the individual
user:

First, as the database administrator (shown here as \"postgres\"), edit
postgresql.conf:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Extra parameters can be added to the setting log_line_prefix to identify the user:

log_line_prefix = '< %m %a %u %d %r %p %m >'

Now, as the system administrator, reload the server with the new configuration:

# SYSTEMD SERVER ONLY
$ sudo systemctl reload postgresql-${PG_VER}

# INITD SERVER ONLY
$ sudo service postgresql-${PG_VER} reload

Use accounts assigned to individual users. Where the application connects to
PostgreSQL using a standard, shared account, ensure that it also captures the
individual user identification and passes it to PostgreSQL."

  sql = postgres_session(PG_DBA, PG_DBA_PASSWORD, PG_HOST)

  log_line_prefix_escapes = %w(%m %u %d %p %r %a)

  log_line_prefix_escapes.each do |escape|
    describe sql.query('SHOW log_line_prefix;', [PG_DB]) do
      its('output') { should include escape }
    end
  end

  describe sql.query('SHOW shared_preload_libraries;', [PG_DB]) do
    its('output') { should include 'pgaudit' }
  end
end
