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

control "V-73033" do
  title "PostgreSQL must produce audit records containing sufficient information to
establish what type of events occurred."
  desc  "Information system auditing capability is critical for accurate forensic
analysis. Without establishing what type of event occurred, it would be difficult to
establish, correlate, and investigate the events relating to an incident or identify
those responsible for one.

Audit record content that may be necessary to satisfy the requirement of this policy
includes, for example, time stamps, user/process identifiers, event descriptions,
success/fail indications, filenames involved, and access control or flow control
rules invoked.

Associating event types with detected events in the application and audit logs
provides a means of investigating an attack; recognizing resource utilization or
capacity thresholds; or identifying an improperly configured application.

Database software is capable of a range of actions on data stored within the
database. It is important, for accurate forensic analysis, to know exactly what
actions were performed. This requires specific information regarding the event type
an audit record is referring to. If event type information is not recorded and
stored with the audit record, the record itself is of very limited use."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000095-DB-000039"
  tag "gid": "V-73033"
  tag "rid": "SV-87685r1_rule"
  tag "stig_id": "PGS9-00-010400"
  tag "cci": ["CCI-000130"]
  tag "nist": ["AU-3", "Rev_4"]
  tag "check": "As the database administrator (shown here as \"postgres\"), verify
the current log_line_prefix setting in postgresql.conf:

$ sudo su - postgres
$ psql -c \"SHOW log_line_prefix\"

Verify that the current settings are appropriate for the organization.

The following is what is possible for logged information:

# %a = application name
# %u = user name
# %d = database name
# %r = remote host and port
# %h = remote host
# %p = process ID
# %t = timestamp without milliseconds
# %m = timestamp with milliseconds
# %i = command tag
# %e = SQL state
# %c = session ID
# %l = session line number
# %s = session start timestamp
# %v = virtual transaction ID
# %x = transaction ID (0 if none)
# %q = stop here in non-session
# processes

If the audit record does not log events required by the organization, this is a
finding.

Next, verify the current settings of log_connections and log_disconnections by
running the following SQL:

$ psql -c \"SHOW log_connections\"
$ psql -c \"SHOW log_disconnections\"

If both settings are off, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable.
See supplementary content APPENDIX-F for instructions on configuring PGDATA.

To ensure that logging is enabled, review supplementary content APPENDIX-C for
instructions on enabling logging.

If logging is enabled the following configurations must be made to log connections,
date/time, username and session identifier.

First, edit the postgresql.conf file as a privileged user:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Edit the following parameters based on the organization's needs (minimum
requirements are as follows):

log_connections = on
log_disconnections = on
log_line_prefix = '< %m %u %d %c: >'

Now, as the system administrator, reload the server with the new configuration:

# SYSTEMD SERVER ONLY
$ sudo systemctl reload postgresql-9.5

# INITD SERVER ONLY
$ sudo service postgresql-9.5 reload"

  sql = postgres_session(PG_DBA, PG_DBA_PASSWORD, PG_HOST)

  log_line_prefix_escapes = %w(%m %u %d %s)
  log_line_prefix_escapes.each do |escape|
    describe sql.query('SHOW log_line_prefix;', [PG_DB]) do
      its('output') { should include escape }
    end
  end

  describe sql.query('SHOW log_connections;', [PG_DB]) do
    its('output') { should_not match /off|false/i }
  end

  describe sql.query('SHOW log_disconnections;', [PG_DB]) do
    its('output') { should_not match /off|false/i }
  end
end
