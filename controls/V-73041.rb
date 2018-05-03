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

control "V-73041" do
  title "PostgreSQL must produce audit records containing time stamps to establish
when the events occurred."
  desc  "Information system auditing capability is critical for accurate forensic
analysis. Without establishing when events occurred, it is impossible to establish,
correlate, and investigate the events relating to an incident.

In order to compile an accurate risk assessment and provide forensic analysis, it is
essential for security personnel to know the date and time when events occurred.

Associating the date and time with detected events in the application and audit logs
provides a means of investigating an attack; recognizing resource utilization or
capacity thresholds; or identifying an improperly configured application.

Database software is capable of a range of actions on data stored within the
database. It is important, for accurate forensic analysis, to know exactly when
specific actions were performed. This requires the date and time an audit record is
referring to. If date and time information is not recorded and stored with the audit
record, the record itself is of very limited use."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000096-DB-000040"
  tag "gid": "V-73041"
  tag "rid": "SV-87693r1_rule"
  tag "stig_id": "PGS9-00-011100"
  tag "cci": ["CCI-000131"]
  tag "nist": ["AU-3", "Rev_4"]
  tag "check": "As the database administrator (usually postgres), run the following
SQL:

$ sudo su - postgres
$ psql -c \"SHOW log_line_prefix\"

If the query result does not contain \"%m\", this is a finding."
  tag "fix": "Logging must be enabled in order to capture timestamps. To ensure that
logging is enabled, review supplementary content APPENDIX-C for instructions on
enabling logging.

If logging is enabled the following configurations must be made to log events with
timestamps:

First, as the database administrator (shown here as \"postgres\"), edit
postgresql.conf:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add %m to log_line_prefix to enable timestamps with milliseconds:

log_line_prefix = '< %m >'

Now, as the system administrator, reload the server with the new configuration:

# SYSTEMD SERVER ONLY
$ sudo systemctl reload postgresql-${PG_VER}

# INITD SERVER ONLY
$ sudo service postgresql-${PG_VER} reload"

  sql = postgres_session(PG_DBA, PG_DBA_PASSWORD, PG_HOST)

  log_line_prefix_escapes = ['%m']

  log_line_prefix_escapes.each do |escape|
    describe sql.query('SHOW log_line_prefix;', [PG_DB]) do
      its('output') { should include escape }
    end
  end
end
