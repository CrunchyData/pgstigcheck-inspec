# encoding: utf-8

pg_dba = attribute('pg_dba')
pg_dba_password = attribute('pg_dba_password')
pg_db = attribute('pg_db')
pg_host = attribute('pg_host')

control "V-73123" do
  title "PostgreSQL must produce audit records containing sufficient information
  to establish where the events occurred."
  desc  "Information system auditing capability is critical for accurate forensic
  analysis. Without establishing where events occurred, it is impossible to
  establish, correlate, and investigate the events relating to an incident.
  In order to compile an accurate risk assessment and provide forensic analysis,
  it is essential for security personnel to know where events occurred, such as
  application components, modules, session identifiers, filenames, host names,
  and functionality.
  Associating information about where the event occurred within the application
  provides a means of investigating an attack; recognizing resource utilization
  or capacity thresholds; or identifying an improperly configured application."
  impact 0.5
  tag "severity": "medium"

  tag "gtitle": "SRG-APP-000097-DB-000041"
  tag "gid": "V-73123"
  tag "rid": "SV-87775r1_rule"
  tag "stig_id": "PGS9-00-007100"
  tag "cci": ["CCI-000132"]
  tag "nist": ["AU-3", "Rev_4"]

  tag "check": "Note: The following instructions use the PGDATA environment variable.
  See supplementary content APPENDIX-F for instructions on configuring PGDATA.
  First, as the database administrator (shown here as \"postgres\"), check the
  current log_line_prefix setting by running the following SQL:

  $ sudo su - postgres
  $ psql -c \"SHOW log_line_prefix\"

  If log_line_prefix does not contain %m %u %d %s, this is a finding."

  tag "fix": "Note: The following instructions use the PGDATA environment variable.
  See supplementary content APPENDIX-F for instructions on configuring PGDATA.
  To check that logging is enabled, review supplementary content APPENDIX-C for
  instructions on enabling logging.
  First edit the postgresql.conf file as the database administrator (shown here
  as \"postgres\"):

  $ sudo su - postgres
  $ vi ${PGDATA?}/postgresql.conf

  Extra parameters can be added to the setting log_line_prefix to log application
  related information:

  # %a = application name
  # %u = user name
  # %d = database name
  # %r = remote host and port
  # %p = process ID
  # %m = timestamp with milliseconds
  # %i = command tag
  # %s = session startup
  # %e = SQL state

  For example:
  log_line_prefix = '<%m %a %u %d %r %p %i %e %s>’

  Now, as the system administrator, reload the server with the new configuration:

  # SYSTEMD SERVER ONLY
  $ sudo systemctl reload postgresql-9.5
  # INITD SERVER ONLY
  $ sudo service postgresql-9.5 reload"

  sql = postgres_session(pg_dba, pg_dba_password, pg_host)

  log_line_prefix_escapes = %w(%m %u %d %s)

  log_line_prefix_escapes.each do |escape|
    describe sql.query('SHOW log_line_prefix;', [pg_db]) do
      its('output') { should include escape }
    end
  end
end
