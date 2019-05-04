pg_dba = attribute('pg_dba')
pg_dba_password = attribute('pg_dba_password')
pg_db = attribute('pg_db')
pg_host = attribute('pg_host')

control 'V-72987' do
  title "PostgreSQL must produce audit records containing sufficient information
  to establish the identity of any user/subject or process associated with the
  event."
  desc  "Information system auditing capability is critical for accurate
  forensic analysis. Without information that establishes the identity of the
  subjects (i.e., users or processes acting on behalf of users) associated with
  the events, security personnel cannot determine responsibility for the
  potentially harmful event.
  Identifiers (if authenticated or otherwise known) include, but are not limited
  to, user database tables, primary key values, user names, or process identifiers.
  1) Linux's sudo and su feature enables a user (with sufficient OS privileges)
  to emulate another user, and it is the identity of the emulated user that is
  seen by PostgreSQL and logged in the audit trail. Therefore, care must be
  taken (outside of Postgresql) to restrict sudo/su to the minimum set of users
  necessary.
  2) PostgreSQL's SET ROLE feature enables a user (with sufficient PostgreSQL
  privileges) to emulate another user running statements under the permission
  set of the emulated user. In this case, it is the emulating user's identity,
  and not that of the emulated user, that gets logged in the audit trail.
  While this is definitely better than the other way around, ideally, both
  identities would be recorded."
  tag "check": "Check PostgreSQL settings and existing audit records to verify a
  user name associated with the event is being captured and stored with the
  audit records. If audit records exist without specific user information, this
  is a finding.
  First, as the database administrator (shown here as \"postgres\"), verify the
  current setting of log_line_prefix by running the following SQL:
  $ sudo su - postgres
  $ psql -c \"SHOW log_line_prefix\"
  If log_line_prefix does not contain %m, %u, %d, %p, %r, %a, this is a finding."
  tag "fix": "Logging must be enabled in order to capture the identity of any
  user/subject or process associated with an event. To ensure that logging is
  enabled, review supplementary content APPENDIX-C for instructions on enabling
  logging.
  To enable username, database name, process ID, remote host/port and
  application name in logging, as the database administrator (shown here as
  \"postgres\"), edit the following in postgresql.conf:
  $ sudo su - postgres
  $ vi ${PGDATA?}/postgresql.conf
  log_line_prefix = '< %m %u %d %p %r %a >'
  Now, as the system administrator, reload the server with the new configuration:
  # SYSTEMD SERVER ONLY
  $ sudo systemctl reload postgresql-9.5
  # INITD SERVER ONLY
  $ sudo service postgresql-9.5 reload"

  sql = postgres_session(pg_dba, pg_dba_password, pg_host)

  log_line_prefix_escapes = %w{%m %u %d %p %r %a}

  log_line_prefix_escapes.each do |escape|
    describe sql.query('SHOW log_line_prefix;', [pg_db]) do
      its('output') { should include escape }
    end
  end
end
