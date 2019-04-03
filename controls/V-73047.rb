# encoding: utf-8

pg_dba = attribute('pg_dba')
pg_dba_password = attribute('pg_dba_password')
pg_db = attribute('pg_db')
pg_host = attribute('pg_host')

control "V-73047" do
  title "PostgreSQL must maintain the authenticity of communications sessions by
guarding against man-in-the-middle attacks that guess at Session ID values."
  desc  "One class of man-in-the-middle, or session hijacking, attack involves the
adversary guessing at valid session identifiers based on patterns in identifiers
already known.

The preferred technique for thwarting guesses at Session IDs is the generation of
unique session identifiers using a FIPS 140-2 approved random number generator.

However, it is recognized that available PostgreSQL products do not all implement
the preferred technique yet may have other protections against session hijacking.
Therefore, other techniques are acceptable, provided they are demonstrated to be
effective."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000224-DB-000384"
  tag "gid": "V-73047"
  tag "rid": "SV-87699r1_rule"
  tag "stig_id": "PGS9-00-011400"
  tag "cci": ["CCI-001188"]
  tag "nist": ["SC-23 (3)", "Rev_4"]
  tag "check": "To check if PostgreSQL is configured to use ssl, as the database
administrator (shown here as \"postgres\"), run the following SQL:

$ sudo su - postgres
$ psql -c \"SHOW ssl\"

If this is not set to `on`, this is a finding."

  tag "fix": "To configure PostgreSQL to use SSL, as a database owner (shown here as
\"postgres\"), edit postgresql.conf:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameter:

ssl = on

Now, as the system administrator, reload the server with the new configuration:

# SYSTEMD SERVER ONLY
$ sudo systemctl reload postgresql-9.5

# INITD SERVER ONLY
$ sudo service postgresql-9.5 reload

For more information on configuring PostgreSQL to use SSL, see supplementary content
APPENDIX-G.

For further SSL configurations, see the official documentation:
https://www.postgresql.org/docs/current/static/ssl-tcp.html"

  sql = postgres_session(pg_dba, pg_dba_password, pg_host)

  describe sql.query('SHOW ssl;', [pg_db]) do
    its('output') { should match /on|true/i }
  end
end
