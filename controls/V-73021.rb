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

control "V-73021" do
  title "PostgreSQL must provide the capability for authorized users to capture,
record, and log all content related to a user session."
  desc  "Without the capability to capture, record, and log all content related to a
user session, investigations into suspicious user activity would be hampered.

Typically, this PostgreSQL capability would be used in conjunction with comparable
monitoring of a user's online session, involving other software components such as
operating systems, web servers and front-end user applications. The current
requirement, however, deals specifically with PostgreSQL."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000093-DB-000052"
  tag "gid": "V-73021"
  tag "rid": "SV-87673r1_rule"
  tag "stig_id": "PGS9-00-009800"
  tag "cci": "CCI-001462"
  tag "nist": ["AU-14 (2)", "Rev_4"]
  tag "check": "First, as the database administrator (shown here as \"postgres\"),
verify pgaudit is installed by running the following SQL:

$ sudo su - postgres
$ psql -c \"SHOW shared_preload_libraries\"

If shared_preload_libraries does not contain pgaudit, this is a finding.

Next, to verify connections and disconnections are logged, run the following SQL:

$ psql -c \"SHOW log_connections\"
$ psql -c \"SHOW log_disconnections\"

If log_connections and log_disconnections are off, this is a finding.

Now, to verify that pgaudit is configured to log, run the following SQL:

$ psql -c \"SHOW pgaudit.log\"

If pgaudit.log does not contain ddl, role, read, write, this is a finding."
  tag "fix": "Configure the database capture, record, and log all content related to
a user session.

To ensure that logging is enabled, review supplementary content APPENDIX-C for
instructions on enabling logging.

With logging enabled, as the database administrator (shown here as \"postgres\"),
enable log_connections and log_disconnections:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf
log_connections = on
log_disconnections = on

Using pgaudit PostgreSQL can be configured to audit activity. See supplementary
content APPENDIX-B for documentation on installing pgaudit.

With pgaudit installed, as a database administrator (shown here as \"postgres\"),
enable which objects required for auditing a user's session:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf
pgaudit.log = 'write, ddl, role, read, function';
pgaudit.log_relation = on;

Now, as the system administrator, reload the server with the new configuration:

# SYSTEMD SERVER ONLY
$ sudo systemctl reload postgresql-9.5

# INITD SERVER ONLY
$ sudo service postgresql-9.5 reload"

  sql = postgres_session(PG_DBA, PG_DBA_PASSWORD, PG_HOST)

  describe sql.query('SHOW shared_preload_libraries;', [PG_DB]) do
    its('output') { should include 'pgaudit' }
  end

  pgaudit_types = %w(ddl read role write)

  pgaudit_types.each do |type|
    describe sql.query('SHOW pgaudit.log;', [PG_DB]) do
      its('output') { should include type }
    end
  end

  describe sql.query('SHOW log_connections;', [PG_DB]) do
    its('output') { should_not match /off|false/i }
  end

  describe sql.query('SHOW log_disconnections;', [PG_DB]) do
    its('output') { should_not match /off|false/i }
  end
end
