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
  'pg_ver',
  description: "The version of the postgres process",
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

PG_MAX_CONNECTIONS = attribute(
  'pg_max_connections',
  description: 'The maximum number of connections a user can have open at one time',
)

control "V-72863" do
  title "PostgreSQL must limit the number of concurrent sessions to an
  organization-defined number per user for all accounts and/or account types."
  desc  "Database management includes the ability to control the number of users
  and user sessions utilizing PostgreSQL. Unlimited concurrent connections to
  PostgreSQL could allow a successful Denial of Service (DoS) attack by
  exhausting connection resources; and a system can also fail or be degraded by
  an overload of legitimate users. Limiting the number of concurrent sessions
  per user is helpful in reducing these risks.
  This requirement addresses concurrent session control for a single account.
  It does not address concurrent sessions by a single user via multiple system
  accounts; and it does not deal with the total number of sessions across all
  accounts.
  The capability to limit the number of concurrent sessions per user must be
  configured in or added to PostgreSQL (for example, by use of a logon trigger),
  when this is technically feasible. Note that it is not sufficient to limit
  sessions via a web server or application server alone, because legitimate
  users and adversaries can potentially connect to PostgreSQL by other means.
  The organization will need to define the maximum number of concurrent sessions
  by account type, by account, or a combination thereof. In deciding on the
  appropriate number, it is important to consider the work requirements of the
  various types of users. For example, 2 might be an acceptable limit for
  general users accessing the database via an application; but 10 might be too
  few for a database administrator using a database management GUI tool, where
  each query tab and navigation pane may count as a separate session.
  (Sessions may also be referred to as connections or logons, which for the
  purposes of this requirement are synonyms.."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000001-DB-000031"
  tag "gid": "V-72863"
  tag "rid": "SV-87515r1_rule"
  tag "stig_id": "PGS9-00-001200"
  tag "cci": ["CCI-000054"]
  tag "nist": ["AC-10", "Rev_4"]
  tag "check": 'To check the total amount of connections allowed by the database,
                as the database administrator, run the following SQL:
                $ sudo su - postgres
                $ psql -c "SHOW max_connections"
                If the total amount of connections is greater than documented by
                an organization, this is a finding.
                To check the amount of connections allowed for each role, as the
                database administrator, run the following SQL:
                $ sudo su - postgres
                $ psql -c "SELECT rolname, rolconnlimit from pg_authid"
                If any roles have more connections configured than documented,
                this is a finding. A value of -1 indicates Unlimited, this is a
                finding.'

  tag "fix": "Note: The following instructions use the PGDATA environment variable.
      See supplementary content APPENDIX-F for instructions on
      configuring PGDATA.

      To configure the maximum amount of connections allowed to the
      database, as the database administrator (shown here as \"postgres\")
      change the following in postgresql.conf

      (the value 10 is an example; set the value to suit local conditions):

      $ sudo su - postgres
      $ vi ${PGDATA?}/postgresql.conf
      max_connections = 10

      Next, restart the database:

      # SYSTEMD SERVER ONLY
      $ sudo systemctl restart postgresql-PG_VER

      # INITD SERVER ONLY
      $ sudo service postgresql-PG_VER restart

      To limit the amount of connections allowed by a specific role,
      as the database administrator, run the following SQL:

      $ psql -c \"ALTER ROLE <rolname> CONNECTION LIMIT 1\";"

  sql = postgres_session(PG_DBA, PG_DBA_PASSWORD, PG_HOST)

  describe sql.query('SHOW max_connections;', [PG_DB]) do
    its('output') { should be <= PG_MAX_CONNECTIONS }
  end

  describe sql.query('SELECT rolname, rolconnlimit from pg_authid;', [PG_DB]) do
    its('output') { should_not include '-1' }
  end
end
