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

control "V-72981" do
  title "PostgreSQL must maintain the confidentiality and integrity of
  information during preparation for transmission."
  desc  "Information can be either unintentionally or maliciously disclosed or
  modified during preparation for transmission, including, for example, during
  aggregation, at protocol transformation points, and during packing/unpacking.
  These unauthorized disclosures or modifications compromise the confidentiality
  or integrity of the information.
  Use of this requirement will be limited to situations where the data owner has
  a strict requirement for ensuring data integrity and confidentiality is
  maintained at every step of the data transfer and handling process.
  When transmitting data, PostgreSQL, associated applications, and
  infrastructure must leverage transmission protection mechanisms.
  PostgreSQL uses OpenSSL SSLv23_method() in fe-secure-openssl.c, while the name
  is misleading, this function enables only TLS encryption methods, not SSL.
  See OpenSSL: https://mta.openssl.org/pipermail/openssl-dev/2015-May/001449.htm."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000441-DB-000378"
  tag "gid": "V-72981"
  tag "rid": "SV-87633r1_rule"
  tag "stig_id": "PGS9-00-007200"
  tag "cci": ["CCI-002420"]
  tag "nist": ["SC-8 (2)", "Rev_4"]
  tag "check": "If the data owner does not have a strict requirement for ensuring
  data integrity and confidentiality is maintained at every step of the data
  transfer and handling process, this is not a finding.
  As the database administrator (shown here as \"postgres\"), verify SSL is
  enabled by running the following SQL:
  $ sudo su - postgres
  $ psql -c \"SHOW ssl\"
  If SSL is not enabled, this is a finding.
  If PostgreSQL does not employ protective measures against unauthorized
  disclosure and modification during preparation for transmission, this is a
  finding."
  tag "fix": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.
  Implement protective measures against unauthorized disclosure and modification
  during preparation for transmission.
  To configure PostgreSQL to use SSL, as a database administrator (shown here as
  \"postgres\"), edit postgresql.conf:
  $ sudo su - postgres
  $ vi ${PGDATA?}/postgresql.conf
  Add the following parameter:
  ssl = on
  Now, as the system administrator, reload the server with the new configuration:
  # SYSTEMD SERVER ONLY
  $ sudo systemctl reload postgresql-PG_VER
  # INITD SERVER ONLY
  $ sudo service postgresql-PG_VER reload
  For more information on configuring PostgreSQL to use SSL, see supplementary
  content APPENDIX-G."

  sql = postgres_session(PG_DBA, PG_DBA_PASSWORD, PG_HOST)

  describe sql.query('SHOW ssl;', [PG_DB]) do
    its('output') { should match /on|true/i }
  end
end
