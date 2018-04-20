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

control "V-72895" do
  title "PostgreSQL must maintain the confidentiality and integrity of
  information during reception."
  desc  "Information can be either unintentionally or maliciously disclosed or
  modified during reception, including, for example, during aggregation, at
  protocol transformation points, and during packing/unpacking. These
  unauthorized disclosures or modifications compromise the confidentiality or
  integrity of the information.
  This requirement applies only to those applications that are either
  distributed or can allow access to data nonlocally. Use of this requirement
  will be limited to situations where the data owner has a strict requirement
  for ensuring data integrity and confidentiality is maintained at every step of
  the data transfer and handling process.
  When receiving data, PostgreSQL, associated applications, and infrastructure
  must leverage protection mechanisms.
  PostgreSQL uses OpenSSL SSLv23_method() in fe-secure-openssl.c; while the name
  is misleading, this function enables only TLS encryption methods, not SSL.
  See OpenSSL: https://mta.openssl.org/pipermail/openssl-dev/2015-May/001449.htm."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000442-DB-000379"
  tag "gid": "V-72895"
  tag "rid": "SV-87547r1_rule"
  tag "stig_id": "PGS9-00-003000"
  tag "cci": ["CCI-002422"]
  tag "nist": ["SC-8 (2)", "Rev_4"]
  tag "check": "If the data owner does not have a strict requirement for
  ensuring data integrity and confidentiality is maintained at every step of the
  data transfer and handling process, this is not a finding.

  As the database administrator (shown here as \"postgres\"), verify SSL is
  enabled in postgresql.conf by:

  First, open the postgresql.conf file and ensure the ssl paramater is set to on:

  $ vi <pg_conf_dir>/postgresql.conf
  $ ssl = 'on'

  is set and not commented out with a '#'.

  Second, run the following SQL:

  $ sudo su - postgres
  $ psql -c \"SHOW ssl\"

  If SSL is off, this is a finding.

  If PostgreSQL, associated applications, and infrastructure do not employ
  protective measures against unauthorized disclosure and modification during
  reception, this is a finding."

  tag "fix": "Implement protective measures against unauthorized disclosure and
  modification during reception.
  To configure PostgreSQL to use SSL, see supplementary content APPENDIX-G for
  instructions on enabling SSL."

  sql = postgres_session(PG_DBA, PG_DBA_PASSWORD, PG_HOST)

  describe sql.query('SHOW ssl;', [PG_DB]) do
    its('output') { should_not match /off|false/i }
  end
end
