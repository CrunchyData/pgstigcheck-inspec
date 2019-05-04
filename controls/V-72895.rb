pg_dba = attribute('pg_dba')
pg_dba_password = attribute('pg_dba_password')
pg_db = attribute('pg_db')
pg_host = attribute('pg_host')

control 'V-72895' do
  title "PostgreSQL must maintain the confidentiality and integrity of
  information during reception."
  desc "Information can be either unintentionally or maliciously disclosed or
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

  tag "gtitle": 'SRG-APP-000442-DB-000379'
  tag "gid": 'V-72895'
  tag "rid": 'SV-87547r1_rule'
  tag "stig_id": 'PGS9-00-003000'
  tag "cci": ['CCI-002422']
  tag "nist": ['SC-8 (2)', 'Rev_4']
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

  sql = postgres_session(pg_dba, pg_dba_password, pg_host)

  describe sql.query('SHOW ssl;', [pg_db]) do
    its('output') { should_not match /off|false/i }
  end
end
