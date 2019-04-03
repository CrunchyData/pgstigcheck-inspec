# encoding: utf-8

pg_dba = attribute('pg_dba')
pg_dba_password = attribute('pg_dba_password')
pg_db = attribute('pg_db')
pg_host = attribute('pg_host')

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
  $ sudo systemctl reload postgresql-9.5
  # INITD SERVER ONLY
  $ sudo service postgresql-9.5 reload
  For more information on configuring PostgreSQL to use SSL, see supplementary
  content APPENDIX-G."

  sql = postgres_session(pg_dba, pg_dba_password, pg_host)

  describe sql.query('SHOW ssl;', [pg_db]) do
    its('output') { should match /on|true/i }
  end
end
