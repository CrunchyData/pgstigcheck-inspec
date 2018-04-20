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

control "V-72991" do

  title "PostgreSQL must use NSA-approved cryptography to protect classified
information in accordance with the data owners requirements."
  desc  "Use of weak or untested encryption algorithms undermines the purposes of
utilizing encryption to protect data. The application must implement cryptographic
modules adhering to the higher standards approved by the federal government since
this provides assurance they have been tested and validated.

It is the responsibility of the data owner to assess the cryptography requirements
in light of applicable federal laws, Executive Orders, directives, policies,
regulations, and standards.

NSA-approved cryptography for classified networks is hardware based. This
requirement addresses the compatibility of PostgreSQL with the encryption devices."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000416-DB-000380"
  tag "gid": "V-72991"
  tag "rid": "SV-87643r1_rule"
  tag "stig_id": "PGS9-00-008100"
  tag "cci": ["CCI-002450"]
  tag "nist": ["SC-13", "Rev_4"]

  tag "check": "If PostgreSQL is deployed in an unclassified environment, this is
not applicable (NA).

If PostgreSQL is not using NSA-approved cryptography to protect classified
information in accordance with applicable federal laws, Executive Orders,
directives, policies, regulations, and standards, this is a finding.

To check if PostgreSQL is configured to use SSL, as the database administrator
(shown here as \"postgres\"), run the following SQL:

$ sudo su - postgres
$ psql -c \"SHOW ssl\"

If SSL is off, this is a finding.

Consult network administration staff to determine whether the server is protected by
NSA-approved encrypting devices. If not, this a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable.
See supplementary content APPENDIX-F for instructions on configuring PGDATA.

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

For more information on configuring PostgreSQL to use SSL, see supplementary content
APPENDIX-G.

Deploy NSA-approved encrypting devices to protect the server on the network."

  sql = postgres_session(PG_DBA, PG_DBA_PASSWORD, PG_HOST)

  describe sql.query('SHOW ssl;', [PG_DB]) do
    its('output') { should match /on|true/i }
  end
end
