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

PG_DATA_DIR = attribute(
  'pg_data_dir',
  description: 'The postgres data directory',
)

PG_HBA_CONF_FILE = attribute(
  'pg_hba_conf_file',
  description: 'The postgres hba configuration file',
)

control "V-72979" do
  title "PostgreSQL, when utilizing PKI-based authentication, must validate
  certificates by performing RFC 5280-compliant certification path validation."
  desc  "The DoD standard for authentication is DoD-approved PKI certificates.
  A certificate’s certification path is the path from the end entity certificate
  to a trusted root certification authority (CA). Certification path validation
  is necessary for a relying party to make an informed decision regarding
  acceptance of an end entity certificate. Certification path validation
  includes checks such as certificate issuer trust, time validity and revocation
  status for each certificate in the certification path. Revocation status
  information for CA and subject certificates in a certification path is
  commonly provided via certificate revocation lists (CRLs) or online
  certificate status protocol (OCSP) responses.
  Database Management Systems that do not validate certificates by performing
  RFC 5280-compliant certification path validation are in danger of accepting
  certificates that are invalid and/or counterfeit. This could allow unauthorized
  access to the database."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000175-DB-000067"
  tag "gid": "V-72979"
  tag "rid": "SV-87631r1_rule"
  tag "stig_id": "PGS9-00-007000"
  tag "cci": ["CCI-000185"]
  tag "nist": ["IA-5 (2) (a)", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.
  To verify that a CRL file exists, as the database administrator (shown here as
  \"postgres\"), run the following:
  $ sudo su - postgres
  $ psql -c \"SHOW ssl_crl_file\" If this is not set to a CRL file, this is a finding.
  Next verify the existence of the CRL file by checking the directory set in
  postgresql.conf in the ssl_crl_file parameter from above:
  Note: If no directory is specified, then the CRL file should be located in the
  same directory as postgresql.conf (PGDATA).
  If the CRL file does not exist, this is a finding.
  Next, verify that hostssl entries in pg_hba.conf have \"cert\" and
  \"clientcert=1\" enabled:
  $ sudo su - postgres
  $ grep hostssl ${PGDATA?}/pg_hba.conf
  If hostssl entries does not contain cert or clientcert=1, this is a finding.
  If certificates are not being validated by performing RFC 5280-compliant
  certification path validation, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.
  To configure PostgreSQL to use SSL, see supplementary content APPENDIX-G.
  To generate a Certificate Revocation List, see the official Red Hat
  Documentation:
  https://access.redhat.com/documentation/en-US/Red_Hat_Update_Infrastructure/
  2.1/html/Administration_Guide/chap-Red_Hat_Update_Infrastructure-
  Administration_Guide-Certification_Revocation_List_CRL.html
  As the database administrator (shown here as \"postgres\"), copy the CRL file
  into the data directory:
  First, as the system administrator, copy the CRL file into the PostgreSQL Data
  Directory:
  $ sudo cp root.crl ${PGDATA?}/root.crl
  As the database administrator (shown here as \"postgres\"), set the
  ssl_crl_file parameter to the filename of the CRL:
  $ sudo su - postgres
  $ vi ${PGDATA?}/postgresql.conf
  ssl_crl_file = 'root.crl'
  Next, in pg_hba.conf, require ssl authentication:
  $ sudo su - postgres
  $ vi ${PGDATA?}/pg_hba.conf
  hostssl <database> <user> <address> cert clientcert=1
  Now, as the system administrator, reload the server with the new configuration:
  # SYSTEMD SERVER ONLY
  $ sudo systemctl reload postgresql-PG_VER
  # INITD SERVER ONLY
  $ sudo service postgresql-PG_VER reload"

  sql = postgres_session(PG_DBA, PG_DBA_PASSWORD, PG_HOST)

  ssl_crl_file_query = sql.query('SHOW ssl_crl_file;', [PG_DB])

  describe ssl_crl_file_query do
    its('output') { should match /^\w+\.crl$/ }
  end

  ssl_crl_file = ssl_crl_file_query.output

  if ssl_crl_file.empty?
    ssl_crl_file = "#{PG_DATA_DIR}/root.crl"
  elsif File.dirname(ssl_crl_file) == '.'
    ssl_crl_file = "#{PG_DATA_DIR}/#{ssl_crl_file}"
  end

  describe file(ssl_crl_file) do
    it { should be_file }
  end

  describe.one do
    describe postgres_hba_conf(PG_HBA_CONF_FILE).where { type == 'hostssl' } do
      its('auth_method') { should include 'cert' }
    end
    describe postgres_hba_conf(PG_HBA_CONF_FILE).where { type == 'hostssl' } do
      its('auth_params') { should match [/clientcert=1.*/] }
    end
  end
end
