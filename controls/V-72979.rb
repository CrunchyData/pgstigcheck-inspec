pg_dba = attribute('pg_dba')
pg_dba_password = attribute('pg_dba_password')
pg_db = attribute('pg_db')
pg_host = attribute('pg_host')
pg_data_dir = attribute('pg_data_dir')
pg_hba_conf_file = attribute('pg_hba_conf_file')

control 'V-72979' do
  title "PostgreSQL, when utilizing PKI-based authentication, must validate
  certificates by performing RFC 5280-compliant certification path validation."
  desc "The DoD standard for authentication is DoD-approved PKI certificates.
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

  tag "gtitle": 'SRG-APP-000175-DB-000067'
  tag "gid": 'V-72979'
  tag "rid": 'SV-87631r1_rule'
  tag "stig_id": 'PGS9-00-007000'
  tag "cci": ['CCI-000185']
  tag "nist": ['IA-5 (2) (a)', 'Rev_4']
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
  $ grep hostssl ${PGDATA?}/postgresql.conf
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
  $ sudo systemctl reload postgresql-9.5
  # INITD SERVER ONLY
  $ sudo service postgresql-9.5 reload"

  sql = postgres_session(pg_dba, pg_dba_password, pg_host)

  ssl_crl_file_query = sql.query('SHOW ssl_crl_file;', [pg_db])

  describe ssl_crl_file_query do
    its('output') { should match /^\w+\.crl$/ }
  end

  ssl_crl_file = ssl_crl_file_query.output

  if ssl_crl_file.empty?
    ssl_crl_file = "#{pg_data_dir}/root.crl"
  elsif File.dirname(ssl_crl_file) == '.'
    ssl_crl_file = "#{pg_data_dir}/#{ssl_crl_file}"
  end

  describe file(ssl_crl_file) do
    it { should be_file }
  end

  describe.one do
    describe postgres_hba_conf(pg_hba_conf_file).where { type == 'hostssl' } do
      its('auth_method') { should include 'cert' }
    end
    describe postgres_hba_conf(pg_hba_conf_file).where { type == 'hostssl' } do
      its('auth_params') { should match [/clientcert=1.*/] }
    end
  end
end
