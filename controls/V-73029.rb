# encoding: utf-8

pg_owner = attribute('pg_owner')
pg_dba = attribute('pg_dba')
pg_dba_password = attribute('pg_dba_password')
pg_db = attribute('pg_db')
pg_host = attribute('pg_host')
pg_data_dir = attribute('pg_data_dir')

control "V-73029" do
  title "PostgreSQL must enforce authorized access to all PKI private keys
stored/utilized by PostgreSQL."
  desc  "The DoD standard for authentication is DoD-approved PKI certificates. PKI
certificate-based authentication is performed by requiring the certificate holder to
cryptographically prove possession of the corresponding private key.

If the private key is stolen, an attacker can use the private key(s) to impersonate
the certificate holder. In cases where PostgreSQL-stored private keys are used to
authenticate PostgreSQL to the system’s clients, loss of the corresponding private
keys would allow an attacker to successfully perform undetected man-in-the-middle
attacks against PostgreSQL system and its clients.

Both the holder of a digital certificate and the issuing authority must take careful
measures to protect the corresponding private key. Private keys should always be
generated and protected in FIPS 140-2 validated cryptographic modules.

All access to the private key(s) of PostgreSQL must be restricted to authorized and
authenticated users. If unauthorized users have access to one or more of
PostgreSQL's private keys, an attacker could gain access to the key(s) and use them
to impersonate the database on the network or otherwise perform unauthorized
actions."
  impact 0.7
  tag "severity": "high"
  tag "gtitle": "SRG-APP-000176-DB-000068"
  tag "gid": "V-73029"
  tag "rid": "SV-87681r1_rule"
  tag "stig_id": "PGS9-00-010200"
  tag "cci": ["CCI-000186"]
  tag "nist": ["IA-5 (2) (b)", "Rev_4"]
  tag "check": "First, as the database administrator (shown here as \"postgres\"),
verify the following settings:

Note: If no specific directory given before the name, the files are stored in
PGDATA.

$ sudo su - postgres
$ psql -c \"SHOW ssl_ca_file\"
$ psql -c \"SHOW ssl_cert_file\"
$ psql -c \"SHOW ssl_crl_file\"
$ psql -c \"SHOW ssl_key_file\"

If the directory these files are stored in is not protected, this is a finding."
  tag "fix": "Store all PostgreSQL PKI private keys in a FIPS 140-2 validated
cryptographic module. Ensure access to PostgreSQL PKI private keys is restricted to
only authenticated and authorized users.

PostgreSQL private key(s) can be stored in $PGDATA directory, which is only
accessible by the database owner (usually postgres, DBA) user. Do not allow access
to this system account to unauthorized users.

To put the keys in a different directory, as the database administrator (shown here
as \"postgres\"), set the following settings to a protected directory:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf
ssl_ca_file = \"/some/protected/directory/root.crt\"
ssl_crl_file = \"/some/protected/directory/root.crl\"
ssl_cert_file = \"/some/protected/directory/server.crt\"
ssl_key_file = \"/some/protected/directory/server.key\"

Now, as the system administrator, restart the server with the new configuration:

# SYSTEMD SERVER ONLY
$ sudo systemctl restartpostgresql-9.5

# INITD SERVER ONLY
$ sudo service postgresql-9.5 restart

For more information on configuring PostgreSQL to use SSL, see supplementary content
APPENDIX-G."

  sql = postgres_session(pg_dba, pg_dba_password, pg_host)

  settings = %w(ssl_cert_file ssl_key_file ssl_ca_file ssl_crl_file)

  settings.each do |setting|
    file_query = sql.query("SHOW #{setting};", [pg_db])
    file = file_query.output

    if file.empty?
      name = ''
      ext = ''

      case setting
      when /cert/
        name = 'server'
        ext = 'crt'
      when /key/
        name = 'server'
        ext = 'key'
      when /ca/
        name = 'root'
        ext = 'crt'
      when /crl/
        name = 'root'
        ext = 'crl'
      end

      file = "#{pg_data_dir}/#{name}.#{ext}"
    elsif File.dirname(file) == '.'
      file = "#{pg_data_dir}/#{file}"
    end

    describe file(file) do
      it { should be_file }
    end

    directory = File.dirname(file)

    describe directory(directory) do
      its('owner') { should match /root|#{pg_owner}/ }
      its('mode') { should cmp '0700' }
    end
  end
end
