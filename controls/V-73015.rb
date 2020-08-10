pg_dba = input('pg_dba')

pg_dba_password = input('pg_dba_password')

pg_db = input('pg_db')

pg_host = input('pg_host')

control "V-73015" do
  title "If passwords are used for authentication, PostgreSQL must store only
  hashed, salted representations of passwords."
  desc  "The DoD standard for authentication is DoD-approved PKI certificates.

      Authentication based on User ID and Password may be used only when it is
  not possible to employ a PKI certificate, and requires AO approval.

      In such cases, database passwords stored in clear text, using reversible
  encryption, or using unsalted hashes would be vulnerable to unauthorized
  disclosure. Database passwords must always be in the form of one-way, salted
  hashes when stored internally or externally to PostgreSQL."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000171-DB-000074"
  tag "gid": "V-73015"
  tag "rid": "SV-87667r2_rule"
  tag "stig_id": "PGS9-00-009500"
  tag "fix_id": "F-79461r2_fix"
  tag "cci": ["CCI-000196"]
  tag "nist": ["IA-5 (1) (c)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  desc "check", "To check if password encryption is enabled, as the database
  administrator (shown here as \"postgres\"), run the following SQL:

  $ sudo su - postgres
  $ psql -c \"SHOW password_encryption\"

  If password_encryption is not on, this is a finding.

  Next, to identify if any passwords have been stored without being hashed and
  salted, as the database administrator (shown here as \"postgres\"), run the
  following SQL:

  $ sudo su - postgres
  $ psql -x -c \"SELECT * FROM pg_shadow\"

  If any password is in plaintext, this is a finding."

  desc "fix", "Note: The following instructions use the PGDATA and PGVER
  environment variables. See supplementary content APPENDIX-F for instructions on
  configuring PGDATA and APPENDIX-H for PGVER.

  To enable password_encryption, as the database administrator, edit
  postgresql.conf: 

  $ sudo su - postgres 
  $ vi ${PGDATA?}/postgresql.conf 
  password_encryption = on 

  Institute a policy of not using the \"WITH UNENCRYPTED PASSWORD\" option with
  the CREATE ROLE/USER and ALTER ROLE/USER commands. (This option overrides the
  setting of the password_encryption configuration parameter.) 

  As the system administrator, restart the server with the new configuration: 

  # SYSTEMD SERVER ONLY 
  $ sudo systemctl restart postgresql-${PGVER?}

  # INITD SERVER ONLY 
  $ sudo service postgresql-${PGVER?} restart"


  sql = postgres_session(pg_dba, pg_dba_password, pg_host)

  describe sql.query('SHOW password_encryption;', [pg_db]) do
    its('output') { should match /on|true/i }
  end

  passwords_sql = "SELECT usename FROM pg_shadow "\
    "WHERE passwd !~ '^md5[0-9a-f]+$';"

  describe sql.query(passwords_sql, [pg_db]) do
    its('output') { should eq '' }
  end

end
