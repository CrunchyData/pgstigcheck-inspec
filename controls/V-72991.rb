pg_dba = input('pg_dba')

pg_dba_password = input('pg_dba_password')

pg_db = input('pg_db')

pg_host = input('pg_host')

control "V-72991" do
  title "PostgreSQL must use NSA-approved cryptography to protect classified
  information in accordance with the data owners requirements."
  desc  "Use of weak or untested encryption algorithms undermines the purposes
  of utilizing encryption to protect data. The application must implement
  cryptographic modules adhering to the higher standards approved by the federal
  government since this provides assurance they have been tested and validated.

  It is the responsibility of the data owner to assess the cryptography
  requirements in light of applicable federal laws, Executive Orders, directives,
  policies, regulations, and standards.

  NSA-approved cryptography for classified networks is hardware based. This
  requirement addresses the compatibility of PostgreSQL with the encryption
  devices."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000416-DB-000380"
  tag "gid": "V-72991"
  tag "rid": "SV-87643r2_rule"
  tag "stig_id": "PGS9-00-008100"
  tag "fix_id": "F-79437r2_fix"
  tag "cci": ["CCI-002450"]
  tag "nist": ["SC-13", "Rev_4"]
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
  desc "check", "If PostgreSQL is deployed in an unclassified environment, this is
  not applicable (NA).

  If PostgreSQL is not using NSA-approved cryptography to protect classified
  information in accordance with applicable federal laws, Executive Orders,
  directives, policies, regulations, and standards, this is a finding.

  To check if PostgreSQL is configured to use SSL, as the database administrator
  (shown here as \"postgres\"), run the following SQL:

  $ sudo su - postgres
  $ psql -c \"SHOW ssl\"

  If SSL is off, this is a finding.

  Consult network administration staff to determine whether the server is
  protected by NSA-approved encrypting devices. If not, this a finding."
  
  desc "fix", "Note: The following instructions use the PGDATA and PGVER
  environment variables. See supplementary content APPENDIX-F for instructions on
  configuring PGDATA and APPENDIX-H for PGVER.

  To configure PostgreSQL to use SSL, as a database administrator (shown here as
  \"postgres\"), edit postgresql.conf: 

  $ sudo su - postgres 
  $ vi ${PGDATA?}/postgresql.conf 

  Add the following parameter: 

  ssl = on 

  Now, as the system administrator, reload the server with the new configuration: 

  # SYSTEMD SERVER ONLY 
  $ sudo systemctl reload postgresql-${PGVER?}

  # INITD SERVER ONLY 
  $ sudo service postgresql-${PGVER?} reload 

  For more information on configuring PostgreSQL to use SSL, see supplementary
  content APPENDIX-G. 

  Deploy NSA-approved encrypting devices to protect the server on the network."

  sql = postgres_session(pg_dba, pg_dba_password, pg_host)

  describe sql.query('SHOW ssl;', [pg_db]) do
    its('output') { should match /on|true/i }
  end
end
