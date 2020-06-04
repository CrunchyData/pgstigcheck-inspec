pg_ver = input('pg_version')

pg_dba = input('pg_dba')

pg_dba_password = input('pg_dba_password')

pg_db = input('pg_db')

pg_host = input('pg_host')

pg_data_dir = input('pg_data_dir')

pg_conf_file = input('pg_conf_file')

pg_user_defined_conf = input('pg_user_defined_conf')

control "V-72851" do
  title "PostgreSQL must provide non-privileged users with error messages that
  provide information necessary for corrective actions without revealing
  information that could be exploited by adversaries."
  desc  "Any PostgreSQL or associated application providing too much
  information in error messages on the screen or printout risks compromising the
  data and security of the system. The structure and content of error messages
  need to be carefully considered by the organization and development team.

  Databases can inadvertently provide a wealth of information to an attacker
  through improperly handled error messages. In addition to sensitive business or
  personal information, database errors can provide host names, IP addresses,
  user names, and other system information not required for troubleshooting but
  very useful to someone targeting the system.

  Carefully consider the structure/content of error messages. The extent to
  which information systems are able to identify and handle error conditions is
  guided by organizational policy and operational requirements. Information that
  could be exploited by adversaries includes, for example, logon attempts with
  passwords entered by mistake as the username, mission/business information that
  can be derived from (if not stated explicitly by) information recorded, and
  personal information, such as account numbers, social security numbers, and
  credit card numbers."
  
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000266-DB-000162"
  tag "gid": "V-72851"
  tag "rid": "SV-87503r3_rule"
  tag "stig_id": "PGS9-00-000600"
  tag "fix_id": "F-79293r3_fix"
  tag "cci": ["CCI-001312"]
  tag "nist": ["SI-11 a", "Rev_4"]
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
  desc "check", "As the database administrator, run the following SQL:

  SELECT current_setting('client_min_messages');

  If client_min_messages is not set to error, this is a finding."

  desc "fix", "Note: The following instructions use the PGDATA and PGVER
  environment variables. See supplementary content APPENDIX-F for instructions on
  configuring PGDATA and APPENDIX-H for PGVER.

  As the database administrator, edit \"postgresql.conf\":

  $ sudo su - postgres
  $ vi $PGDATA/postgresql.conf

  Change the client_min_messages parameter to be \"error\":

  client_min_messages = error

  Reload the server with the new configuration (this just reloads settings
  currently in memory; it will not cause an interruption):

  # SYSTEMD SERVER ONLY
  $ sudo systemctl reload postgresql-${PGVER?}

  # INITD SERVER ONLY
  $ sudo service postgresql-${PGVER?} reload"


  default = postgres_conf(pg_conf_file)
  override = postgres_conf(pg_user_defined_conf)
  sql = postgres_session(pg_dba, pg_dba_password, pg_host)

  describe sql.query('SHOW client_min_messages;', [pg_db]) do
   its('output') { should match /^error$/i }
  end

  cmm_conf = override.client_min_messages ? override : default
  describe cmm_conf do
    its('client_min_messages') { should match /^error$/i }
  end
end
