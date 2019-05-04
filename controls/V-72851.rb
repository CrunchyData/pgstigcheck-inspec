pg_dba = attribute('pg_dba')
pg_dba_password = attribute('pg_dba_password')
pg_db = attribute('pg_db')
pg_host = attribute('pg_host')
pg_data_dir = attribute('pg_data_dir')
pg_conf_file = attribute('pg_conf_file')
pg_conf_file = attribute('pg_user_defined_conf')

control 'V-72851' do
  title "PostgreSQL must provide non-privileged users with error messages that
        provide information necessary for corrective actions without revealing
        information that could be exploited by adversaries."
  desc  "Any PostgreSQL or associated application providing too much information
        in error messages on the screen or printout risks compromising the data
        and security of the system. The structure and content of error messages
        need to be carefully considered by the organization and development team.

        Databases can inadvertently provide a wealth of information to an
        attacker through improperly handled error messages. In addition to
        sensitive business or personal information, database errors can provide
        host names, IP addresses, user names, and other system information not
        required for troubleshooting but very useful to someone targeting the
        system.

        Carefully consider the structure/content of error messages. The extent
        to which information systems are able to identify and handle error
        conditions is guided by organizational policy and operational
        requirements. Information that could be exploited by adversaries
        includes, for example, logon attempts with passwords entered by mistake
        as the username, mission/business information that can be derived from
        (if not stated explicitly by) information recorded, and personal
        information, such as account numbers, social security numbers, and
        credit card numbers."
  impact 0.5

  tag "gtitle": 'SRG-APP-000266-DB-000162'
  tag "gid": 'V-72851'
  tag "rid": 'SV-87503r1_rule'
  tag "stig_id": 'PGS9-00-000600'
  tag "cci": ['CCI-001312']
  tag "nist": ['SI-11 a', 'Rev_4']
  tag "check": "As the database administrator, run the following SQL:

  SELECT current_setting('client_min_messages');

  If client_min_messages is *not* set to error, this is a finding."

  tag "fix": "As the database administrator, edit postgresql.conf:

  $ sudo su - postgres
  $ vi $PGDATA/postgresql.conf
  Change the client_min_messages parameter to be error:
  client_min_messages = 'error'

  Now reload the server with the new configuration (this just reloads settings
  currently in memory, will not cause an interruption):

  $ sudo su - postgres
  # SYSTEMD SERVER ONLY
  $ systemctl reload postgresql-9.5

  # INITD SERVER ONLY
  $ service postgresql-9.5 reload "

  default = postgres_conf(pg_conf_file)
  override = postgres_conf(pg_conf_file)
  sql = postgres_session(pg_dba, pg_dba_password, pg_host)

  describe sql.query('SHOW client_min_messages;', [pg_db]) do
    its('output') { should match /^error$/i }
  end

  cmm_conf = override.client_min_messages ? override : default
  describe cmm_conf do
    its('client_min_messages') { should match /^error$/i }
  end
end
