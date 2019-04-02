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
pg_dba = attribute(
  'pg_dba',
  description: 'The postgres DBA user to access the test database',
)

pg_dba_password = attribute(
  'pg_dba_password',
  description: 'The password for the postgres DBA user',
)

pg_db = attribute(
  'pg_db',
  description: 'The database used for tests',
)

pg_host = attribute(
  'pg_host',
  description: 'The hostname or IP address used to connect to the database',
)

pg_data_dir = attribute(
  'pg_data_dir',
  description: 'The postgres data directory',
)

pg_conf_file = attribute(
  'pg_conf_file',
  description: 'The postgres configuration file',
)

pg_user_defined_conf = attribute(
  'pg_user_defined_conf',
  description: 'An additional postgres configuration file used to override default values',
)

control "V-72851" do
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
  tag "severity": "medium"

  tag "gtitle": "SRG-APP-000266-DB-000162"
  tag "gid": "V-72851"
  tag "rid": "SV-87503r1_rule"
  tag "stig_id": "PGS9-00-000600"
  tag "cci": ["CCI-001312"]
  tag "nist": ["SI-11 a", "Rev_4"]
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
