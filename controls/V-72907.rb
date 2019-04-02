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
  description: "The version of the PostgreSQL process which is being inspected (tested)",
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

PG_LOG_DIR = attribute(
  'pg_log_dir',
  description: 'define path for the postgreql log directory',
  default: '/var/lib/pgsql/9.5/data/pg_log'
)

PG_AUDIT_LOG_DIR = attribute(
  'pg_audit_log_dir',
  description: 'define path for the postgreql audit log directory',
  default: '/var/lib/pgsql/9.5/data/pg_log'
)

control "V-72907" do
  title "When invalid inputs are received, PostgreSQL must behave in a
  predictable and documented manner that reflects organizational and system
  objectives."
  desc  "A common vulnerability is unplanned behavior when invalid inputs are
  received. This requirement guards against adverse or unintended system
  behavior caused by invalid inputs, where information system responses to the
  invalid input may be disruptive or cause the system to fail into an unsafe
  state.
  The behavior will be derived from the organizational and system requirements
  and includes, but is not limited to, notification of the appropriate
  personnel, creating an audit record, and rejecting invalid input."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000447-DB-000393"
  tag "gid": "V-72907"
  tag "rid": "SV-87559r1_rule"
  tag "stig_id": "PGS9-00-003700"
  tag "cci": "CCI-002754"
  tag "nist": ["SI-10 (3)", "Rev_4"]
  tag "check": "As the database administrator (shown here as \"postgres\"), make
  a small SQL syntax error in psql by running the following:
  $ sudo su - postgres
  $ psql -c \"CREAT TABLEincorrect_syntax(id INT)\"
  ERROR: syntax error at or near \"CREAT\"
  Now, as the database administrator (shown here as \"postgres\"), verify the
  syntax error was logged (change the log file name and part to suit the
  circumstances):
  $ sudo su - postgres
  $ cat ~/9.5/data/pg_log/postgresql-Wed.log
  2016-03-30 16:18:10.772 EDT postgres postgres 5706bb87.90dERROR: syntax error
  at or near \"CRT\" at character 1
  2016-03-30 16:18:10.772 EDT postgres postgres 5706bb87.90dSTATEMENT: CRT TABLE
  incorrect_syntax(id INT);
  Review system documentation to determine how input errors from application to
  PostgreSQL are to be handled in general and if any special handling is defined
  for specific circumstances.
  If it does not implement the documented behavior, this is a finding."
  tag "fix": "Enable logging.
  To ensure that logging is enabled, review supplementary content APPENDIX-C for
  instructions on enabling logging.
  All errors and denials are logged if logging is enabled."

  #Execute an incorrectly-formed SQL statement with bad syntax, to prompt log ouput

  describe command("PGPASSWORD='#{PG_DBA_PASSWORD}' psql -U #{PG_DBA} -d #{PG_DB} -h #{PG_HOST} -A -t -c \"CREAT TABLE incorrect_syntax2(id INT);\"") do
    its('stdout') { should match // }     
  end

  #Find the most recently modified log file in the pg_audit_log_dir, grep for the syntax error statement, and then
  #test to validate the output matches the regex.

  describe command("cat `find #{PG_AUDIT_LOG_DIR} -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d\" \"` | grep \"syntax error at or near\"") do
    its('stdout') { should match /^.*syntax error at or near .CREAT..*$/ }
  end

 end 
