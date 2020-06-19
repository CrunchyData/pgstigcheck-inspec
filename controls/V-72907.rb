pg_dba = input('pg_dba')

pg_dba_password = input('pg_dba_password',)

pg_db = input('pg_db')

pg_host = input('pg_host')

pg_audit_log_dir = input('pg_audit_log_dir')

control "V-72907" do
  title "When invalid inputs are received, PostgreSQL must behave in a
  predictable and documented manner that reflects organizational and system
  objectives."
  desc  "A common vulnerability is unplanned behavior when invalid inputs are
  received. This requirement guards against adverse or unintended system behavior
  caused by invalid inputs, where information system responses to the invalid
  input may be disruptive or cause the system to fail into an unsafe state.

  The behavior will be derived from the organizational and system
  requirements and includes, but is not limited to, notification of the
  appropriate personnel, creating an audit record, and rejecting invalid input."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000447-DB-000393"
  tag "gid": "V-72907"
  tag "rid": "SV-87559r2_rule"
  tag "stig_id": "PGS9-00-003700"
  tag "fix_id": "F-79349r1_fix"
  tag "cci": ["CCI-002754"]
  tag "nist": ["SI-10 (3)", "Rev_4"]
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
  desc "check", "As the database administrator (shown here as \"postgres\"), make
  a small SQL syntax error in psql by running the following: 

  $ sudo su - postgres 
  $ psql -c \"CREAT TABLEincorrect_syntax(id INT)\" 
  ERROR: syntax error at or near \"CREAT\" 

  Note: The following instructions use the PGVER environment variable. See
  supplementary content APPENDIX-H for instructions on configuring PGVER.

  Now, as the database administrator (shown here as \"postgres\"), verify the
  syntax error was logged (change the log file name and part to suit the
  circumstances): 

  $ sudo su - postgres 
  $ cat ~/${PGVER?}/data/pg_log/postgresql-Wed.log 
  2016-03-30 16:18:10.772 EDT postgres postgres 5706bb87.90dERROR: syntax error
  at or near \"CREAT\" at character 1 
  2016-03-30 16:18:10.772 EDT postgres postgres 5706bb87.90dSTATEMENT: CREAT
  TABLE incorrect_syntax(id INT); 

  Review system documentation to determine how input errors from application to
  PostgreSQL are to be handled in general and if any special handling is defined
  for specific circumstances. 

  If it does not implement the documented behavior, this is a finding."
    
  desc "fix", "Enable logging.

  To ensure that logging is enabled, review supplementary content APPENDIX-C for
  instructions on enabling logging.

  All errors and denials are logged if logging is enabled."

  #Execute an incorrectly-formed SQL statement with bad syntax, to prompt log ouput

  sql = postgres_session(pg_dba, pg_dba_password, pg_host)

  describe sql.query('CREAT TABLE incorrect_syntax2(id INT);', [pg_db]) do
    its('stdout') { should match // }     
  end

  #Find the most recently modified log file in the pg_audit_log_dir, grep for the syntax error statement, and then
  #test to validate the output matches the regex.

  describe command("cat `find #{pg_audit_log_dir} -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d\" \"` | grep \"syntax error at or near\"") do
    its('stdout') { should match /^.*syntax error at or near .CREAT..*$/ }
  end
 end 
