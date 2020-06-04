pg_owner = input('pg_owner')

pg_log_dir = input('pg_log_dir')

pg_audit_log_dir = input('pg_audit_log_dir')

pg_dba = input('pg_dba')

pg_dba_password = input('pg_dba_password')

pg_db = input('pg_db')

pg_port = input('pg_port')

pg_host = input('pg_host')

pg_conf_file = input('pg_conf_file')

client_min_mesg = input(
  'client_min_mesg',
  description: 'the requried value of "client_min_messages" setting',
  value: 'error'
)

if command('psql').exist?

  control "V-72889" do
    title "PostgreSQL must reveal detailed error messages only to the ISSO, ISSM,
    SA and DBA."
    desc  "If PostgreSQL provides too much information in error logs and
    administrative messages to the screen, this could lead to compromise. The
    structure and content of error messages need to be carefully considered by the
    organization and development team. The extent to which the information system
    is able to identify and handle error conditions is guided by organizational
    policy and operational requirements.

    Some default PostgreSQL error messages can contain information that could
    aid an attacker in, among others things, identifying the database type, host
    address, or state of the database. Custom errors may contain sensitive customer
    information.

    It is important that detailed error messages be visible only to those who
    are authorized to view them; that general users receive only generalized
    acknowledgment that errors have occurred; and that these generalized messages
    appear only when relevant to the user's task. For example, a message along the
    lines of, \"An error has occurred. Unable to save your changes. If this problem
    persists, please contact your help desk\" would be relevant. A message such as
    \"Warning: your transaction generated a large number of page splits\" would
    likely not be relevant.

    Administrative users authorized to review detailed error messages typically
    are the ISSO, ISSM, SA, and DBA. Other individuals or roles may be specified
    according to organization-specific needs, with DBA approval."

    impact 0.5
    tag "severity": "medium"
    tag "gtitle": "SRG-APP-000267-DB-000163"
    tag "gid": "V-72889"
    tag "rid": "SV-87541r2_rule"
    tag "stig_id": "PGS9-00-002500"
    tag "fix_id": "F-79331r1_fix"
    tag "cci": ["CCI-001314"]
    tag "nist": ["SI-11 b", "Rev_4"]
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
    desc "check", "Note: The following instructions use the PGDATA environment
    variable. See supplementary content APPENDIX-F for instructions on configuring
    PGDATA. 

    Check PostgreSQL settings and custom database code to determine if detailed
    error messages are ever displayed to unauthorized individuals. 

    To check the level of detail for errors exposed to clients, as the database
    administrator (shown here as \"postgres\"), run the following: 

    $ sudo su - postgres 
    $ grep \"client_min_messages\" ${PGDATA?}/postgresql.conf 

    If client_min_messages is set to LOG or DEBUG, this is a finding. 

    If detailed error messages are displayed to individuals not authorized to view
    them, this is a finding. 

    #### stderr Logging 

    Logs may contain detailed information and should only be accessible by the
    database owner. 

    As the database administrator, verify the following settings of logs in the
    postgresql.conf file. 

    Note: Consult the organization's documentation on acceptable log privileges 

    $ sudo su - postgres 
    $ grep log_directory ${PGDATA?}/postgresql.conf 
    $ grep log_file_mode ${PGDATA?}/postgresql.conf 

    Next, verify the log files have the set configurations. 

    Note: Use location of logs from log_directory. 

    $ ls -l <audit_log_path> 
    total 32 
    -rw-------. 1 postgres postgres 0 Apr 8 00:00 postgresql-Fri.log 
    -rw-------. 1 postgres postgres 8288 Apr 11 17:36 postgresql-Mon.log 
    -rw-------. 1 postgres postgres 0 Apr 9 00:00 postgresql-Sat.log 
    -rw-------. 1 postgres postgres 0 Apr 10 00:00 postgresql-Sun.log 
    -rw-------. 1 postgres postgres 16212 Apr 7 17:05 postgresql-Thu.log 
    -rw-------. 1 postgres postgres 1130 Apr 6 17:56 postgresql-Wed.log 

    If logs are not owned by the database administrator or have permissions that
    are not 0600, this is a finding. 

    #### syslog Logging 

    If PostgreSQL is configured to use syslog for logging, consult organization
    location and permissions for syslog log files. If the logs are not owned by
    root or have permissions that are not 0600, this is a finding."
      
    desc "fix", "Note: The following instructions use the PGDATA environment
    variable. See supplementary content APPENDIX-F for instructions on configuring
    PGDATA.

    To set the level of detail for errors messages exposed to clients, as the
    database administrator (shown here as \"postgres\"), run the following commands:

    $ sudo su - postgres
    $ vi ${PGDATA?}/postgresql.conf
    client_min_messages = notice"

  # @todo determine how to handle stderr errors?

    describe directory(pg_log_dir) do
      it { should be_directory }
      it { should be_owned_by pg_owner }
      it { should be_grouped_into pg_owner }
      its('mode') { should  cmp '0700' }
    end

    describe directory(pg_audit_log_dir) do
      it { should be_directory }
      it { should be_owned_by pg_owner }
      it { should be_grouped_into pg_owner }
      its('mode') { should  cmp '0700' }
    end

    sql = postgres_session(pg_dba, pg_dba_password, pg_host)
    describe sql.query("SELECT current_setting('client_min_messages')", [pg_db]) do
      its('output') { should_not match %r{log|debug|LOG|DEBUG} }
      its('output') { should cmp client_min_mesg }
    end

    describe postgres_conf(pg_conf_file) do
      its('log_directory') { should eq 'pg_log' }
      its('log_file_mode') { should eq '0600' }
      its('client_min_messages') { should cmp client_min_mesg }
    end

    describe command("find #{pg_audit_log_dir} -type f ! -perm 0600 | wc -l") do
      its('stdout.strip') { should eq '0' }
    end
  end
end