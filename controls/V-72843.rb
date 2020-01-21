pg_conf_file= input('pg_conf_file')

pg_dba = input('pg_dba')

pg_dba_password = input('pg_dba_password')

pg_db = input('pg_db')

pg_host = input('pg_host')


  # @todo we need to provide a better example of the error_log output
  control "V-72843" do
    title "PostgreSQL must produce audit records containing sufficient
          information to establish the outcome (success or failure) of the events."
    desc  "Information system auditing capability is critical for accurate
          forensic analysis. Without information about the outcome of events, security
          personnel cannot make an accurate assessment as to whether an attack was
          successful or if changes were made to the security state of the system.
  
          Event outcomes can include indicators of event success or failure and
          event-specific results (e.g., the security state of the information system
          after the event occurred). As such, they also provide a means to measure the
          impact of an event and help authorized personnel to determine the appropriate
          response."

    impact 0.5
    tag "severity": "medium"
    tag "gtitle": "SRG-APP-000099-DB-000043"
    tag "gid": "V-72843"
    tag "rid": "SV-87495r3_rule"
    tag "stig_id": "PGS9-00-000200"
    tag "fix_id": "F-79285r5_fix"
    tag "cci": ["CCI-000134"]
    tag "nist": ["AU-3", "Rev_4"]
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
    
    As a database administrator (shown here as \"postgres\"), create a table,
    insert a value, alter the table and update the table by running the following
    SQL:
    
    CREATE TABLE stig_test(id INT);
    INSERT INTO stig_test(id) VALUES (0);
    ALTER TABLE stig_test ADD COLUMN name text;
    UPDATE stig_test SET id = 1 WHERE id = 0;
    
    Next, as a user without access to the stig_test table, run the following SQL:

    INSERT INTO stig_test(id) VALUES (1);
    ALTER TABLE stig_test DROP COLUMN name;
    UPDATE stig_test SET id = 0 WHERE id = 1;

    The prior SQL should generate errors:

    ERROR: permission denied for relation stig_test
    ERROR: must be owner of relation stig_test
    ERROR: permission denied for relation stig_test

    Now, as the database administrator, drop the test table by running the
    following SQL:

    DROP TABLE stig_test;

    Now verify the errors were logged:
    $ sudo su - postgres
    $ cat ${PGDATA?}/pg_log/<latest_logfile>$PGDATA/
    < 2016-02-23 14:51:31.103 EDT psql postgres postgres 570bf22a.3af2 2016-04-11
    14:51:22 EDT [local] >LOG: AUDIT: SESSION,1,1,DDL,CREATE TABLE,,,CREATE TABLE
    stig_test(id INT);,<none>
    < 2016-02-23 14:51:44.835 EDT psql postgres postgres 570bf22a.3af2 2016-04-11
    14:51:22 EDT [local] >LOG: AUDIT: SESSION,2,1,WRITE,INSERT,,,INSERT INTO
    stig_test(id) VALUES (0);,<none>
    < 2016-02-23 14:53:25.805 EDT psql postgres postgres 570bf22a.3af2 2016-04-11
    14:51:22 EDT [local] >LOG: AUDIT: SESSION,3,1,DDL,ALTER TABLE,,,ALTER TABLE
    stig_test ADD COLUMN name text;,<none>
    < 2016-02-23 14:53:54.381 EDT psql postgres postgres 570bf22a.3af2 2016-04-11
    14:51:22 EDT [local] >LOG: AUDIT: SESSION,4,1,WRITE,UPDATE,,,UPDATE stig_test
    SET id = 1 WHERE id = 0;,<none>
    < 2016-02-23 14:54:20.832 EDT psql postgres postgres 570bf22a.3af2 2016-04-11
    14:51:22 EDT [local] >ERROR: permission denied for relation stig_test
    < 2016-02-23 14:54:20.832 EDT psql postgres postgres 570bf22a.3af2 2016-04-11
    14:51:22 EDT [local] >STATEMENT: INSERT INTO stig_test(id) VALUES (1);
    < 2016-02-23 14:54:41.032 EDT psql postgres postgres 570bf22a.3af2 2016-04-11
    14:51:22 EDT [local] >ERROR: must be owner of relation stig_test
    < 2016-02-23 14:54:41.032 EDT psql postgres postgres 570bf22a.3af2 2016-04-11
    14:51:22 EDT [local] >STATEMENT: ALTER TABLE stig_test DROP COLUMN name;
    < 2016-02-23 14:54:54.378 EDT psql postgres postgres 570bf22a.3af2 2016-04-11
    14:51:22 EDT [local] >ERROR: permission denied for relation stig_test
    < 2016-02-23 14:54:54.378 EDT psql postgres postgres 570bf22a.3af2 2016-04-11
    14:51:22 EDT [local] >STATEMENT: UPDATE stig_test SET id = 0 WHERE id = 1;
    < 2016-02-23 14:55:23.723 EDT psql postgres postgres 570bf307.3b0a 2016-04-11
    14:55:03 EDT [local] >LOG: AUDIT: SESSION,1,1,DDL,DROP TABLE,,,DROP TABLE
    stig_test;,<none>

    If audit records exist without the outcome of the event that occurred, this is
    a finding."

    desc "fix", "Using pgaudit PostgreSQL can be configured to audit various facets
    of PostgreSQL. See supplementary content APPENDIX-B for documentation on
    installing pgaudit.

    All errors, denials and unsuccessful requests are logged if logging is enabled.
    See supplementary content APPENDIX-C for documentation on enabling logging.

    Note: The following instructions use the PGDATA and PGVER environment
    variables. See supplementary content APPENDIX-F for instructions on configuring
    PGDATA and APPENDIX-H for PGVER.

    With pgaudit and logging enabled, set the following configuration settings in
    postgresql.conf, as the database administrator (shown here as \"postgres\"), to
    the following:

    $ sudo su - postgres
    $ vi ${PGDATA?}/postgresql.conf
    pgaudit.log_catalog='on'
    pgaudit.log_level='log'
    pgaudit.log_parameter='on'
    pgaudit.log_statement_once='off'
    pgaudit.log='all, -misc'

    Next, tune the following logging configurations in postgresql.conf:

    $ sudo su - postgres
    $ vi ${PGDATA?}/postgresql.conf
    log_line_prefix = '< %m %u %d %e: >'
    log_error_verbosity = default

    Last, as the system administrator, restart PostgreSQL:

    # SYSTEMD SERVER ONLY
    $ sudo systemctl reload postgresql-${PGVER?}

    # INITD SERVER ONLY
    $ sudo service postgresql-${PGVER?} reload"

  # @FIXME related to Issue#1

    admin_sql = postgres_session(pg_dba, pg_dba_password, pg_host)

  #   these are the set-up actions for test
    

    describe admin_sql.query('DROP TABLE IF EXISTS stig_test;', [pg_db]) do
      its('output') { should eq 'DROP TABLE' }
    end

    describe admin_sql.query('CREATE TABLE stig_test(id INT);', [pg_db]) do
      its('output') { should eq 'CREATE TABLE' }
    end

    describe admin_sql.query('INSERT INTO stig_test(id) VALUES (0);', [pg_db]) do
      its('output') { should eq 'INSERT 0 1' }
    end

    describe admin_sql.query('ALTER TABLE stig_test ADD COLUMN name text;', [pg_db]) do
      its('output') { should eq 'ALTER TABLE' }
    end

    describe admin_sql.query('UPDATE stig_test SET id = 1 WHERE id = 0;', [pg_db]) do
      its('output') { should eq 'UPDATE 1' }
    end

    describe admin_sql.query('show pgaudit.log_catalog') do
      its('output') { should eq 'on' }
    end

    describe admin_sql.query('show pgaudit.log_level') do
      its('output') { should eq 'log' }
    end

    describe admin_sql.query('show pgaudit.log_parameter') do
      its('output') { should eq 'on' }
    end

    describe admin_sql.query('show pgaudit.log_statement_once') do
      its('output') { should eq 'off' }
    end

    describe admin_sql.query('show pgaudit.log') do
      its('output') { should eq 'ddl,read,role, write' }
    end

    describe admin_sql.query('CREATE ROLE foostigtest LOGIN CONNECTION LIMIT 100;') do
      its('output') { should eq 'CREATE ROLE' }
    end

    describe admin_sql.query('SET ROLE foostigtest; INSERT INTO stig_test(id) VALUES (1);', [pg_db]) do
      its('output') { should match /ERROR:  permission denied for relation stig_test/ }
    end

    describe admin_sql.query('SET ROLE foostigtest; ALTER TABLE stig_test DROP COLUMN name;', [pg_db]) do
      its('output') { should match /ERROR:  must be owner of relation stig_test/ }
    end
    
    describe admin_sql.query('SET ROLE foostigtest; UPDATE stig_test SET id = 0 WHERE id = 1;', [pg_db]) do
      its('output') { should match /ERROR:  permission denied for relation stig_test/ }
    end

   describe admin_sql.query('DROP TABLE stig_test;', [pg_db]) do
      its('output') { should eq 'DROP TABLE' }
   end
  
  describe admin_sql.query('DROP ROLE foostigtest') do
      its('output') { should eq 'DROP ROLE' }
  end   

    describe postgres_conf(pg_conf_file) do
      its('log_error_verbosity') { should eq 'default' }
      its('log_duration') { should eq 'on'}
    end
  end
