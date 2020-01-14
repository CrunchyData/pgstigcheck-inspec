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
PG_CONF_FILE= attribute(
  'pg_conf_file',
  description: 'define path for the postgresql configuration file',
  default: '/var/lib/pgsql/9.5/data/postgresql.conf'
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



control "V-72951" do
  title "PostgreSQL must generate audit records when unsuccessful accesses to
  objects occur."
  desc  "Without tracking all or selected types of access to all or selected
  objects (tables, views, procedures, functions, etc.), it would be difficult to
  establish, correlate, and investigate the events relating to an incident or
  identify those responsible for one.
  In an SQL environment, types of access include, but are not necessarily
  limited to:
  SELECT
  INSERT
  UPDATE
  DROP
  EXECUTE
  To aid in diagnosis, it is necessary to keep track of failed attempts in
  addition to the successful ones."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000507-DB-000357"
  tag "gid": "V-72951"
  tag "rid": "SV-87603r1_rule"
  tag "stig_id": "PGS9-00-005700"
  tag "cci": "CCI-000172"
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.
  First, as the database administrator (shown here as \"postgres\"), create a
  schema, test_schema, create a table, test_table, within test_schema, and
  insert a value:
  $ sudo su - postgres
  $ psql -c \"CREATE SCHEMA test_schema\"
  $ psql -c \"CREATE TABLE test_schema.test_table(id INT)\"
  $ psql -c \"INSERT INTO test_schema.test_table(id) VALUES (0)\"
  Next, create a role 'bob' and attempt to SELECT, INSERT, UPDATE, and DROP from
  the test table:
  $ psql -c \"CREATE ROLE BOB\"
  $ psql -c \"SELECT * FROM test_schema.test_table\"
  $ psql -c \"INSERT INTO test_schema.test_table VALUES (0)\"
  $ psql -c \"UPDATE test_schema.test_table SET id = 1 WHERE id = 0\"
  $ psql -c \"DROP TABLE test_schema.test_table\"
  $ psql -c \"DROP SCHEMA test_schema\"
  Now, as the database administrator (shown here as \"postgres\"), review
  PostgreSQL/database security and audit settings to verify that audit records
  are created for unsuccessful attempts at the specified access to the specified
  objects:
  $ sudo su - postgres
  $ cat ${PGDATA?}/pg_log/<latest_log>2016-03-30 17:23:41.254 EDT postgres
  postgres ERROR: permission denied for schema test_schema at character 15
  2016-03-30 17:23:41.254 EDT postgres postgres STATEMENT: SELECT *
  FROM test_schema.test_table;
  2016-03-30 17:23:53.973 EDT postgres postgres ERROR: permission denied for
  schema test_schema at character 13
  2016-03-30 17:23:53.973 EDT postgres postgres STATEMENT: INSERT INTO
  test_schema.test_table VALUES (0);
2016-03-30 17:24:32.647 EDT postgres
  postgres ERROR: permission denied for schema test_schema at character 8
  2016-03-30 17:24:32.647 EDT postgres postgres STATEMENT:
  UPDATE test_schema.test_table SET id = 1 WHERE id = 0;
  2016-03-30 17:24:46.197 EDT postgres postgres ERROR: permission denied for
  schema test_schema
  2016-03-30 17:24:46.197 EDT postgres postgres STATEMENT: DROP
  TABLE test_schema.test_table;
  2016-03-30 17:24:51.582 EDT postgres postgres ERROR: must be owner of schema
  test_schema
  2016-03-30 17:24:51.582 EDT postgres postgres STATEMENT: DROP SCHEMA
  test_schema;
  If any of the above steps did not create audit records for SELECT, INSERT,
  UPDATE, and DROP, this is a finding."
  tag "fix": "Configure PostgreSQL to produce audit records when unsuccessful
  attempts to access objects occur.
  All errors and denials are logged if logging is enabled. To ensure that
  logging is enabled, review supplementary content APPENDIX-C for instructions
  on enabling logging."

  
  admin_sql = postgres_session(PG_DBA, PG_DBA_PASSWORD, PG_HOST)

    describe admin_sql.query('DROP TABLE IF EXISTS test_schema.test_table;', [PG_DB]) do
      its('output') { should eq 'DROP TABLE' }
    end

    describe admin_sql.query('DROP SCHEMA IF EXISTS test_schema;', [PG_DB]) do
      its('output') { should eq 'DROP SCHEMA' }
    end

    describe admin_sql.query('CREATE SCHEMA test_schema;', [PG_DB]) do
      its('output') { should eq 'CREATE SCHEMA' }
    end

    describe admin_sql.query('CREATE TABLE test_schema.test_table;', [PG_DB]) do
      its('output') { should eq 'CREATE TABLE' }
    end
    
    describe admin_sql.query('INSERT INTO test_schema.test_table(id) VALUES (0);', [PG_DB]) do
      its('output') { should eq 'INSERT 0 1' }
    end

    describe admin_sql.query('CREATE ROLE bob;', [PG_DB]) do
      its('output') { should eq 'CREATE ROLE' }
    end

    describe admin_sql.query('SET ROLE bob; SELECT * FROM test_schema.test_table;', [PG_DB]) do
      its('output') { should match /ERROR:  permission denied for schema test_schema/ }
    end

    describe admin_sql.query('SET ROLE bob; INSERT INTO test_schema.test_table VALUES (0);', [PG_DB]) do
      its('output') { should match /ERROR:  permission denied for schema test_schema/ }
    end

    describe admin_sql.query('SET ROLE bob; UPDATE test_schema.test_table SET id = 1 WHERE id = 0;', [PG_DB]) do
      its('output') { should match /ERROR:  permission denied for schema test_schema/ }
    end

    describe admin_sql.query('SET ROLE bob; DROP TABLE test_schema.test_table;', [PG_DB]) do
      its('output') { should match /ERROR:  permission denied for schema test_schema/ }
    end

    describe admin_sql.query('SET ROLE bob; DROP SCHEMA test_schema;', [PG_DB]) do
      its('output') { should match /ERROR:  permission denied for schema test_schema/ }
    end

    describe command('grep "SELECT \* FROM test_schema.test_table" "$(find ${PGDATA?}/pg_log -type f -printf "%T@ %p\0" | sort -rz | sed -Ezn "1s/[^ ]* //p")"') do
      its('exit_status') { should eq 0 }
    end

    describe command('grep "INSERT INTO test_schema.test_table VALUES (0)" "$(find ${PGDATA?}/pg_log -type f -printf "%T@ %p\0" | sort -rz | sed -Ezn "1s/[^ ]* //p")"') do
      its('exit_status') { should eq 0 }
    end

    describe command('grep "UPDATE test_schema.test_table SET id = 1 WHERE id = 0" "$(find ${PGDATA?}/pg_log -type f -printf "%T@ %p\0" | sort -rz | sed -Ezn "1s/[^ ]* //p")"') do
      its('exit_status') { should eq 0 }
    end

    describe command('grep "DROP TABLE test_schema.test_table" "$(find ${PGDATA?}/pg_log -type f -printf "%T@ %p\0" | sort -rz | sed -Ezn "1s/[^ ]* //p")"') do
      its('exit_status') { should eq 0 }
    end

end
