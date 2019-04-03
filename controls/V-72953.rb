# encoding: utf-8

pg_dba = attribute('pg_dba')
pg_dba_password = attribute('pg_dba_password')
pg_db = attribute('pg_db')
pg_host = attribute('pg_host')

control "V-72953" do
  title "PostgreSQL must generate audit records for all privileged activities or
  other system-level access."
  desc  "Without tracking privileged activity, it would be difficult to
  establish, correlate, and investigate the events relating to an incident or
  identify those responsible for one.
  System documentation should include a definition of the functionality
  considered privileged.
  A privileged function in this context is any operation that modifies the
  structure of the database, its built-in logic, or its security settings.
  This would include all Data Definition Language (DDL) statements and all
  security-related statements. In an SQL environment, it encompasses, but is not
  necessarily limited to:
  CREATE
  ALTER
  DROP
  GRANT
  REVOKE
  There may also be Data Manipulation Language (DML) statements that, subject to
  context, should be regarded as privileged. Possible examples in SQL include:
  TRUNCATE TABLE;DELETE, or DELETE affecting more than n rows, for some n, or
  DELETE without a WHERE clause;
  UPDATE or UPDATE affecting more than n rows, for some n, or UPDATE without a
  WHERE clause;
  any SELECT, INSERT, UPDATE, or DELETE to an application-defined security table
  executed by other than a security principal.
  Depending on the capabilities of PostgreSQL and the design of the database and
  associated applications, audit logging may be achieved by means of DBMS
  auditing features, database triggers, other mechanisms, or a combination of
  these.
  Note: That it is particularly important to audit, and tightly control, any
  action that weakens the implementation of this requirement itself, since the
  objective is to have a complete audit trail of all administrative activity."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000504-DB-000354"
  tag "gid": "V-72953"
  tag "rid": "SV-87605r1_rule"
  tag "stig_id": "PGS9-00-005800"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "check": "First, as the database administrator, verify pgaudit is enabled
  by running the following SQL:
  $ sudo su - postgres
  $ psql -c \"SHOW shared_preload_libraries\"
  If the output does not contain pgaudit, this is a finding.
  Next, verify that role, read, write, and ddl auditing are enabled:
  $ psql -c \"SHOW pgaudit.log\"
  If the output does not contain role, read, write, and ddl, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.
  Using pgaudit PostgreSQL can be configured to audit these requests. See
  supplementary content APPENDIX-B for documentation on installing pgaudit.
  With pgaudit installed the following configurations can be made:
  $ sudo su - postgres
  $ vi ${PGDATA?}/postgresql.conf
  Add the following parameters (or edit existing parameters):
  shared_preload_libraries = ‘pgaudit’
  pgaudit.log='ddl, role, read, write'
  Now, as the system administrator, reload the server with the new configuration:
  # SYSTEMD SERVER ONLY
  $ sudo systemctl reload postgresql-9.5
  # INITD SERVER ONLY
  $ sudo service postgresql-9.5 reload"

  sql = postgres_session(pg_dba, pg_dba_password, pg_host)

  describe sql.query('SHOW shared_preload_libraries;', [pg_db]) do
    its('output') { should include 'pgaudit' }
  end

  pgaudit_types = %w(ddl read role write)

  pgaudit_types.each do |type|
    describe sql.query('SHOW pgaudit.log;', [pg_db]) do
      its('output') { should include type }
    end
  end
end
