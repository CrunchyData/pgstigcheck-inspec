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

control "V-72905" do
  title "Execution of software modules (to include functions and trigger
  procedures) with elevated privileges must be restricted to necessary cases
  only."
  desc  "In certain situations, to provide required functionality, PostgreSQL
  needs to execute internal logic (stored procedures, functions, triggers, etc.)
  and/or external code modules with elevated privileges. However, if the
  privileges required for execution are at a higher level than the privileges
  assigned to organizational users invoking the functionality
  applications/programs, those users are indirectly provided with greater
  privileges than assigned by organizations.
  Privilege elevation must be utilized only where necessary and protected
  from misuse.
  This calls for inspection of application source code, which will require
  collaboration with the application developers. It is recognized that in
  many cases, the database administrator (DBA) is organizationally separate
  from the application developers, and may have limited, if any, access to
  source code. Nevertheless, protections of this type are so important to the
  secure operation of databases that they must not be ignored. At a minimum,
  the DBA must attempt to obtain assurances from the development organization
  that this issue has been addressed, and must document what has been discovered."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000342-DB-000302"
  tag "gid": "V-72905"
  tag "rid": "SV-87557r1_rule"
  tag "stig_id": "PGS9-00-003600"
  tag "cci": ["CCI-002233"]
  tag "nist": ["AC-6 (8)", "Rev_4"]
  tag "check": "Functions in PostgreSQL can be created with the SECURITY
  DEFINER option. When SECURITY DEFINER functions are executed by a user, said
  function is run with the privileges of the user who created it.
  To list all functions that have SECURITY DEFINER, as, the database
  administrator (shown here as \"postgres\"), run the following SQL:
  $ sudo su - postgres
  $ psql -c \"SELECT nspname, proname, proargtypes, prosecdef, rolname,
  proconfig FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid JOIN
  pg_authid a ON a.oid = p.proowner WHERE prosecdef OR NOT proconfig IS NULL;\"
  In the query results, a prosecdef value of \"t\" on a row indicates that that
  function uses privilege elevation.
  If elevation of PostgreSQL privileges is utilized but not documented, this is
  a finding.
  If elevation of PostgreSQL privileges is documented, but not implemented as
  described in the documentation, this is a finding.
  If the privilege-elevation logic can be invoked in ways other than intended,
  or in contexts other than intended, or by subjects/principals other than
  intended, this is a finding."
  tag "fix": "Determine where, when, how, and by what principals/subjects
  elevated privilege is needed.
  To change a SECURITY DEFINER function to SECURITY INVOKER, as the database
  administrator (shown here as \"postgres\"), run the following SQL:\
  $ sudo su - postgres
  $ psql -c \"ALTER FUNCTION <function_name> SECURITY INVOKER;\""

  sql = postgres_session(PG_DBA, PG_DBA_PASSWORD, PG_HOST)

  security_definer_sql = "SELECT nspname, proname, prosecdef "\
    "FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid "\
    "JOIN pg_authid a ON a.oid = p.proowner WHERE prosecdef = 't';"

  databases_sql = "SELECT datname FROM pg_catalog.pg_database where datname = '#{PG_DB}';"
  databases_query = sql.query(databases_sql, [PG_DB])
  databases = databases_query.lines

  databases.each do |database|
    connection_error = "FATAL:\\s+database \"#{database}\" is not currently "\
      "accepting connections"
    connection_error_regex = Regexp.new(connection_error)

    sql_result=sql.query(security_definer_sql, [database])

    describe.one do
      describe sql_result do
        its('output') { should eq '' }
      end

      describe sql_result do
        it { should match connection_error_regex }
      end
    end
  end
end
