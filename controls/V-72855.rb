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
  description: 'The postgres DBA user to access the database',
  default: 'stig_dba'
)

PG_DBA_PASSWORD = attribute(
  'pg_dba_password',
  description: "password for the postgres dba password",
  default: 'stigD@1234#')

PG_DB = attribute(
  'pg_db',
  description: 'the default postgres database',
  default: 'stig_test_db'
)

PG_PORT = attribute(
  'pg_port',
  description: "The port that the postgres server is listening to",
  default: '5432'
)

PG_HOST = attribute(
  'pg_host',
  description: "Hostname or ip allow to connect to the database",
  default: '127.0.0.1'
)

only_if do
  command('psql').exist?
end


control "V-72855" do
  title "PostgreSQL must limit privileges to change functions and triggers, and
  links to software external to PostgreSQL."
  desc  "If the system were to allow any user to make changes to software
  libraries, those changes might be implemented without undergoing the
  appropriate testing and approvals that are part of a robust change management
  process.  Accordingly, only qualified and authorized individuals must be
  allowed to obtain access to information system components for purposes of
  initiating changes, including upgrades and modifications.  nmanaged changes
  that occur to the database code can lead to unauthorized or compromised
  installations."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000133-DB-000179"
  tag "gid": "V-72855"
  tag "rid": "SV-87507r1_rule"
  tag "stig_id": "PGS9-00-000710"
  tag "cci": "CCI-001499"
  tag "nist": ["CM-5 (6)", "Rev_4"]

  tag "check": "Only owners of objects can change them. To view all functions,
  triggers, and trigger procedures, their ownership and source, as the database
  administrator (shown here as \"postgres\") run the following SQL:

  $ sudo su - postgres
  $ psql -x -c \"\\df+\"

  Only the OS database owner user (shown here as \"postgres\") or a PostgreSQL
  superuser can change links to external software.

  As the database administrator (shown here as \"postgres\"), check the permissions
  of configuration files for the database:

  $ sudo su - postgres
  $ ls -la ${PGDATA?}

  If any files are not owned by the database owner or have permissions allowing
  others to modify (write) configuration files, this is a finding."

  tag "fix": "To change ownership of an object, as the database administrator
  (shown here as \"postgres\"), run the following SQL:

  $ sudo su – postgres\
  $ psql -c \"ALTER FUNCTION function_name OWNER TO new_role_name\"

  To change ownership of postgresql.conf, as the database administrator (shown
  here as \"postgres\"), run the following commands:

  $ sudo su - postgres
  $ chown postgres:postgres ${PGDATA?}/postgresql.conf
  $ chmod 0600 ${PGDATA?}/postgresql.conf

  To remove superuser from a role, as the database administrator (shown here as
  \"postgres\"), run the following SQL:

  $ sudo su - postgres
  $ psql -c \"ALTER ROLE rolename WITH NOSUPERUSER\""

# @todo draft code below, how do we test for manual checks?

  dbs = nil
  db = nil

  if !("#{PG_DB}".to_s.empty?)
    db = ["#{PG_DB}"]
    dbs = db.map { |x| "-d #{x}" }.join(' ')
  end

  describe command("PGPASSWORD='#{PG_DBA_PASSWORD}' psql -U #{PG_DBA} #{dbs} -h #{PG_HOST} -p #{PG_PORT} -A -t -c \"\\df+\"") do
    its('stdout') { should match /5432/ }
  end

end
