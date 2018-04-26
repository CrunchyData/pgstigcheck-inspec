# encoding: utf-8
#
# :xccdf2inspec: v. 1.1.0
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
  description: "The version of the postgres process",
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

PG_PORT = attribute(
  'pg_port',
  description: 'The port used to connect to the database',
)

control "V-72841" do
  title "PostgreSQL must be configured to prohibit or restrict the use of
        organization-defined functions, ports, protocols, and/or services, as
        defined in the PPSM CAL and vulnerability assessments."
  desc  "In order to prevent unauthorized connection of devices, unauthorized
        transfer of information, or unauthorized tunneling (i.e., embedding of
        data types within data types), organizations must disable or restrict
        unused or unnecessary physical and logical ports/protocols/services on
        information systems.

        Applications are capable of providing a wide variety of functions and
        services. Some of the functions and services provided by default may
        not be necessary to support essential organizational operations.
        Additionally, it is sometimes convenient to provide multiple services
        from a single component (e.g., email and web services); however, doing
        so increases risk over limiting the services provided by any one component.

        To support the requirements and principles of least functionality, the
        application must support the organizational requirements providing only
        essential capabilities and limiting the use of ports, protocols, and/or
        services to only those required, authorized, and approved to conduct
        official business or to address authorized quality of life issues.

        Database Management Systems using ports, protocols, and services deemed
        unsafe are open to attack through those ports, protocols, and services.
        This can allow unauthorized access to the database and through the
        database to other components of the information system."
  impact 0.5

  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000142-DB-000094"
  tag "gid": "V-72841"
  tag "rid": "SV-87493r1_rule"
  tag "stig_id": "PGS9-00-000100"
  tag "cci": ["CCI-000382","CCI-001762"]
  tag "nist": ["CM-7 b", "CM-7 (1) (b)", "Rev_4"]

  tag "check": "As the database administrator, run the following SQL:

  $ psql -c \"SHOW port\"

  If the currently defined port configuration is deemed prohibited, this is a
  finding."

  tag "fix": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.

  To change the listening port of the database, as the database administrator,
  change the following setting in postgresql.conf:

  $ vi $PGDATA/postgresql.conf

  Change the port parameter to the desired port.

  Next, restart the database:

  $ sudo su - postgres
  # SYSTEMD SERVER ONLY
  $ sudo systemctl restart postgresql-PG_VER
  # INITD SERVER ONLY
  $ sudo service postgresql-PG_VER restart

  Note: psql uses the default port 5432 by default. This can be changed by
  specifying the port with psql or by setting the PGPORT environment variable:

  $ psql -p 5432 -c \"SHOW port\"
  $ export PGPORT=5432"

  sql = postgres_session(PG_DBA, PG_DBA_PASSWORD, PG_HOST)

  describe sql.query('SHOW port;', [PG_DB]) do
    its('output') { should eq PG_PORT }
  end

  describe port(PG_PORT) do
    it { should be_listening }
    its('processes') { should include 'postgres' }
  end
end
