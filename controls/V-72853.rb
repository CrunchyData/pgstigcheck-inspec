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

PG_OWNER = attribute(
  'pg_owner',
  description: "The system user of the postgres process",
  default: 'postgres'
)

PG_VER = attribute(
  'pg_ver',
  description: "The version of postgres that is running",
  default: '9.5'
)

PG_DATA_DIR = attribute(
'pg_data_dir',
description: 'the postgres data dir',
default: '/var/lib/pgsql/9.5/data' )

PG_SHARED_LIBS = attribute(
  'pg_shared_libs',
  description: 'defines the locations of the postgresql shared library directories',
  default: [
    "/usr/pgsql-#{PG_VER}",
    "/usr/pgsql-#{PG_VER}/bin",
    "/usr/pgsql-#{PG_VER}/include",
    "/usr/pgsql-#{PG_VER}/lib",
    "/usr/pgsql-#{PG_VER}/share"
    ])

control "V-72853" do
  title "Privileges to change PostgreSQL software modules must be limited."
  desc  "If the system were to allow any user to make changes to software
  libraries, those changes might be implemented without undergoing the
  appropriate testing and approvals that are part of a robust change management
  process.  Accordingly, only qualified and authorized individuals must be
  allowed to obtain access to information system components for purposes of
  initiating changes, including upgrades and modifications.  Unmanaged changes
  that occur to the database software libraries or configuration can lead to
  unauthorized or compromised installations."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000133-DB-000179"
  tag "gid": "V-72853"
  tag "rid": "SV-87505r1_rule"
  tag "stig_id": "PGS9-00-000700"
  tag "cci": "CCI-001499"
  tag "nist": ["CM-5 (6)", "Rev_4"]

  tag "check": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.  As the database administrator (shown here as \"postgres\"), check the
  permissions of configuration files for the database:

  $ sudo su - postgres
  $ ls -la ${PGDATA?}

  If any files are not owned by the database owner or have permissions allowing
  others to modify (write) configuration files, this is a finding.

  As the server administrator, check the permissions on the shared libraries for
  PostgreSQL:

  $ sudo ls -la /usr/pgsql-9.5
  $ sudo ls -la /usr/pgsql-9.5/bin
  $ sudo ls -la /usr/pgsql-9.5/include
  $ sudo ls -la /usr/pgsql-9.5/lib
  $ sudo ls -la /usr/pgsql-9.5/share

  If any files are not owned by root or have permissions allowing others to
  modify (write) configuration files, this is a finding."

  tag "fix": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.  As the database administrator (shown here as \"postgres\"), change
  the ownership and permissions of configuration files in PGDATA:

  $ sudo su - postgres
  $ chown postgres:postgres ${PGDATA?}/postgresql.conf
  $ chmod 0600 ${PGDATA?}/postgresql.conf

  As the server administrator, change the ownership and permissions of shared
  objects in /usr/pgsql-9.5/*.so

  $ sudo chown root:root /usr/pgsql-9.5/lib/*.so
  $ sudo chmod 0755 /usr/pgsql-9.5/lib/*.so

  As the service administrator, change the ownership and permissions of
  executables in /usr/pgsql-9.5/bin:

  $ sudo chown root:root /usr/pgsql-9.5/bin/*
  $ sudo chmod 0755 /usr/pgsql-9.5/bin/*"

  #ver=nil
  #ver=inspec.command("psql --version | awk \'{ print $NF }\' | awk -F. \'{ print $1\".\"$2 }\'").stdout.strip

  describe file(PG_DATA_DIR) do
      it { should be_directory }
      it { should be_owned_by PG_OWNER }
      its('mode') { should cmp '0700' }
    end

    PG_SHARED_LIBS.each do |libs|
      describe file(libs) do
        it { should be_directory }
        it { should be_owned_by 'root' }
        its('mode') { should cmp '0755' }
      end
    end
  end
