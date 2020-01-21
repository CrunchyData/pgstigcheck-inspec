pg_owner = input('pg_owner')

pg_ver = input('pg_version')

pg_data_dir = input('pg_data_dir')

PG_SHARED_LIBS = input(
  'pg_shared_libs',
  value: [
    "/usr/pgsql-#{pg_ver}",
    "/usr/pgsql-#{pg_ver}/bin",
    "/usr/pgsql-#{pg_ver}/include",
    "/usr/pgsql-#{pg_ver}/lib",
    "/usr/pgsql-#{pg_ver}/share"
    ])

control "V-72853" do
  title "Privileges to change PostgreSQL software modules must be limited."
  desc  "If the system were to allow any user to make changes to software
  libraries, those changes might be implemented without undergoing the
  appropriate testing and approvals that are part of a robust change management
  process.
    
  Accordingly, only qualified and authorized individuals must be allowed to
  obtain access to information system components for purposes of initiating
  changes, including upgrades and modifications.
      
  Unmanaged changes that occur to the database software libraries or
  configuration can lead to unauthorized or compromised installations."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000133-DB-000179"
  tag "gid": "V-72853"
  tag "rid": "SV-87505r2_rule"
  tag "stig_id": "PGS9-00-000700"
  tag "fix_id": "F-79295r4_fix"
  tag "cci": ["CCI-001499"]
  tag "nist": ["CM-5 (6)", "Rev_4"]
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
  desc "check", "Note: The following instructions use the PGDATA and PGVER
  environment variables. See supplementary content APPENDIX-F for instructions on
  configuring PGDATA and APPENDIX-H for PGVER.

  As the database administrator (shown here as \"postgres\"), check the
  permissions of configuration files for the database: 

  $ sudo su - postgres 
  $ ls -la ${PGDATA?} 

  If any files are not owned by the database owner or have permissions allowing
  others to modify (write) configuration files, this is a finding. 

  As the server administrator, check the permissions on the shared libraries for
  PostgreSQL: 

  $ sudo ls -la /usr/pgsql-${PGVER?}
  $ sudo ls -la /usr/pgsql-${PGVER?}/bin 
  $ sudo ls -la /usr/pgsql-${PGVER?}/include 
  $ sudo ls -la /usr/pgsql-${PGVER?}/lib 
  $ sudo ls -la /usr/pgsql-${PGVER?}/share 

  If any files are not owned by root or have permissions allowing others to
  modify (write) configuration files, this is a finding."

  desc "fix", "Note: The following instructions use the PGDATA and PGVER
  environment variables. See supplementary content APPENDIX-F for instructions on
  configuring PGDATA and APPENDIX-H for PGVER.

  As the database administrator (shown here as \"postgres\"), change the
  ownership and permissions of configuration files in PGDATA:

  $ sudo su - postgres
  $ chown postgres:postgres ${PGDATA?}/postgresql.conf
  $ chmod 0600 ${PGDATA?}/postgresql.conf

  As the server administrator, change the ownership and permissions of shared
  objects in /usr/pgsql-${PGVER?}/*.so

  $ sudo chown root:root /usr/pgsql-${PGVER?}/lib/*.so
  $ sudo chmod 0755 /usr/pgsql-${PGVER?}/lib/*.so

  As the service administrator, change the ownership and permissions of
  executables in /usr/pgsql-${PGVER?}/bin:

  $ sudo chown root:root /usr/pgsql-${PGVER?}/bin/*
  $ sudo chmod 0755 /usr/pgsql-${PGVER?}/bin/*"


  #ver=nil
  #ver=inspec.command("psql --version | awk \'{ print $NF }\' | awk -F. \'{ print $1\".\"$2 }\'").stdout.strip

  describe file(pg_data_dir) do
      it { should be_directory }
      it { should be_owned_by pg_owner }
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
