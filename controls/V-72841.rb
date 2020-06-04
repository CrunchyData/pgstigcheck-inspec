pg_ver = input('pg_version')

pg_dba = input('pg_dba')

pg_dba_password = input('pg_dba_password')

pg_db = input('pg_db')

pg_host = input('pg_host')

pg_port = input('pg_port')

control "V-72841" do
  title "PostgreSQL must be configured to prohibit or restrict the use of
	organization-defined functions, ports, protocols, and/or services, as defined
	in the PPSM CAL and vulnerability assessments."
  desc  "In order to prevent unauthorized connection of devices, unauthorized
	transfer of information, or unauthorized tunneling (i.e., embedding of data
	types within data types), organizations must disable or restrict unused or
	unnecessary physical and logical ports/protocols/services on information
	systems.

    Applications are capable of providing a wide variety of functions and
	services. Some of the functions and services provided by default may not be
	necessary to support essential organizational operations. Additionally, it is
	sometimes convenient to provide multiple services from a single component
	(e.g., email and web services); however, doing so increases risk over limiting
	the services provided by any one component.

    To support the requirements and principles of least functionality, the
	application must support the organizational requirements providing only
	essential capabilities and limiting the use of ports, protocols, and/or
	services to only those required, authorized, and approved to conduct official
	business or to address authorized quality of life issues.

    Database Management Systems using ports, protocols, and services deemed
	unsafe are open to attack through those ports, protocols, and services. This
	can allow unauthorized access to the database and through the database to other
	components of the information system."

  	impact 0.5
  	tag "severity": "medium"
  	tag "gtitle": "SRG-APP-000142-DB-000094"
  	tag "gid": "V-72841"
  	tag "rid": "SV-87493r2_rule"
  	tag "stig_id": "PGS9-00-000100"
  	tag "fix_id": "F-79283r5_fix"
  	tag "cci": ["CCI-000382", "CCI-001762"]
  	tag "nist": ["CM-7 b", "CM-7 (1) (b)", "Rev_4"]
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
  	desc "check", "As the database administrator, run the following SQL:

	$ psql -c \"SHOW port\"

	If the currently defined port configuration is deemed prohibited, this is a
	finding."

  	desc "fix", "Note: The following instructions use the PGDATA and PGVER
	environment variables. See supplementary content APPENDIX-F for instructions on
	configuring PGDATA and APPENDIX-H for PGVER.

	To change the listening port of the database, as the database administrator,
	change the following setting in postgresql.conf:

	$ sudo su - postgres
	$ vi $PGDATA/postgresql.conf
	
	Change the port parameter to the desired port.

	Next, restart the database:

	# SYSTEMD SERVER ONLY
	$ sudo systemctl restart postgresql-${PGVER?}
	
	# INITD SERVER ONLY
	$ sudo service postgresql-${PGVER?} restart

	Note: psql uses the default port 5432 by default. This can be changed by
	specifying the port with psql or by setting the PGPORT environment variable:

	$ psql -p 5432 -c \"SHOW port\"
	$ export PGPORT=5432"

  sql = postgres_session(pg_dba, pg_dba_password, pg_host)

  describe sql.query('SHOW port;', [pg_db]) do
    its('output') { should eq pg_port }
  end

  describe port(pg_port) do
    it { should be_listening }
    its('processes') { should include 'postgres' }
  end
end
