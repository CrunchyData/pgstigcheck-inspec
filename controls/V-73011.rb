pg_host = input('pg_host')

login_user = input('login_user')

pg_dba = input('pg_dba')

pg_dba_password = input('pg_dba_password')

pg_db = input('pg_db')

approved_packages = input('approved_packages')

control "V-73011" do
  title "Unused database components which are integrated in PostgreSQL and
  cannot be uninstalled must be disabled."
  desc  "Information systems are capable of providing a wide variety of
  functions and services. Some of the functions and services, provided by
  default, may not be necessary to support essential organizational operations
  (e.g., key missions, functions).  

  It is detrimental for software products to provide, or install by default,
  functionality exceeding requirements or mission objectives.  

  PostgreSQL must adhere to the principles of least functionality by
  providing only essential capabilities. 

  Unused, unnecessary PostgreSQL components increase the attack vector for
  PostgreSQL by introducing additional targets for attack. By minimizing the
  services and applications installed on the system, the number of potential
  vulnerabilities is reduced. Components of the system that are unused and cannot
  be uninstalled must be disabled. The techniques available for disabling
  components will vary by DBMS product, OS and the nature of the component and
  may include DBMS configuration settings, OS service settings, OS file access
  security, and DBMS user/role permissions."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000141-DB-000092"
  tag "gid": "V-73011"
  tag "rid": "SV-87663r2_rule"
  tag "stig_id": "PGS9-00-009200"
  tag "fix_id": "F-79457r1_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
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
  desc "check", "To list all installed packages, as the system administrator, run
  the following:

  # RHEL/CENT Systems
  $ sudo yum list installed | grep postgres

  # Debian Systems
  $ dpkg --get-selections | grep postgres

  If any packages are installed that are not required, this is a finding."
  
  desc "fix", "To remove any unneeded executables, as the system administrator,
  run the following:

  # RHEL/CENT Systems
  $ sudo yum erase <package_name>

  # Debian Systems
  $ sudo apt-get remove <package_name>"

  if command('yum').exist?
    yum_packages = command("yum list installed | grep \"postgres\"")
    yum_packages.each do |package|
      describe(package) do
        it { should be_in approved_packages }
      end
    end
  end
  
  if command('dpkg').exist?
    dpkg_packages = command("dpkg --get-selections | grep \"postgres\"")
    dpkg_packages.each do |package|
      describe(package) do
        it { should be_in approved_packages }
      end
    end
  end
end