# encoding: utf-8

control "V-73011" do
  title "Unused database components which are integrated in PostgreSQL and cannot be
uninstalled must be disabled."
  desc  "Information systems are capable of providing a wide variety of functions
and services. Some of the functions and services, provided by default, may not be
necessary to support essential organizational operations (e.g., key missions,
functions).

It is detrimental for software products to provide, or install by default,
functionality exceeding requirements or mission objectives.

PostgreSQLs must adhere to the principles of least functionality by providing only
essential capabilities.

Unused, unnecessary PostgreSQL components increase the attack vector for PostgreSQL
by introducing additional targets for attack. By minimizing the services and
applications installed on the system, the number of potential vulnerabilities is
reduced. Components of the system that are unused and cannot be uninstalled must be
disabled. The techniques available for disabling components will vary by DBMS
product, OS and the nature of the component and may include DBMS configuration
settings, OS service settings, OS file access security, and DBMS user/role
permissions."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000141-DB-000092"
  tag "gid": "V-73011"
  tag "rid": "SV-87663r1_rule"
  tag "stig_id": "PGS9-00-009200"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "check": "To list all installed packages, as the system administrator, run the
following:

# RHEL/CENT Systems
$ sudo yum list installed | grep postgres

# Debian Systems
$ dpkg --get-selections | grep postgres

If any packages are installed that are not required, this is a finding."

  tag "fix": "To remove any unneeded executables, as the system administrator, run
the following:

# RHEL/CENT Systems
$ sudo yum erase <package_name>

# Debian Systems
$ sudo apt-get remove <package_name>"

  only_if { false }

end
