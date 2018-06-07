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

control "V-73039" do
  title "PostgreSQL must protect its audit features from unauthorized access."
  desc  "Protecting audit data also includes identifying and protecting the tools 
used to view and manipulate log data. 

Depending upon the log format and application, system and application log tools may 
provide the only means to manipulate and manage application and system log data. It 
is, therefore, imperative that access to audit tools be controlled and protected 
from unauthorized access. 

Applications providing tools to interface with audit data will leverage user 
permissions and roles identifying the user accessing the tools and the corresponding 
rights the user enjoys in order make access decisions regarding the access to audit 
tools.

Audit tools include, but are not limited to, OS-provided audit tools, 
vendor-provided audit tools, and open source audit tools needed to successfully view 
and manipulate audit information system activity and records. 

If an attacker were to gain access to audit tools, he could analyze audit logs for 
system weaknesses or weaknesses in the auditing itself. An attacker could also 
manipulate logs to hide evidence of malicious activity."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000121-DB-000202"
  tag "gid": "V-73039"
  tag "rid": "SV-87691r1_rule"
  tag "stig_id": "PGS9-00-010700"
  tag "cci": "CCI-001493"
  tag "nist": ["AU-9", "Rev_4"]
  tag "check": "Note: The following instructions use the PGDATA environment 
variable. See supplementary content APPENDIX-F for instructions on configuring 
PGDATA. Only the database owner and superuser can alter configuration of PostgreSQL.

Make sure the pg_log directory are owned by postgres user and group:

$ sudo su - postgres
$ ls -la ${PGDATA?}/pg_log

If pg_log is not owned by the database owner, this is a finding.

Make sure the data directory are owned by postgres user and group.

$ sudo su - postgres
$ ls -la ${PGDATA?}

If PGDATA is not owned by the database owner, this is a finding.

Make sure pgaudit installation is owned by root:

$ sudo su - postgres
$ ls -la /usr/pgsql-9.5/share/contrib/pgaudit

If pgaudit installation is not owned by root, this is a finding.

Next, as the database administrator (shown here as \"postgres\"), run the following 
SQL to list all roles and their privileges:

$ sudo su - postgres
$ psql -x -c \"\\du\"

If any role has \"superuser\" that should not, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable. 
See supplementary content APPENDIX-F for instructions on configuring PGDATA.

If pg_log or data directory are not owned by postgres user and group, configure them 
as follows:

$ sudo chown -R postgres:postgres ${PGDATA?}

If the pgaudit installation is not owned by root user and group, configure it as 
follows:

$ sudo chown -R root:root /usr/pgsql-9.5/share/contrib/pgaudit.

To remove superuser from a role, as the database administrator (shown here as 
\"postgres\"), run the following SQL:

$ sudo su - postgres
$ psql -c \"ALTER ROLE <role-name> WITH NOSUPERUSER\""
end
