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

PG_VER = attribute(
  'pg_ver',
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

control "V-73025" do
  title "PostgreSQL must provide the means for individuals in authorized roles to
change the auditing to be performed on all application components, based on all
selectable event criteria within organization-defined time thresholds."
  desc  "If authorized individuals do not have the ability to modify auditing
parameters in response to a changing threat environment, the organization may not be
able to effectively respond, and important forensic information may be lost.

This requirement enables organizations to extend or limit auditing as necessary to
meet organizational requirements. Auditing that is limited to conserve information
system resources may be extended to address certain threat situations. In addition,
auditing may be limited to a specific set of events to facilitate audit reduction,
analysis, and reporting. Organizations can establish time thresholds in which audit
actions are changed, for example, near real time, within minutes, or within hours."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000353-DB-000324"
  tag "gid": "V-73025"
  tag "rid": "SV-87677r1_rule"
  tag "stig_id": "PGS9-00-010000"
  tag "cci": ["CCI-001914"]
  tag "nist": ["AU-12 (3)", "Rev_4"]
  tag "check": "First, as the database administrator, check if pgaudit is present in
shared_preload_libraries:

$ sudo su - postgres
$ psql -c \"SHOW shared_preload_libraries\"

If pgaudit is not present in the result from the query, this is a finding."
  tag "fix": "Note: The following instructions use the PGDATA environment variable.
See supplementary content APPENDIX-F for instructions on configuring PGDATA.

To ensure that logging is enabled, review supplementary content APPENDIX-C for
instructions on enabling logging.

For audit logging we suggest using pgaudit. For instructions on how to setup
pgaudit, see supplementary content APPENDIX-B.

As a superuser (postgres), any pgaudit parameter can be changed in postgresql.conf.
Configurations can only be changed by a superuser.

### Example: Change Auditing To Log Any ROLE Statements

Note: This will override any setting already configured.

Alter the configuration to do role-based logging:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameters (or edit existing parameters):

pgaudit.log = 'role'

Now, as the system administrator, reload the server with the new configuration:

# SYSTEMD SERVER ONLY
$ sudo systemctl reload postgresql-PG_VER

# INITD SERVER ONLY
$ sudo service postgresql-PG_VER reload

### Example: Set An Auditing Role And Grant Privileges

An audit role can be configured and granted privileges to specific tables and
columns that need logging.

##### Create Test Table

$ sudo su - postgres
$ psql -c \"CREATE TABLE public.stig_audit_example(id INT, name TEXT, password
TEXT);\"

##### Define Auditing Role

As PostgreSQL superuser (such as postgres), add the following to postgresql.conf or
any included configuration files.

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameters (or edit existing parameters):

pgaudit.role = 'auditor'

Now, as the system administrator, reload the server with the new configuration:

# SYSTEMD SERVER ONLY
$ sudo systemctl reload postgresql-PG_VER

# INITD SERVER ONLY
$ sudo service postgresql-PG_VER reload

Next in PostgreSQL create a new role:

postgres=# CREATE ROLE auditor;
postgres=# GRANT select(password) ON public.stig_audit_example TO auditor;

Note: This role is created with NOLOGIN privileges by default.

Now any SELECT on the column password will be logged:

$ sudo su - postgres
$ psql -c \"SELECT password FROM public.stig_audit_example;\"
$ cat ${PGDATA?}/pg_log/<latest_log>
< 2016-01-28 16:46:09.038 UTC bob postgres: >LOG: AUDIT:
OBJECT,6,1,READ,SELECT,TABLE,public.stig_audit_example,SELECT password FROM
stig_audit_example;,<none>

## Change Configurations During A Specific Timeframe

Deploy PostgreSQL that allows audit configuration changes to take effect within the
timeframe required by the application owner and without involving actions or events
that the application owner rules unacceptable.

Crontab can be used to do this.

For a specific audit role:

# Grant specific audit privileges to an auditing role at 5 PM every day of the week,
month, year at the 0 minute mark.
0 5 * * * postgres /usr/bin/psql -c \"GRANT select(password) ON
public.stig_audit_example TO auditor;\"
# Revoke specific audit privileges to an auditing role at 5 PM every day of the
week, month, year at the 0 minute mark.
0 17 * * * postgres /usr/bin/psql -c \"REVOKE select(password) ON
public.stig_audit_example FROM auditor;\""

  sql = postgres_session(PG_DBA, PG_DBA_PASSWORD, PG_HOST)

  describe sql.query('SHOW shared_preload_libraries;', [PG_DB]) do
    its('output') { should include 'pgaudit' }
  end
end
