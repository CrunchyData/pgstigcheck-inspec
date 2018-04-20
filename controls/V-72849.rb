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

control "V-72849" do
  title "PostgreSQL must integrate with an organization-level
  authentication/access mechanism providing account management and automation
  for all users, groups, roles, and any other principals."
  desc  "Enterprise environments make account management for applications and
  databases challenging and complex. A manual process for account management
  functions adds the risk of a potential oversight or other error. Managing
  accounts for the same person in multiple places is inefficient and prone to
  problems with consistency and synchronization.  A comprehensive application
  account management process that includes automation helps to ensure that
  accounts designated as requiring attention are consistently and promptly
  addressed. Examples include, but are not limited to, using automation to take
  action on multiple accounts designated as inactive, suspended, or terminated,
  or by disabling accounts located in non-centralized account stores, such as
  multiple servers. Account management functions can also include: assignment of
  group or role membership; identifying account type; specifying user access
  authorizations (i.e., privileges); account removal, update, or termination;
  and administrative alerts. The use of automated mechanisms can include, for
  example: using email or text messaging to notify account managers when users
  are terminated or transferred; using the information system to monitor account
  usage; and using automated telephone notification to report atypical system
  account usage.  PostgreSQL must be configured to automatically utilize
  organization-level account management functions, and these functions must
  immediately enforce the organization's current account policy. Automation may
  be comprised of differing technologies that when placed together contain an
  overall mechanism supporting an organization's automated account management
  requirements."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000023-DB-000001"
  tag "gid": "V-72849"
  tag "rid": "SV-87501r1_rule"
  tag "stig_id": "PGS9-00-000500"
  tag "cci": ["CCI-000015"]
  tag "nist": ["AC-2 (1)", "Rev_4"]

  tag "check": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.  If all accounts are authenticated by the organization-level
  authentication/access mechanism, such as LDAP or Kerberos and not by
  PostgreSQL, this is not a finding.  As the database administrator (shown here
  as \"postgres\"), review pg_hba.conf authentication file settings:

  $ sudo su - postgres
  $ cat ${PGDATA?}/pg_hba.conf

  All records must use an auth-method of gss, sspi, or ldap. For details on the
  specifics of these authentication methods see:
  http://www.postgresql.org/docs/current/static/auth-pg-hba-conf.html

  If there are any records with a different auth-method than gss, sspi, or ldap,
  review the system documentation for justification and approval of these records.
  If there are any records with a different auth-method than gss, sspi, or ldap,
  that are not documented and approved, this is a finding."

  tag "fix": "Note: The following instructions use the PGDATA environment
  variable. See supplementary content APPENDIX-F for instructions on configuring
  PGDATA.  Integrate PostgreSQL security with an organization-level
  authentication/access mechanism providing account management for all users,
  groups, roles, and any other principals.  As the database administrator (shown
  here as \"postgres\"), edit pg_hba.conf authentication file:

  $ sudo su - postgres
  $ vi ${PGDATA?}/pg_hba.conf

  For each PostgreSQL-managed account that is not documented and approved,
  either transfer it to management by the external mechanism, or document the
  need for it and obtain approval, as appropriate."

  only_if { false }

end
