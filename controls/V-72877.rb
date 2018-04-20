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

control "V-72877" do
  title "PostgreSQL must allocate audit record storage capacity in accordance
  with organization-defined audit record storage requirements."
  desc  "In order to ensure sufficient storage capacity for the audit logs,
  PostgreSQL must be able to allocate audit record storage capacity. Although
  another requirement (SRG-APP-000515-DB-000318) mandates that audit data be
  off-loaded to a centralized log management system, it remains necessary to
  provide space on the database server to serve as a buffer against outages and
  capacity limits of the off-loading mechanism.
  The task of allocating audit record storage capacity is usually performed
  during initial installation of PostgreSQL and is closely associated with the
  DBA and system administrator roles. The DBA or system administrator will
  usually coordinate the allocation of physical drive space with the application
  owner/installer and the application will prompt the installer to provide the
  capacity information, the physical location of the disk, or both.
  In determining the capacity requirements, consider such factors as: total
  number of users; expected number of concurrent users during busy periods;
  number and type of events being monitored; types and amounts of data being
  captured; the frequency/speed with which audit records are off-loaded to the
  central log management system; and any limitations that exist on PostgreSQL's
  ability to reuse the space formerly occupied by off-loaded records."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000357-DB-000316"
  tag "gid": "V-72877"
  tag "rid": "SV-87529r1_rule"
  tag "stig_id": "PGS9-00-002100"
  tag "cci": ["CCI-001849"]
  tag "nist": ["AU-4", "Rev_4"]
  tag "check": "Investigate whether there have been any incidents where
  PostgreSQL ran out of audit log space since the last time the space was
  allocated or other corrective measures were taken.
  If there have been incidents where PostgreSQL ran out of audit log space,
  this is a finding."
  tag "fix": "Allocate sufficient audit file/table space to support peak demand."

  only_if { false }
  
end
