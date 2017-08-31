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

control "V-72917" do
  title "When updates are applied to PostgreSQL software, any software
  components that have been replaced or made unnecessary must be removed."
  desc  "Previous versions of PostgreSQL components that are not removed from
  the information system after updates have been installed may be exploited
  by adversaries.
  Some PostgreSQL installation tools may remove older versions of software
  automatically from the information system. In other cases, manual review and
  removal will be required. In planning installations and upgrades,
  organizations must include steps (automated, manual, or both) to identify and
  remove the outdated modules.
  A transition period may be necessary when both the old and the new software
  are required. This should be taken into account in the planning."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000454-DB-000389"
  tag "gid": "V-72917"
  tag "rid": "SV-87569r1_rule"
  tag "stig_id": "PGS9-00-004300"
  tag "cci": "CCI-002617"
  tag "nist": ["SI-2 (6)", "Rev_4"]
  tag "check": "To check software installed by packages, as the system
  administrator, run the following command:
  # RHEL/CENT Systems
  $ sudo rpm -qa | grep postgres
  If multiple versions of postgres are installed but are unused, this is a
  finding."
  tag "fix": "Use package managers (RPM or apt-get) for installing PostgreSQL.
  Unused software is removed when updated."

  only_if { false }

end
