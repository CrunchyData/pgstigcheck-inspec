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

control "V-72903" do
  title "PostgreSQL must include additional, more detailed, organization-defined
  information in the audit records for audit events identified by type,
  location, or subject."
  desc  "Information system auditing capability is critical for accurate
  forensic analysis. Reconstruction of harmful events or forensic analysis is
  not possible if audit records do not contain enough information. To support
  analysis, some types of events will need information to be logged that
  exceeds the basic requirements of event type, time stamps, location, source,
  outcome, and user identity. If additional information is not available, it
  could negatively impact forensic investigations into user actions or other
  malicious events.
  The organization must determine what additional information is required for
  complete analysis of the audited events. The additional information required
  is dependent on the type of information (e.g., sensitivity of the data and
  the environment within which it resides). At a minimum, the organization
  must employ either full-text recording of privileged commands or the
  individual identities of users of shared accounts, or both. The organization
  must maintain audit trails in sufficient detail to reconstruct events to
  determine the cause and impact of compromise.
  Examples of detailed information the organization may require in audit
  records are full-text recording of privileged commands or the individual
  identities of shared account users."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000101-DB-000044"
  tag "gid": "V-72903"
  tag "rid": "SV-87555r1_rule"
  tag "stig_id": "PGS9-00-003500"
  tag "cci": "CCI-000135"
  tag "nist": ["AU-3 (1)", "Rev_4"]
  tag "check": "Review the system documentation to identify what additional
  information the organization has determined necessary.
  Check PostgreSQL settings and existing audit records to verify that all
  organization-defined additional, more detailed information is in the audit
  records for audit events identified by type, location, or subject.
  If any additional information is defined and is not contained in the audit
  records, this is a finding."
  tag "fix": "Configure PostgreSQL audit settings to include all
  organization-defined detailed information in the audit records for audit
  events identified by type, location, or subject.
  Using pgaudit PostgreSQL can be configured to audit these requests. See
  supplementary content APPENDIX-B for documentation on installing pgaudit.
  To ensure that logging is enabled, review supplementary content APPENDIX-C for
  instructions on enabling logging."

  only_if { false }

end
