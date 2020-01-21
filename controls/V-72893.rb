control "V-72893" do
  title "PostgreSQL must provide an immediate real-time alert to appropriate
  support staff of all audit failure events requiring real-time alerts."
  desc  "It is critical for the appropriate personnel to be aware if a system
  is at risk of failing to process audit logs as required. Without a real-time
  alert, security personnel may be unaware of an impending failure of the audit
  capability, and system operation may be adversely affected.

  The appropriate support staff include, at a minimum, the ISSO and the
  DBA/SA.

  Alerts provide organizations with urgent messages. Real-time alerts provide
  these messages immediately (i.e., the time from event detection to alert occurs
  in seconds or less).

  The necessary monitoring and alerts may be implemented using features of
  PostgreSQL, the OS, third-party software, custom code, or a combination of
  these. The term \"the system\" is used to encompass all of these."

  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-APP-000360-DB-000320"
  tag "gid": "V-72893"
  tag "rid": "SV-87545r1_rule"
  tag "stig_id": "PGS9-00-002700"
  tag "fix_id": "F-79335r1_fix"
  tag "cci": ["CCI-001858"]
  tag "nist": ["AU-5 (2)", "Rev_4"]
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
  desc "check", "Review the system documentation to determine which audit failure
  events require real-time alerts.

  Review the system settings and code. If the real-time alerting that is
  specified in the documentation is not enabled, this is a finding."
  
  desc "fix", "Configure the system to provide an immediate real-time alert to
  appropriate support staff when a specified audit failure occurs.

  It is possible to create scripts or implement third-party tools to enable
  real-time alerting for audit failures in PostgreSQL."

  only_if { false }

end
