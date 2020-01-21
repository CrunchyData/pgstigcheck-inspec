control "V-72861" do
  title "PostgreSQL must associate organization-defined types of security
  labels having organization-defined security label values with information in
  transmission."
  desc  "Without the association of security labels to information, there is no
  basis for PostgreSQL to make security-related access-control decisions.

  Security labels are abstractions representing the basic properties or
  characteristics of an entity (e.g., subjects and objects) with respect to
  safeguarding information.

  These labels are typically associated with internal data structures (e.g.,
  tables, rows) within the database and are used to enable the implementation of
  access control and flow control policies, reflect special dissemination,
  handling or distribution instructions, or support other aspects of the
  information security policy.

  One example includes marking data as classified or FOUO. These security
  labels may be assigned manually or during data processing, but, either way, it
  is imperative these assignments are maintained while the data is in storage. If
  the security labels are lost when the data is stored, there is the risk of a
  data compromise."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000314-DB-000310"
  tag "gid": "V-72861"
  tag "rid": "SV-87513r1_rule"
  tag "stig_id": "PGS9-00-001100"
  tag "fix_id": "F-79303r2_fix"
  tag "cci": ["CCI-002264"]
  tag "nist": ["AC-16 a", "Rev_4"]
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
  desc "check", "If security labeling is not required, this is not a finding.

  First, as the database administrator (shown here as \"postgres\"), run the
  following SQL against each table that requires security labels:

  $ sudo su - postgres
  $ psql -c \"\\d+ <schema_name>.<table_name>\"

  If security labeling is required and the results of the SQL above do not show a
  policy attached to the table, this is a finding.

  If security labeling is required and not implemented according to the system
  documentation, such as SSP, this is a finding.

  If security labeling requirements have been specified, but the security
  labeling is not implemented or does not reliably maintain labels on information
  in storage, this is a finding."

  desc "fix", "In addition to the SQL-standard privilege system available through
  GRANT, tables can have row security policies that restrict, on a per-user
  basis, which rows can be returned by normal queries or inserted, updated, or
  deleted by data modification commands. This feature is also known as Row-Level
  Security(RLS).

  RLS policies can be very different depending on their use case. For one example
  of using RLS for Security Labels, see supplementary content APPENDIX-D."

  only_if { false }

end
