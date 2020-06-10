control "V-72871" do
  title "PostgreSQL must check the validity of all data inputs except those
  specifically identified by the organization."
  desc  "Invalid user input occurs when a user inserts data or characters into
  an application's data entry fields and the application is unprepared to process
  that data. This results in unanticipated application behavior, potentially
  leading to an application or information system compromise. Invalid user input
  is one of the primary methods employed when attempting to compromise an
  application.

  With respect to database management systems, one class of threat is known
  as SQL Injection, or more generally, code injection. It takes advantage of the
  dynamic execution capabilities of various programming languages, including
  dialects of SQL. Potentially, the attacker can gain unauthorized access to
  data, including security settings, and severely corrupt or destroy the database.

  Even when no such hijacking takes place, invalid input that gets recorded
  in the database, whether accidental or malicious, reduces the reliability and
  usability of the system. Available protections include data types, referential
  constraints, uniqueness constraints, range checking, and application-specific
  logic. Application-specific logic can be implemented within the database in
  stored procedures and triggers, where appropriate.

  This calls for inspection of application source code, which will require
  collaboration with the application developers. It is recognized that in many
  cases, the database administrator (DBA) is organizationally separate from the
  application developers, and may have limited, if any, access to source code.
  Nevertheless, protections of this type are so important to the secure operation
  of databases that they must not be ignored. At a minimum, the DBA must attempt
  to obtain assurances from the development organization that this issue has been
  addressed, and must document what has been discovered."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000251-DB-000160"
  tag "gid": "V-72871"
  tag "rid": "SV-87523r1_rule"
  tag "stig_id": "PGS9-00-001800"
  tag "fix_id": "F-79313r1_fix"
  tag "cci": ["CCI-001310"]
  tag "nist": ["SI-10", "Rev_4"]
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
  desc "check", "Review PostgreSQL code (trigger procedures, functions),
  application code, settings, column and field definitions, and constraints to
  determine whether the database is protected against invalid input.

  If code exists that allows invalid data to be acted upon or input into the
  database, this is a finding.

  If column/field definitions do not exist in the database, this is a finding.

  If columns/fields do not contain constraints and validity checking where
  required, this is a finding.

  Where a column/field is noted in the system documentation as necessarily
  free-form, even though its name and context suggest that it should be strongly
  typed and constrained, the absence of these protections is not a finding.

  Where a column/field is clearly identified by name, caption or context as
  Notes, Comments, Description, Text, etc., the absence of these protections is
  not a finding.

  Check application code that interacts with PostgreSQL for the use of prepared
  statements. If prepared statements are not used, this is a finding."

  desc "fix", "Modify database code to properly validate data before it is put
  into the database or acted upon by the database.

  Modify the database to contain constraints and validity checking on database
  columns and tables that require them for data integrity.

  Use prepared statements when taking user input.

  Do not allow general users direct console access to PostgreSQL."

  describe "Skip Test" do
    skip "This is a manual check"
  end
end
