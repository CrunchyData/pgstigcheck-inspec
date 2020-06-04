control "V-73053" do
  title "PostgreSQL must prevent non-privileged users from executing privileged
  functions, to include disabling, circumventing, or altering implemented
  security safeguards/countermeasures."
  desc  "Preventing non-privileged users from executing privileged functions
  mitigates the risk that unauthorized individuals or processes may gain
  unnecessary access to information or privileges.

  System documentation should include a definition of the functionality
  considered privileged.

  Depending on circumstances, privileged functions can include, for example,
  establishing accounts, performing system integrity checks, or administering
  cryptographic key management activities. Non-privileged users are individuals
  that do not possess appropriate authorizations. Circumventing intrusion
  detection and prevention mechanisms or malicious code protection mechanisms are
  examples of privileged functions that require protection from non-privileged
  users.

  A privileged function in PostgreSQL/database context is any operation that
  modifies the structure of the database, its built-in logic, or its security
  settings. This would include all Data Definition Language (DDL) statements and
  all security-related statements. In an SQL environment, it encompasses, but is
  not necessarily limited to:

      CREATE
      ALTER
      DROP
      GRANT
      REVOKE

      There may also be Data Manipulation Language (DML) statements that, subject
  to context, should be regarded as privileged. Possible examples include:

      TRUNCATE TABLE;
      DELETE, or
      DELETE affecting more than n rows, for some n, or
      DELETE without a WHERE clause;

      UPDATE or
      UPDATE affecting more than n rows, for some n, or
      UPDATE without a WHERE clause;

      any SELECT, INSERT, UPDATE, or DELETE to an application-defined security
  table executed by other than a security principal.

  Depending on the capabilities of PostgreSQL and the design of the database
  and associated applications, the prevention of unauthorized use of privileged
  functions may be achieved by means of DBMS security features, database
  triggers, other mechanisms, or a combination of these.

  However, the use of procedural languages within PostgreSQL, such as pl/R
  and pl/Python, introduce security risk. Any user on the PostgreSQL who is
  granted access to pl/R or pl/Python is able to run UDFs to escalate privileges
  and perform unintended functions. Procedural languages such as pl/Perl and
  pl/Java have \"untrusted\" mode of operation, which do not allow a
  non-privileged PostgreSQL user to escalate privileges or perform actions as a
  database administrator."

  impact 0.7
  tag "severity": "high"
  tag "gtitle": "SRG-APP-000340-DB-000304"
  tag "gid": "V-73053"
  tag "rid": "SV-87705r1_rule"
  tag "stig_id": "PGS9-00-011700"
  tag "fix_id": "F-79499r1_fix"
  tag "cci": ["CCI-002235"]
  tag "nist": ["AC-6 (10)", "Rev_4"]
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
  desc "check", "Review the system documentation to obtain the definition of the
  PostgreSQL functionality considered privileged in the context of the system in
  question.

  Review the PostgreSQL security configuration and/or other means used to protect
  privileged functionality from unauthorized use.

  If the configuration does not protect all of the actions defined as privileged,
  this is a finding.

  If PostgreSQL instance uses procedural languages, such as pl/Python or pl/R,
  without AO authorization, this is a finding."
  
  desc "fix", "Configure PostgreSQL security to protect all privileged
  functionality.

  If pl/R and pl/Python are used, document their intended use, document users
  that have access to pl/R and pl/Python, as well as their business use case,
  such as data-analytics or data-mining. Because of the risks associated with
  using pl/R and pl/Python, their use must have AO risk acceptance.
  
  To remove unwanted extensions, use:
  
  DROP EXTENSION <extension_name>
  
  To remove unwanted privileges from a role, use the REVOKE command.
  
  See the PostgreSQL documentation for more details:
  http://www.postgresql.org/docs/current/static/sql-revoke.html"

  describe "Skip Test" do
    skip "This is a manual check"
  end
end
