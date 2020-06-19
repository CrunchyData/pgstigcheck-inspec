control "V-72873" do
  title "PostgreSQL and associated applications must reserve the use of dynamic
  code execution for situations that require it."
  desc  "With respect to database management systems, one class of threat is
  known as SQL Injection, or more generally, code injection. It takes advantage
  of the dynamic execution capabilities of various programming languages,
  including dialects of SQL. In such cases, the attacker deduces the manner in
  which SQL statements are being processed, either from inside knowledge or by
  observing system behavior in response to invalid inputs. When the attacker
  identifies scenarios where SQL queries are being assembled by application code
  (which may be within the database or separate from it) and executed
  dynamically, the attacker is then able to craft input strings that subvert the
  intent of the query. Potentially, the attacker can gain unauthorized access to
  data, including security settings, and severely corrupt or destroy the database.
  The principal protection against code injection is not to use dynamic execution
  except where it provides necessary functionality that cannot be utilized
  otherwise. Use strongly typed data items rather than general-purpose strings
  as input parameters to task-specific, pre-compiled stored procedures and 
  functions (and triggers). This calls for inspection of application source code,
  which will require collaboration with the application developers. It is recognized
  that in many cases, the database administrator (DBA) is organizationally separate 
  from the application developers, and may have limited, if any, access to source code. 
  Nevertheless, protections of this type are so important to the secure operation of databases 
  that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from 
  the development organization that this issue has been addressed, and must document what has 
  been discovered."
  
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000251-DB-000391"
  tag "gid": "V-72873"
  tag "rid": "	SV-87545r2_rule"
  tag "stig_id": "PGS9-00-002700"
  tag "fix_id": "F-79335r2_fix"
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
  desc "check", "Review PostgreSQL source code (trigger procedures, functions)
  and application source code, to identify cases of dynamic code execution. Any
  user input should be handled through prepared statements.
  If dynamic code execution is employed in circumstances where the objective
  could practically be satisfied by static execution with strongly typed
  parameters, this is a finding."
  desc "fix", "Where dynamic code execution is employed in circumstances where
  the objective could practically be satisfied by static execution with strongly
  typed parameters, modify the code to do so."

  describe "Review PostgreSQL source code and application source code, to identify cases of dynamic code execution." do
    skip "If dynamic code execution is employed where an objective can satisfied by static execution with strongly typed parameters, this is a finding."
  end
end
