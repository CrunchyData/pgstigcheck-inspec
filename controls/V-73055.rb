control "V-73055" do
  title "PostgreSQL must map the PKI-authenticated identity to an associated
  user account."
  desc  "The DoD standard for authentication is DoD-approved PKI certificates.
  Once a PKI certificate has been validated, it must be mapped to PostgreSQL user
  account for the authenticated identity to be meaningful to PostgreSQL and
  useful for authorization decisions."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000177-DB-000069"
  tag "gid": "V-73055"
  tag "rid": "SV-87707r1_rule"
  tag "stig_id": "PGS9-00-011800"
  tag "fix_id": "F-79501r1_fix"
  tag "cci": ["CCI-000187"]
  tag "nist": ["IA-5 (2) (c)", "Rev_4"]
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
  desc "check", "The cn (Common Name) attribute of the certificate will be
  compared to the requested database user name, and if they match the login will
  be allowed.

  To check the cn of the certificate, using openssl, do the following:

  $ openssl x509 -noout -subject -in client_cert

  If the cn does not match the users listed in PostgreSQL and no user mapping is
  used, this is a finding.

  User name mapping can be used to allow cn to be different from the database
  user name. If User Name Maps are used, run the following as the database
  administrator (shown here as \"postgres\"), to get a list of maps used for
  authentication:

  $ sudo su - postgres
  $ grep \"map\" ${PGDATA?}/pg_hba.conf

  With the names of the maps used, check those maps against the user name
  mappings in pg_ident.conf:

  $ sudo su - postgres
  $ cat ${PGDATA?}/pg_ident.conf

  If user accounts are not being mapped to authenticated identities, this is a
  finding.

  If the cn and the username mapping do not match, this is a finding."
    
  desc "fix", "Configure PostgreSQL to map authenticated identities directly to
  PostgreSQL user accounts.

  For information on configuring PostgreSQL to use SSL, see supplementary content
  APPENDIX-G."


  only_if { false }

end
