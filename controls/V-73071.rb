control "V-73071" do
  title "The DBMS must be configured on a platform that has a NIST certified
  FIPS 140-2 installation of OpenSSL."
  desc  "PostgreSQL uses OpenSSL for the underlying encryption layer. It must
  be installed on an operating system that contains a certified FIPS 140-2
  distribution of OpenSSL. For other operating systems, users must obtain or
  build their own FIPS 140-2 OpenSSL libraries."
  
  impact 0.7
  tag "severity": "high"
  tag "gtitle": "SRG-APP-000179-DB-000114"
  tag "gid": "V-73071"
  tag "rid": "SV-87723r3_rule"
  tag "stig_id": "PGS9-00-012800"
  tag "fix_id": "F-79517r4_fix"
  tag "cci": ["CCI-000803"]
  tag "nist": ["IA-7", "Rev_4"]
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
  desc "check", "If the deployment incorporates a custom build of the operating
  system and PostgreSQL guaranteeing the use of FIPS 140-2- compliant OpenSSL,
  this is not a finding.
  Go to the below webpage and click \"show all\":
  https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search
  Note: Certificates 3130, 3016, and 2441 are the most common.
  If the OS is not using a FIPS 140-2 certified implementation that is listed,
  this is a finding.

  If FIPS encryption is not enabled, this is a finding."

  desc "fix", "Install PostgreSQL on an operating system with FIPS-compliant
  cryptography enabled; or by other means ensure that FIPS 140-2-certified
  OpenSSL libraries are used by the DBMS."

  describe "Skip Test" do
    skip "This is a manual check"
  end
end
