control "V-73063" do
  title "PostgreSQL must use NIST FIPS 140-2 validated cryptographic modules
  for cryptographic operations."
  desc  "Use of weak or not validated cryptographic algorithms undermines the
  purposes of utilizing encryption and digital signatures to protect data. Weak
  algorithms can be easily broken and not validated cryptographic modules may not
  implement algorithms correctly. Unapproved cryptographic modules or algorithms
  should not be relied on for authentication, confidentiality or integrity. Weak
  cryptography could allow an attacker to gain access to and modify data stored
  in the database as well as the administration settings of the DBMS.

  Applications, including DBMSs, utilizing cryptography are required to use
  approved NIST FIPS 140-2 validated cryptographic modules that meet the
  requirements of applicable federal laws, Executive Orders, directives,
  policies, regulations, standards, and guidance.

  The security functions validated as part of FIPS 140-2 for cryptographic
  modules are described in FIPS 140-2 Annex A.

  NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based
  encryption modules."

  impact 0.7
  tag "severity": "high"
  tag "gtitle": "SRG-APP-000179-DB-000114"
  tag "gid": "V-73063"
  tag "rid": "SV-87715r1_rule"
  tag "stig_id": "PGS9-00-012300"
  tag "fix_id": "F-79509r1_fix"
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
  desc "check", "As the system administrator, run the following:

  $ openssl version

  If \"fips\" is not included in the openssl version, this is a finding."
    
  desc "fix", "Configure OpenSSL to meet FIPS Compliance using the following
  documentation in section 9.1:

  http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140sp/140sp1758.pdf

  For more information on configuring PostgreSQL to use SSL, see supplementary
  content APPENDIX-G."

  if virtualization.system == 'docker'
	  describe "The docker container must have openssl to enforce encryption" do
	    skip "If \"fips\" is not included in the openssl version, this is a finding."
    end
  
  elsif virtualization.system != 'docker'
    describe command('openssl version') do
      its('stdout') { should include 'fips' }
    end
  end
end