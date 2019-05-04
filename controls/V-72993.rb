# @todo this entire test appears to be identical and a duplicate of V-72989.
# If so, delete this test.

control 'V-72993' do
  title "PostgreSQL must implement NIST FIPS 140-2 validated cryptographic modules
to protect unclassified information requiring confidentiality and cryptographic
protection, in accordance with the data owners requirements."
  desc  "Use of weak or untested encryption algorithms undermines the purposes of
utilizing encryption to protect data. The application must implement cryptographic
modules adhering to the higher standards approved by the federal government since
this provides assurance they have been tested and validated.

It is the responsibility of the data owner to assess the cryptography requirements
in light of applicable federal laws, Executive Orders, directives, policies,
regulations, and standards.

For detailed information, refer to NIST FIPS Publication 140-2, Security
Requirements For Cryptographic Modules. Note that the product's cryptographic
modules must be validated and certified by NIST as FIPS-compliant."

  impact 0.7

  tag "gtitle": 'SRG-APP-000514-DB-000383'
  tag "gid": 'V-72993'
  tag "rid": 'SV-87645r1_rule'
  tag "stig_id": 'PGS9-00-008200'
  tag "cci": ['CCI-002450']
  tag "nist": ['SC-13', 'Rev_4']

  tag "check": "First, as the system administrator, run the following to see if FIPS
is enabled:

$ cat /proc/sys/crypto/fips_enabled

If fips_enabled is not 1, this is a finding."

  tag "fix": "Configure OpenSSL to be FIPS compliant.

PostgreSQL uses OpenSSL for cryptographic modules. To configure OpenSSL to be FIPS
140-2 compliant, see the official RHEL Documentation:
https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Securit
y_Guide/sect-Security_Guide-Federal_Standards_And_Regulations-Federal_Information_Pro
cessing_Standard.html

For more information on configuring PostgreSQL to use SSL, see supplementary content
APPENDIX-G."

  describe kernel_parameter('crypto.fips_enabled') do
    its('value') { should cmp 1 }
  end
end
