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

control "V-72989" do
  title "PostgreSQL must implement NIST FIPS 140-2 validated cryptographic
  modules to generate and validate cryptographic hashes."
  desc  "Use of weak or untested encryption algorithms undermines the purposes
  of utilizing encryption to protect data. The application must implement
  cryptographic modules adhering to the higher standards approved by the federal
  government since this provides assurance they have been tested and validated.
  For detailed information, refer to NIST FIPS Publication 140-2, Security
  Requirements For Cryptographic Modules. Note that the product's cryptographic
  modules must be validated and certified by NIST as FIPS-compliant."

  impact 0.7
  tag "severity": "high"
  tag "gtitle": "SRG-APP-000514-DB-000381"
  tag "gid": "V-72989"
  tag "rid": "SV-87641r1_rule"
  tag "stig_id": "PGS9-00-008000"
  tag "cci": "CCI-002450"
  tag "nist": ["SC-13", "Rev_4"]

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
