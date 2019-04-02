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
pg_owner = attribute(
  'pg_owner',
  description: "The system user of the postgres process",
)

pg_group = attribute(
  'pg_group',
  description: "The system group of the postgres process",
)

pg_dba = attribute(
  'pg_dba',
  description: 'The postgres DBA user to access the test database',
)

pg_dba_password = attribute(
  'pg_dba_password',
  description: 'The password for the postgres DBA user',
)

pg_db = attribute(
  'pg_db',
  description: 'The database used for tests',
)

pg_host = attribute(
  'pg_host',
  description: 'The hostname or IP address used to connect to the database',
)

pg_port = attribute(
  'pg_port',
  description: 'The port used to connect to the database',
)

pg_data_dir = attribute(
  'pg_data_dir',
  description: 'The postgres data directory',
)

pg_conf_file = attribute(
  'pg_conf_file',
  description: 'The postgres configuration file',
)

pg_user_defined_conf = attribute(
  'pg_user_defined_conf',
  description: 'An additional postgres configuration file used to override default values',
)

pg_superusers = attribute(
  'pg_superusers',
  description: 'Authorized superuser accounts',
)

pg_version = attribute(
  'pg_version',
  description: "The version of postgres",
)

pg_shared_dirs = attribute(
  'pg_shared_dirs',
  description: 'defines the locations of the postgresql shared library directories',
)

control "V-73063" do
  title "PostgreSQL must use NIST FIPS 140-2 validated cryptographic modules for
        cryptographic operations."
  desc  "Use of weak or not validated cryptographic algorithms undermines the
        purposes of utilizing encryption and digital signatures to protect data.
        Weak algorithms can be easily broken and not validated cryptographic
        modules may not implement algorithms correctly. Unapproved cryptographic
        modules or algorithms should not be relied on for authentication,
        confidentiality or integrity. Weak cryptography could allow an attacker
        to gain access to and modify data stored in the database as well as the
        administration settings of the DBMS.

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
  tag "cci": ["CCI-000803"]
  tag "nist": ["IA-7", "Rev_4"]

  tag "check": "As the system administrator, run the following:

      $ openssl version
      If \"fips\" is not included in the openssl version, this is a finding."

  tag "fix": "Configure OpenSSL to meet FIPS Compliance using the following
      documentation in section 9.1:

      http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140sp/140sp1758.pdf

      For more information on configuring PostgreSQL to use SSL, see supplementary
      content APPENDIX-G."

  only_if do
    command('openssl').exist?
  end

  describe command('openssl version') do
    its('stdout') { should include 'fips' }
  end
end
