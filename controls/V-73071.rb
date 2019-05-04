control 'V-73071' do
  title "The DBMS must be configured on a platform that has a NIST certified
        FIPS 140-2 installation of OpenSSL."
  desc  "Postgres uses OpenSSL for the underlying encryption layer. Currently only
        Red Hat Enterprise Linux is certified as a FIPS 140-2 distribution of
        OpenSSL. For other operating systems, users must obtain or build their
        own FIPS 140-2 OpenSSL libraries."
  impact 0.7

  tag "gtitle": 'SRG-APP-000179-DB-000114'
  tag "gid": 'V-73071'
  tag "rid": 'SV-87723r1_rule'
  tag "stig_id": 'PGS9-00-012800'
  tag "cci": ['CCI-000803']
  tag "nist": ['IA-7', 'Rev_4']

  tag "check": "If the deployment incorporates a custom build of the operating
      system and Postgres guaranteeing the use of FIPS 140-2 compliant OpenSSL,
      this is not a finding.

      If PostgreSQL is not installed on Red Hat Enterprise Linux (RHEL),
      this is a finding.

      If FIPS encryption is not enabled, this is a finding."

  # https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/Security_Guide/chap-Federal_Standards_and_Regulations.html

  # fips=1 kernel option to the kernel command line during system
  # installation.

  # PRELINKING=no option in the /etc/sysconfig/prelink
  # run

  # yum install dracut-fips
  # For the CPUs with the AES New Instructions (AES-NI) support, install the
  # vdracut-fips-aesni package as well:

  # in the CM:
  # To disable existing prelinking on all system files, use the
  # prelink -u -a command.

  tag "fix": "Install Postgres with FIPS-compliant cryptography enabled on RHEL;
      or by other means ensure that FIPS 140-2 certified OpenSSL libraries are
      used by the DBMS."

  only_if { false }
end
