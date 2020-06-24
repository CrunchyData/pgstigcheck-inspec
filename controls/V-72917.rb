pg_version = input('pg_version')
approved_packages = input('approved_packages')

control "V-72917" do
  title "When updates are applied to PostgreSQL software, any software
  components that have been replaced or made unnecessary must be removed."
  desc  "Previous versions of PostgreSQL components that are not removed from
  the information system after updates have been installed may be exploited by
  adversaries.

  Some PostgreSQL installation tools may remove older versions of software
  automatically from the information system. In other cases, manual review and
  removal will be required. In planning installations and upgrades, organizations
  must include steps (automated, manual, or both) to identify and remove the
  outdated modules.

  A transition period may be necessary when both the old and the new software
  are required. This should be taken into account in the planning."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000454-DB-000389"
  tag "gid": "V-72917"
  tag "rid": "SV-87569r1_rule"
  tag "stig_id": "PGS9-00-004300"
  tag "fix_id": "F-79361r1_fix"
  tag "cci": ["CCI-002617"]
  tag "nist": ["SI-2 (6)", "Rev_4"]
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
  desc "check", "To check software installed by packages, as the system
  administrator, run the following command:

  # RHEL/CENT Systems
  $ sudo rpm -qa | grep postgres

  If multiple versions of postgres are installed but are unused, this is a
  finding."

  desc "fix", "Use package managers (RPM or apt-get) for installing PostgreSQL.
  Unused software is removed when updated."

  if os.debian?
    dpkg_packages = command("apt list --installed | grep \"postgres\"").stdout.split("\n")
    dpkg_packages.each do |packages|
      describe(packages) do
        it { should match pg_version }
      end
    end

  elsif os.linux? || os.redhat?
    rpm_packages = command("rpm -qa | grep \"postgres\"").stdout.split("\n")

    rpm_packages.each do |packages|
      describe(packages) do
        it { should match pg_version }
      end
    end
  end
end
