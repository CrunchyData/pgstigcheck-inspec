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

control "V-73023" do
  title "The system must provide a warning to appropriate support staff when
allocated audit record storage volume reaches 75% of maximum audit record storage
capacity."
  desc  "Organizations are required to use a central log management system, so,
under normal conditions, the audit space allocated to PostgreSQL on its own server
will not be an issue. However, space will still be required on PostgreSQL server for
audit records in transit, and, under abnormal conditions, this could fill up. Since
a requirement exists to halt processing upon audit failure, a service outage would
result.

If support personnel are not notified immediately upon storage volume utilization
reaching 75%, they are unable to plan for storage capacity expansion.

The appropriate support staff include, at a minimum, the ISSO and the DBA/SA."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000359-DB-000319"
  tag "gid": "V-73023"
  tag "rid": "SV-87675r1_rule"
  tag "stig_id": "PGS9-00-009900"
  tag "cci": "CCI-001855"
  tag "nist": ["AU-5 (1)", "Rev_4"]
  tag "check": "Review system configuration.

If no script/tool is monitoring the partition for the PostgreSQL log directories,
this is a finding.

If appropriate support staff are not notified immediately upon storage volume
utilization reaching 75%, this is a finding."
  tag "fix": "Configure the system to notify appropriate support staff immediately
upon storage volume utilization reaching 75%.

PostgreSQL does not monitor storage, however, it is possible to monitor storage with
a script.

##### Example Monitoring Script

#!/bin/bash

PGDATA=/var/lib/psql/9.5/data
CURRENT=$(df ${PGDATA?} | grep / | awk '{ print $5}' | sed 's/%//g')
THRESHOLD=75

if [ \"$CURRENT\" -gt \"$THRESHOLD\" ] ; then
mail -s 'Disk Space Alert' mail@support.com << EOF
The data directory volume is almost full. Used: $CURRENT
%EOF
fi

Schedule this script in cron to run around the clock."

  only_if { false }
  
end
