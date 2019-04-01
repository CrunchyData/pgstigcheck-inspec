# PostgreSQL STIG Compliance Validator

PostgreSQL STIG Compliance Validator (pgStigCheck) for InSpec is an open source compliance testing solution for PostgreSQL.

Developed in order to reduce the time it takes to secure authority to operate (ATO) certification for cloud services, pgStickCheck technology leverages open source software to provide automated compliance testing in real time.  pgStigCheck uses the [InSpec](https://github.com/chef/inspec), which provides an open source compliance, security and policy testing framework that dynamically extracts system configuration information.

## PostgreSQL STIG Overview

The [PostgreSQL Security Technical Implementation Guide](https://www.crunchydata.com/postgres-stig/PGSQL-STIG-9.5+.pdf) (STIG) by the United States Defense Information Systems Agency (DISA) offers security-conscious enterprises a comprehensive guide for the configuration and operation of open source PostgreSQL.

[STIG](https://en.wikipedia.org/wiki/Security_Technical_Implementation_Guide)s are the configuration standards for United States Department of Defense (DoD) Information Assurance (IA) and IA-enabled devices/systems published by the United States Defense Information Systems Agency (DISA). Since 1998, DISA has played a critical role enhancing the security posture of DoD's security systems by providing the STIGs. The STIGs contain technical guidance to "lock down" information systems/software that might otherwise be vulnerable to a malicious computer attack.

The requirements associated with the PostgreSQL STIG are derived from the [National Institute of Standards and Technology](https://en.wikipedia.org/wiki/National_Institute_of_Standards_and_Technology) (NIST) [Special Publication (SP) 800-53, Revision 4](https://en.wikipedia.org/wiki/NIST_Special_Publication_800-53) and related documents.

While the PostgreSQL STIG was developed to provide technical guidance to "lock down" information systems used within the DoD, the guidance applies to all organizations that need to meet internal security as well as compliance standards.

The PostgreSQL STIG provides guidance on the configuration of PostgreSQL to address requirements associated with:

- Authentication
- Access Controls
- Data encryption at rest and over the wire
- Auditing
- Logging
- Administration
- Protection against SQL Injection

## Getting Started

### Requirements

To run the PostgreSQL STIG Compliance Validator, there are specific requirements on both the database host as will as the STIG valudation host.

#### Database Host
- PostgreSQL 9.5+ cluster running on \*nix host
- Remote access to PostgreSQL Server
- lsof
- netstat

#### STIG Validation Execution Host
- Linux VM or Host
- sudo access to install packages

#### Required software on STIG Validation Execution Host
- git
- ssh
- ruby using rvm
- [InSpec](https://github.com/chef/inspec)

### Setup Environment on STIG Validation Execution Host
#### Install ruby using rvm
```sh
$ curl -sSL https://rvm.io/mpapis.asc | gpg2 --import -
$ curl -L get.rvm.io | bash -s stable
$ rvm install 2.4.0
$ rvm use 2.4 --default
```

#### Install the needed gems  
```sh
gem install inspec
```

#### Ensure your InSpec version is at least 1.31.x
```sh
inspec --version
```

### Setting attributes.yml

#### OS Group, User and Password
```yaml
pg_owner: 'postgres'
pg_group: 'postgres'
pg_owner_password: '<my secret password>'
```
#### DBA User and Password
```yaml
pg_dba: '<dba username'
pg_dba_password: '<my dba password>'
```
#### Normal DB User and Password
```yaml
pg_user: '<username>'
pg_user_password: '<my password>'
```
#### DB Host and Port
```yaml
pg_host: '127.0.0.1'
pg_port: '5432'
```
#### DB Name and Test table
```yaml
pg_db: 'test_db'
pg_table: 'test_table'
```

#### Misc settings
```yaml
login_user: '<user on remote DB server>'
login_host: '<DB Host IP>'

pg_version: '9.5'

pg_data_dir: "/var/lib/pgsql/9.5/data"
pg_conf_file: "/var/lib/pgsql/9.5/data/postgresql.conf"
pg_user_defined_conf: "/var/lib/pgsql/9.5/data/stig-postgresql.conf"
pg_hba_conf_file: "/var/lib/pgsql/9.5/data/pg_hba.conf"
pg_ident_conf_file: "/var/lib/pgsql/9.5/data/pg_ident.conf"

pg_shared_dirs: [
  "/usr/pgsql-9.5",
  "/usr/pgsql-9.5/bin",
  "/usr/pgsql-9.5/lib",
  "/usr/pgsql-9.5/share"
  ]

pg_conf_mode: '0600'
pg_ssl: 'on'
pg_log_dest: 'syslog'
pg_syslog_facility: ['local0']
pg_syslog_owner: 'postgres'

pgaudit_log_items: ['ddl','role','read','write']
pgaudit_log_line_items: ['%m','%u','%c']

pg_superusers: [
  'postgres',
  ]

pg_users: [
  '',
  ]

pg_replicas: [
  '192.168.1.3/32',
  ]

pg_max_connections: '100'

pg_timezone: 'UTC'

```


### Validating Your PostgreSQL Instance
(See: https://www.inspec.io/docs/reference/cli/)

#### Execute a single Control in the Profile
**Note**: replace the profile's directory name - e.g. - `pgstigcheck-inspec` with `.` if you are in the profile's root directory.
```sh
inspec exec pgstigcheck-inspec/controls/V-72845.rb --attrs attributes.yml -i <your ssh private key>  -t ssh://<user>@<db host>:<port>
```
or use the `--controls` flag
```sh
inspec exec pgstigcheck-inspec --controls=V-72845 V-72861 --attrs attributes.yml  -i <your ssh private key>  -t ssh://<user>@<db host>:<port>
```

#### Execute a Single Control and save results as HTML
```sh
inspec exec pgstigcheck-inspec --controls=V-72845 --attrs attributes.yml -i <your ssh private key> --sudo --sudo-options="-u postgres" -t ssh://<user>@<db host>:<port> | ./tools/ansi2html.sh --bg=dark > inspec-report.html
```

> When executing all the Controls, InSpec will generate warning ```already initialized constant #<Class:0x000000.......>::<Attribuet Name>```, it is safe to ignore it. We are working with InSpec upstream to get it fixed.

#### Execute All Controls in the Profile
```sh
inspec exec pgstigcheck-inspec --attrs attributes.yml -i <your ssh private key> --sudo --sudo-options="-u postgres"  -t ssh://<user>@<db host>:<port>
```

#### Execute all the Controls in the Profile and save results as HTML
```sh
inspec exec pgstigcheck-inspec --attrs attributes.yml -i <your ssh private key> --sudo --sudo-options="-u postgres" -t ssh://<user>@<db host>:<port> | pgstigcheck-inspec/tools/ansi2html.sh --bg=dark > inspec-report.html
```

## Sponsors

[![Crunchy Data](/hugo/static/images/crunchy_logo.png)](https://www.crunchydata.com/)

[Crunchy Data](https://www.crunchydata.com/) is pleased to sponsor pgSTIGcheck-inspec and many other [open-source projects](https://github.com/CrunchyData/) to help promote support the PostgreSQL community and software ecosystem.

---

## Legal Notices

Copyright © 2019 Crunchy Data Solutions, Inc.

CRUNCHY DATA SOLUTIONS, INC. PROVIDES THIS GUIDE "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF NON INFRINGEMENT, MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.

Crunchy, Crunchy Data Solutions, Inc. and the Crunchy Hippo Logo are trademarks of Crunchy Data Solutions, Inc.
