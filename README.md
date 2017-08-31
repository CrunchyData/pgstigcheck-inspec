# PostgreSQL STIG Compliance Testing Solution

PostgreSQL STIG Compliance Testing Solution (pgStigCheck) for InSpec is an Open Source Compliance Testing Solution for PostgreSQL.  

Developed in order to reduce the time it takes to secure authority to operate certification for cloud services, the technology leverages open source software to provide automated compliance testing in real time.  The pgStigCheck for InSpec project specifically uses the InSpec Project, which provides an open source compliance, security and policy testing framework, to dynamically extract system configuration information.

Additional information regarding InSpec is available here: https://github.com/chef/inspec

# PostgreSQL STIG Overview

The PostgreSQL Security Technical Implementation Guide (STIG) by the United States Defense Information Systems Agency (DISA) offers security-conscious enterprises a comprehensive guide for the configuration and operation of open source PostgreSQL.

STIGs are the configuration standards for United States Department of Defense (DoD) Information Assurance (IA) and IA-enabled devices/systems published by the United States Defense Information Systems Agency (DISA). Since 1998, DISA has played a critical role enhancing the security posture of DoD's security systems by providing the STIGs. The STIGs contain technical guidance to “lock down” information systems/software that might otherwise be vulnerable to a malicious computer attack.

The requirements associated with the PostgreSQL STIG are derived from the National Institute of Standards and Technology (NIST) Special Publication (SP) 800-53, Revision 4 and related documents.  While the PostgreSQL STIG is intended to provide technical guidance to “lock down” information systems/software used within the DoD, generally speaking the guidance provided it is not specific to the DoD and Crunchy Data believes the guidance provided is generally applicable to security conscious enterprises.

The PostgreSQL STIG provides guidance on the configuration of PostgreSQL to address requirements associated with:

    Auditing
    Logging
    Data Encryption at Rest
    Data Encryption Over the Wire
    Access Controls
    Administration
    Authentication
    Protecting against SQL Injection

# Getting Started

## Requirements

### Database Host
- PostgreSQL 9.5 Cluster running on *nix host
- Remote access to PostgreSQL Server
- lsof
- netstat

### STIG Validation Execution Host
- Linux VM or Host
- sudo access to install packages

### Required software on STIG Validation Execution Host
- git
- ssh
- ruby using rvm
- InSpec

## Setup Environment on STIG Validation Execution Host
### Install ruby using rvm
```
$ curl -sSL https://rvm.io/mpapis.asc | gpg2 --import -
$ curl -L get.rvm.io | bash -s stable
$ rvm install 2.4.0
$ rvm use 2.4 --default
```

### Install the needed gems  
```
gem install inspec
```

### Ensure your InSpec version is at least 1.31.x
```
inspec --version
```

## Setting attributes.xml

### OS Group, User and Password
```
pg_owner: 'postgres'
pg_group: 'postgres'
pg_owner_password: '<my secret password>'
```
### DBA User and Password
```
pg_dba: '<dba username'
pg_dba_password: '<my dba password>'
```
### Normal DB User and Password
```
pg_user: '<username>'
pg_user_password: '<my password>'
```
### DB Host and Port
```
pg_host: '127.0.0.1'
pg_port: '5432'
```
### DB Name and Test table
```
pg_db: 'test_db'
pg_table: 'test_table'
```

### Misc settings
```
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


## Validating your box
see: https://www.inspec.io/docs/reference/cli/

### Execute a single Control in the Profile
note: replace the profile's directory name - e.g. - `postgresql-stig-insepc` with `.` if you are in the profile's root directory.
```
$ inspec exec postgresql-stig-inspec/controls/V-72845.rb --attrs attributes.yml -i <your ssh private key>  -t ssh://<user>@<db host>:<port>
```
or use the `--controls` flag
```
$ inspec exec postgresql-stig-inspec --controls=V-72845 V-72861 --attrs attributes.yml  -i <your ssh private key>  -t ssh://<user>@<db host>:<port>
```

### Execute a Single Control and save results as HTML
```
$ inspec exec postgresql-stig-insepc --controls=V-72845 --attrs attributes.yml -i <your ssh private key> --sudo --sudo-options="-u postgres" -t ssh://<user>@<db host>:<port> | ./tools/ansi2html.sh --bg=dark > inspec-report.html
```

> When executing all the Controls, InSpec will generate warning ```already initialized constant #<Class:0x000000.......>::<Attribuet Name>```, it is safe to ignore it. We are working with InSpec upstream to get it fixed.

### Execute All Controls in the Profile
```
inspec exec postgresql-stig-inspec --attrs attributes.yml -i <your ssh private key> --sudo --sudo-options="-u postgres"  -t ssh://<user>@<db host>:<port>
```

### Execute all the Controls in the Profile and save results as HTML
```
inspec exec postgresql-stig-inspec --attrs attributes.yml -i <your ssh private key> --sudo --sudo-options="-u postgres" -t ssh://<user>@<db host>:<port> | ./tools/ansi2html.sh --bg=dark > inspec-report.html
```
