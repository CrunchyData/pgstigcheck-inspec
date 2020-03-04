# PostgreSQL STIG Compliance Validator

PostgreSQL STIG Compliance Validator (pgStigCheck) for InSpec is an open source compliance testing solution for PostgreSQL.

Developed in order to reduce the time it takes to secure Authority to Operate (ATO) certification for cloud services, pgStickCheck technology leverages open source software to provide automated compliance testing in real time. pgStigCheck uses the [InSpec](https://github.com/chef/inspec), which provides an open source compliance, security and policy testing framework that dynamically extracts system configuration information.

STIG Baseline: **PostgreSQL 9.x STIG Version 1, Release 6**

## PostgreSQL STIG Overview

The PostgreSQL Security Technical Implementation Guide (STIG) by the United States Defense Information Systems Agency (DISA) offers security-conscious enterprises a comprehensive guide for the configuration and operation of open source PostgreSQL. 

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
- [InSpec](https://www.chef.io/products/chef-inspec/)

### Setup Environment on STIG Validation Execution Host

#### Install InSpec via your System Package Manager (recommended)

The InSpec community and chef provide packages for all major platforms. The installation package will bring all needed libraries and components needed by InSpec.

This is recommended for production and LTS environments.

Goto <https://downloads.chef.io/inspec/stable> and copy download link

For example:

- <https://packages.chef.io/files/stable/inspec/4.18.51/el/7/inspec-4.18.51-1.el7.x86_64.rpm>


```sh
sudo yum insall https://packages.chef.io/files/stable/inspec/4.18.51/el/7/inspec-4.18.51-1.el7.x86_64.rpm
```

#### Ensure InSpec Installed and is 4.x or higher

```sh
inspec --version
```

#### Install InSpec via GEM and RVM (alternative)

If you already have an existing Ruby environment configured on your system, or use RVM to manage your Ruby environments, you can always just install the InSpec gem and its dependencies using GEM.

```sh
$ curl -sSL https://rvm.io/mpapis.asc | gpg2 --import -
$ curl -sSL https://rvm.io/pkuczynski.asc | gpg2 --import -
$ curl -L get.rvm.io | bash -s stable
$ rvm install 2.4.0
$ rvm use 2.4.0 --default

$ source ${HOME}/.rvm/scripts/rvm
```

#### Install the needed gems

```sh
gem install inspec
```

#### Ensure InSpec Installed and is 4.x or higher

```sh
inspec --version
```

### Setting & Reviewing the Core Profile Attributes

The `core` or `shared` attributes are set in the `inspec.yml` file in the profile. This stores the default values for the
shared attributes that the profile uses to examine your system.

These attributes _should not be edited directly_!

If you need to override the default values for the core attributes to better match your system under evaluation, please:

1. Review the attributes and their defaults in the `inspec.yml` and note the attributes/inputs you need to tailor for your installation.
2. Create a `system` or `instance` specific `attributes.yml` - such as `attributes.mysystem.yml` and override the attributes with this file.
3. When you run the profile, you can load your updated attributes using the `--attrs` flag on the `inspec exec` command (see below)

### Sensitive Attributes (aka `passwords`, `system accounts` and `owners` in your PostgreSQL database )

The recommend way to store sensitive information is to use one of the environmental variables outlined below. For instance, you can set the password for the PostgreSQL user with the `PG_USER_PWD` environmental variable.

Alternatively, you can set these variables in your `attributes.mysystem.yml` file, but again, this is not recommended for sensitive information like passwords.

#### Set the following `environment variables` before you run the profile:

- PG_OWNER
- PG_OWNER_GRP
- PG_OWNER_PWD
- PG_DBA
- PG_DBA_PWD
- PG_USER
- PG_USER_PWD
- PG_HOST
- PG_PORT
- LOGIN_USER
- LOGIN_HOST
- PG_SYSLOG_OWNER

### Examples for your `attributes.mysystem.yml`

#### OS Group, User

```yaml
pg_owner: "postgres"
pg_group: "postgres"
# password set via `env_var`
```

#### DBA User

```yaml
pg_dba: "dba"
# password set via `env_var`
```

#### Normal DB User

```yaml
pg_user: "<username>"
# password set via `env_var`
```

#### DB Host and Port

```yaml
pg_host: "127.0.0.1"
pg_port: "5432"
```

#### DB Name and Test table

```yaml
pg_db: "test_db"
pg_table: "test_table"
```

#### Misc settings

```yaml
login_user: "<user on remote DB server>"
login_host: "<DB Host IP>"
pg_version: "9.5"
pg_data_dir: "/var/lib/pgsql/9.5/data"
pg_conf_file: "/var/lib/pgsql/9.5/data/postgresql.conf"
pg_user_defined_conf: "/var/lib/pgsql/9.5/data/stig-postgresql.conf"
pg_hba_conf_file: "/var/lib/pgsql/9.5/data/pg_hba.conf"
pg_ident_conf_file: "/var/lib/pgsql/9.5/data/pg_ident.conf"
pg_shared_dirs:
  [
    "/usr/pgsql-9.5",
    "/usr/pgsql-9.5/bin",
    "/usr/pgsql-9.5/lib",
    "/usr/pgsql-9.5/share",
  ]
pg_conf_mode: "0600"
pg_ssl: "on"
pg_log_dest: "syslog"
pg_syslog_facility: ["local0"]
pg_syslog_owner: "postgres"
pgaudit_log_items: ["ddl", "role", "read", "write"]
pgaudit_log_line_items: ["%m", "%u", "%c"]
pg_superusers: ["postgres"]
pg_users: []
pg_replicas: ["192.168.1.3/32"]
pg_max_connections: "100"
pg_timezone: "UTC"
```

### Validating Your PostgreSQL Instance

(See: <https://www.inspec.io/docs/reference/cli/>)

#### Execute a single Control in the Profile

**Note**: replace the profile's directory name - e.g. - `pgstigcheck-inspec` with `.` if you are in the profile's root directory.

```sh
inspec exec pgstigcheck-inspec/controls/V-72845.rb --input-files=attributes.mysystem.yml -i <your ssh private key> -t ssh://<user>@<db host>:<port> --reporter cli json:myresults.json
```

or use the `--controls` flag

```sh
inspec exec pgstigcheck-inspec --controls=V-72845 V-72861 --input-file=attributes.mysystem.yml  -i <your ssh private key>  -t ssh://<user>@<db host>:<port> --reporter cli json:myresults.json
```

#### Execute a Single Control and save results as HTML

```sh
inspec exec pgstigcheck-inspec --controls=V-72845 --input-file=attributes.mysystem.yml -i <your ssh private key> --sudo --sudo-options="-u postgres" -t ssh://<user>@<db host>:<port> --reporter cli html:myresults.html
```

#### Execute All Controls in the Profile

```sh
inspec exec pgstigcheck-inspec --input-file=attributes.yml -i <your ssh private key> --sudo --sudo-password=<sudo user password> --sudo-options="-u postgres"  -t ssh://<user>@<db host>:<port> --reporter cli json:myresults.json
```

#### Execute all the Controls in the Profile and save results as HTML

```sh
inspec exec pgstigcheck-inspec --input-files=attributes.yml -i <your ssh private key> --sudo --sudo-password=<sudo user password> --sudo-options="-u postgres" -t ssh://<user>@<db host>:<port> --reporter cli html:myresults.html
```

### Reviewing your results

You can review your results from above in many ways, as you saw your results came back in multiple outputs - on the cli and in either `json` or `html`.

You can learn more about the different [InSpec Reporters](https://www.inspec.io/docs/reference/reporters/) on the [inspec.io](http://www.inspec.io) site.

## Pro Tips

### Location, Location, Location

The `--reporters` flags **must _always_** be at the end of your `inspec exec` cli command as they can user either `=` or `spaces` and so they must be at the end of the command.

If you used the examples above, you should have a `myresults.json` or `myresults.html` which you can review.

### HTML Reporter

The `myresults.html` in our examples - aka the InSpec HTML Reporter - is a working `html` file report but its output is very `technical` and is not recommended for **security review** or **accreditation discussions**.

### Use MITRE Hiemdall or Heimdall-Lite

Use the `JSON` InSpec Reporter output and the MITRE [Heimdall-Lite](http://mitre.github.io/heimdall-lite) for the best possible view of the results.

The **recommended** review format for for **security review** or **accreditation discussions** is the `JSON` results format using the InSpec `JSON` reporter and the MITRE `heimdall-lite` viewer.

You can use heimdall-lite any-time anywhere from: <http://mitre.github.io/heimdall-lite/>. Heimdall-Lite is a Single Page Client Side JavaScript app that runs completely in your browser and was designed to help make reviewing, sorting and sharing your InSpec results easier.

You can also download the `.html` files via a simple `save as` from your browser should you need to use `heimdall-lite` in a disconnected setting.

#### Heimdall vs Heimdall-Lite

[Heimdall-Lite](http://mitre.github.io/heimdall-lite) is a [VueJS](https://vuejs.org/) powered client side only view of your data for teams and devs doing their security compliance work.

If you need a more ongoing compliance view of your InSpec results, get the full [MITRE Hiemdall](https://www.github.com/mitre/heimdall) application / server which provides enhanced capabilities - like storage, timelines and more - and is powered by Rails and CrunchyDB PostgreSQL.

You can find out more about the InSpec Tools and Open Source applications at <http://inspec.mitre.org>.

## Sponsors

[![Crunchy Data](/hugo/static/images/crunchy_logo.png)](https://www.crunchydata.com/)

[Crunchy Data](https://www.crunchydata.com/) is pleased to sponsor pgstigcheck-inspec and many other [open-source projects](https://github.com/CrunchyData/) to help promote support the PostgreSQL community and software ecosystem.

[![The MITRE Corporation](https://upload.wikimedia.org/wikipedia/commons/d/d3/Mitre_Corporation_logo.svg)](https://www.mitre.org/)

[The MITRE Corporation](https://www.mitre.org) is pleased to support our Sponsors and CrunchyData in the creation of the PostgreSQL 9.x STIG and the pgstigcheck-inspec validation profile. MITRE also supports many other [inspec validation baselines](https://github.com/mitre?&q=baseline) on the MITRE GitHub (https://github.com/mitre/) in the [Public Interest](https://www.mitre.org/about/mission-and-values).

---

## Legal Notices

Copyright © 2019 Crunchy Data Solutions, Inc.

CRUNCHY DATA SOLUTIONS, INC. PROVIDES THIS GUIDE "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF NON INFRINGEMENT, MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.

Crunchy, Crunchy Data Solutions, Inc. and the Crunchy Hippo Logo are trademarks of Crunchy Data Solutions, Inc.
