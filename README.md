# PostgreSQL pgseccomp Extension Module

## Overview
This extension adds direct support for SECCOMP into PostgreSQL.

SECCOMP ("SECure COMPuting with filters") is a Linux kernel syscall filtering mechanism which allows reduction of the kernel attack surface by preventing (or at least audit logging) normally unused syscalls. Quoting from this link:

https://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt

   "A large number of system calls are exposed to every userland process with many of them going unused for the entire lifetime of the process. As system calls change and mature, bugs are found and eradicated. A certain subset of userland applications benefit by having a reduced set of available system calls. The resulting set reduces the total kernel surface exposed to the application. System call filtering is meant for use with those applications."

Recent security best-practices recommend, and certain highly security-conscious organizations are beginning to require, that SECCOMP be used to the extent possible. The major web browsers, container runtime engines, and systemd are all examples of software that already support seccomp.

A seccomp (BPF) filter is comprised of a default action, and a set of rules with actions pertaining to specific syscalls (possibly with even more specific sets of arguments). Once loaded into the kernel, a filter is inherited by all child processes and cannot be removed. It can, however, be overlaid with another filter. For any given syscall match, the most restrictive (a.k.a. highest precedence) action will be taken by the kernel. Thus, PostgreSQL has already been run "in the wild" under seccomp control in containers, and possibly systemd. Adding seccomp support into PostgreSQL itself mitigates issues with these approaches, and has several advantages:

* Container seccomp filters tend to be extremely broad/permissive, typically allowing about 6 out 7 of all syscalls. They must do this because the use cases for containers vary widely.
* systemd does not implement seccomp filters by default. Packagers may decide to do so, but there is no guarantee. Adding them post install potentially requires cooperation by groups outside control of the database admins.
* In the container and systemd case there is no particularly good way to inspect what filters are active. It is possible to observe actions taken, but again, control is possibly outside the database admin group. For example, the best way to understand what happened is to review the auditd log, which is likely not readable by the DBA.
* With built-in support, it is possible to lock down backend processes more tightly than the postmaster.
* With built-in support, it is possible to calculate and return (in the form of a Set Returning Function) the effective filters being applied to the postmaster and the current backend.
* With built-in support, it is possible to lock down different backend processes differently than each other.
* With built-in support, it could be possible (this part not yet implemented) to have separate filters for different backend types, e.g. autovac workers, background writer, etc.

## Syntax

```
SELECT * FROM seccomp_filter();
```
This function returns rows representing the currently active seccomp filter in the parent (global) PostgreSQL listening process, as well as the client's backend session. For example:
```
select * from seccomp_filter() order by 2,3 LIMIT 10;
  syscall  | syscallnum | filter_action  | context 
-----------+------------+----------------+---------
 <default> |         -1 | global->log    | global
 <default> |         -1 | global->log    | session
 read      |          0 | global->allow  | global
 read      |          0 | session->allow | session
 write     |          1 | global->allow  | global
 write     |          1 | session->allow | session
 close     |          3 | global->allow  | global
 close     |          3 | session->allow | session
 stat      |          4 | global->allow  | global
 stat      |          4 | session->allow | session
(10 rows)
```
This shows that the ```default``` action is ```log``` at both the global and the session level. It also shows that several syscalls are specifically configured to ```allow``` rather than ```log```. Any syscalls in the latter list will be allowed with no action taken, while any syscalls that have not been specified will get a log entry in the auditd log.

The ```syscall``` column lists specific kernel syscalls by name. ```syscallnum``` is the corresponding syscall number for the current architecture.

The ```filter_action``` column shows the action that will be taken when that syscall is made by PostgreSQL. The possible actions are:
* ```allow```: no action will be taken
* ```log```: the syscall will be logged in the auditd log
* ```error```: a "permission denied" error will be returned to PostgreSQL
* ```kill```: the current process will be sent SIGSYS (killed) 

The first part of this field indicates the origin of the action. ```global``` indicates that the action was inherited from the global settings, while ```session``` indicates that the session overlay filter took precedence for this syscall. If the action is the same for both ```global``` and ```session``` the ```session``` action is presumed to win. The ```context``` column indicates the level in which this filter rule is being enforced. ```global``` means that the enforcement is occurring at the postmaster process or in one of the non-client backends (children of the postmaster), and ```session``` means that the enforcement applies to the current session.

```
SELECT set_client_filter(default_action,
                         allow_list, log_list,
                         error_list, kill_list);
```
This function overlays the currently active seccomp session filter with the values as specified by the arguments. It must be noted that, as mentioned above, the resultant filter can only be the same or more restrictive than the initial session filter. Attempts to make a less restrictive filter are ineffective.

Similar to what is shown below for the session parameters in the Configuration section, the lists may be set to a single asterisk character ('*') which means to inherit the global list for this action. On the other hand, if any of the list arguments is passed as a NULL, the session list configuration parameter is used.

This function may only be called once per session. Subsequent attempts will produce an error.

By default, EXECUTE permission is revoked for set_client_filter(). Note, however, that even if EXECUTE permission has been granted, the call will fail unless the seccomp syscall is allowed to run at the session level based on the configuration of previous filters (global and session).

## Configuration
* Add pgseccomp to shared_preload_libraries in postgresql.conf.
```
shared_preload_libraries = 'pgseccomp'
```
* The following custom parameters may be set:
```
# cluster-wide on/off switch
pgseccomp.enabled = on

# Enforced at the parent (postmaster)
# and inherited by all child processes
############
# These are comma delimited lists of syscalls
# to be associated with specific actions.
pgseccomp.global_syscall_allow = '<allowed list >'
pgseccomp.global_syscall_log = '<causes audit log message>'
pgseccomp.global_syscall_error = '<throws permission denied error>'
pgseccomp.global_syscall_kill = '<process killed with SIGSYS>'
# this is the default action for non-specified syscalls
pgseccomp.global_syscall_default = '[allow|log|error|kill]'

# Actions overlayed at the client backend session
############
# These are comma delimited lists of syscalls
# to be associated with specific actions.
# The single char '*' means to inherit the global list
# for this action
pgseccomp.session_syscall_allow = '*'
pgseccomp.session_syscall_log = '*'
pgseccomp.session_syscall_error = '*'
pgseccomp.session_syscall_kill = '*'
# this is the default action for non-specified syscalls
pgseccomp.session_syscall_default = '[allow|log|error|kill]'

# List of per role client backend session settings
pgseccomp.session_roles = '<list of roles with custom syscall lists>'
session_syscall_*.<rolename> = '<role-custom overlay syscall list>'
```
If a role is listed in ```pgseccomp.session_roles``` then pgseccomp will override the session level lists above with the corresponding role specific list. If any role specific lists are missing, the normal session level list will be used in its place.

For example:
```
pgseccomp.global_syscall_allow = ''
pgseccomp.global_syscall_log = ''
pgseccomp.global_syscall_error = ''
pgseccomp.global_syscall_kill = ''
pgseccomp.global_syscall_default = 'allow'

pgseccomp.session_syscall_allow = 'access,<...long list other syscalls...>,write'
pgseccomp.session_syscall_log = ''
pgseccomp.session_syscall_error = ''
pgseccomp.session_syscall_kill = ''
pgseccomp.session_syscall_default = 'error'

pgseccomp.session_roles = 'joe,alice'
session_syscall_allow.joe = 'access,<...long list other syscalls...>,write,clone'
session_syscall_default.joe = 'log'
```
In this example, the default rule is 'allow' at the global level, with a specific allow list and default action of 'error' at the session level.

However, if the rolename 'joe' logs in, the session allow list is overridden with a custom list, which has the 'clone' syscall appended to the end of it. It also has a default action of 'log' rather than 'error' which will apply to all other syscalls.

If rolename 'alice' logs in, the configuration will be searched for custom lists, but since none are defined, the normal session level values will be used.

## Installation

### Requirements

* Linux kernel 3.5 or newer
* libseccomp installed version 2.4 or greater

### Compile and Install

Clone PostgreSQL repository:

```bash
$> git clone https://github.com/postgres/postgres.git
```

Checkout REL9_5_STABLE (for example) branch:

```bash
$> git checkout REL9_5_STABLE
```

Make PostgreSQL:

```bash
$> ./configure
$> make install -s
```

Change to the contrib directory:

```bash
$> cd contrib
```

Clone ```pgseccomp``` extension:

```bash
$> git clone https://github.com/crunchydata/pgseccomp
```

Change to ```pgseccomp``` directory:

```bash
$> cd pgseccomp
```

Build ```pgseccomp```:

```bash
$> make
```

Install ```pgseccomp```:

```bash
$> make install
```

#### Using PGXS

If an instance of PostgreSQL is already installed, then PGXS can be utilized to build and install ```pgseccomp```.  Ensure that PostgreSQL binaries are available via the ```$PATH``` environment variable then use the following commands.

```bash
$> make USE_PGXS=1
$> make USE_PGXS=1 install
```

### Configure

The following bash commands should configure your system to utilize pgseccomp. Replace all paths as appropriate. It may be prudent to visually inspect the files afterward to ensure the changes took place.

###### Initialize PostgreSQL (if needed):

```bash
$> initdb -D /path/to/data/directory
```

###### Create Target Database (if needed):

```bash
$> createdb <database>
```

###### Install ```pgseccomp``` functions:

Edit postgresql.conf and add ```pgseccomp``` to the shared_preload_libraries line, and change custom settings as mentioned above.

Finally, restart PostgreSQL (method may vary):

```
$> service postgresql restart
```
Install the extension into your database:

```bash
psql <database>
CREATE EXTENSION pgseccomp;
```

###### Test basic functionality:
Before enabling pgseccomp run the following:
```
LOI="(Seccomp|NoNewPrivs|Speculation_Store_Bypass)"
for pid in $(ps -fu postgres|tail -n+2|tr -s " "|cut -d" " -f2);
do
  echo "${pid} - $(cat /proc/${pid}/status |grep -E ${LOI})";
done;
25980 - NoNewPrivs:     0
Seccomp:        0
Speculation_Store_Bypass:       thread vulnerable
25982 - NoNewPrivs:     0
Seccomp:        0
Speculation_Store_Bypass:       thread vulnerable
25983 - NoNewPrivs:     0
Seccomp:        0
Speculation_Store_Bypass:       thread vulnerable
25984 - NoNewPrivs:     0
Seccomp:        0
Speculation_Store_Bypass:       thread vulnerable
25985 - NoNewPrivs:     0
Seccomp:        0
Speculation_Store_Bypass:       thread vulnerable
25986 - NoNewPrivs:     0
Seccomp:        0
Speculation_Store_Bypass:       thread vulnerable
25987 - NoNewPrivs:     0
Seccomp:        0
Speculation_Store_Bypass:       thread vulnerable
```
From the above it can be seen that none of the processes owned by the ```postgres``` user are secured with Seccomp, nor from ```Speculation_Store_Bypass```.

After getting pgseccomp up and running, run the same check:
```
LOI="(Seccomp|NoNewPrivs|Speculation_Store_Bypass)"
for pid in $(ps -fu postgres|tail -n+2|tr -s " "|cut -d" " -f2);
do
  echo "${pid} - $(cat /proc/${pid}/status |grep -E ${LOI})";
done;
24613 - NoNewPrivs:     1
Seccomp:        2
Speculation_Store_Bypass:       thread force mitigated
24615 - NoNewPrivs:     1
Seccomp:        2
Speculation_Store_Bypass:       thread force mitigated
24616 - NoNewPrivs:     1
Seccomp:        2
Speculation_Store_Bypass:       thread force mitigated
24617 - NoNewPrivs:     1
Seccomp:        2
Speculation_Store_Bypass:       thread force mitigated
24618 - NoNewPrivs:     1
Seccomp:        2
Speculation_Store_Bypass:       thread force mitigated
24619 - NoNewPrivs:     1
Seccomp:        2
Speculation_Store_Bypass:       thread force mitigated
24620 - NoNewPrivs:     1
Seccomp:        2
Speculation_Store_Bypass:       thread force mitigated
```
Clearly now seccomp is active on the ```postgres``` processes, and as a bonus ```Speculation_Store_Bypass``` has also been mitigated.

Also run:
```
select * from seccomp_filter()
```
or some variation of that, and verify your filters are set up the way you intend them to be.

## Notes
In order to determine your minimally required allow lists, do something like the following on a non-production server with the same architecture as production:

0. Setup:
 * install libseccomp, libseccomp-dev, and seccomp
 * install auditd if not already installed

1. Modify postgresql.conf and/or create <pg_source_dir>/postgresql_tmp.conf
```
pgseccomp.enabled = on

pgseccomp.global_syscall_default = 'allow'
pgseccomp.global_syscall_allow = ''
pgseccomp.global_syscall_log = ''
pgseccomp.global_syscall_error = ''
pgseccomp.global_syscall_kill = ''

pgseccomp.session_syscall_default = 'log'
pgseccomp.session_syscall_allow = '*'
pgseccomp.session_syscall_log = '*'
pgseccomp.session_syscall_error = '*'
pgseccomp.session_syscall_kill = '*'
```

2. Modify /etc/audit/auditd.conf
```
disp_qos = 'lossless'
change max_log_file_action = 'ignore'
```

3. Stop auditd, clear out all audit.logs, start auditd:
```
systemctl stop auditd.service			# if running
echo -n "" > /var/log/audit/audit.log
systemctl start auditd.service
```

4. Start/restart postgres.

5. Exercise postgres as much as possible (one or more of the following):
 * make installcheck-world
 * make check world \
   EXTRA_REGRESS_OPTS=--temp-config=<pg_source_dir>/postgresql_tmp.conf
 * run your application through its paces
 * other random testing of relevant postgres features

```
Note: at this point audit.log will start growing quickly.
```

6. Process results:
 * a) ```systemctl stop auditd.service```
 * b) Run the provided ```get_syscalls.sh``` script (may need editing for your system)
 * c) Cut and paste the result as the value of session_syscall_allow.

7. Optional:
 * a) global_syscall_default = 'log'
 * b) Repeat steps 3-5
 * c) Repeat step 6a and 6b
 * d) Cut and paste the result as the value of global_syscall_allow

8. Iterate steps 3-6b.
 * Output of ```get_syscalls.sh``` should be empty.
 * If there are any new syscalls, add to global_syscall_allow and
   session_syscall_allow.
 * Iterate until output of ```get_syscalls.sh``` script is empty.

9. Optional:
 * Change global and session defaults to ```error``` or ```kill```
 * Reduce the allow lists if desired

10. Adjust settings to taste, restart postgres, and monitor audit.log
    going forward.

##  Licensing

Please see the [LICENSE](./LICENSE) file.


