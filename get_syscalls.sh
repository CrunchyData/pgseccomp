#!/bin/bash

SYS_RESOLVER="/usr/bin/scmp_sys_resolver"
FOI="/var/log/audit/audit.log"

function syscall_resolve ()
{
    F_SYSCALLNUM="$1"

    "${SYS_RESOLVER}" "${F_SYSCALLNUM}"
}

function process_foi ()
{
  for scn in $(grep "type=SECCOMP" /var/log/audit/audit.log|cut -d" " -f12|cut -d= -f2|sort|uniq)
  do
    echo "$(syscall_resolve ${scn})"
  done
}

function build_list ()
{
  dlm=""
  for syscall in $(process_foi | sort)
  do
    echo -n "${dlm}${syscall}"
    dlm=","
  done
  echo
}

build_list
