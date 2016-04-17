#!/usr/sbin/dtrace -s

#pragma D option aggsize=8m
#pragma D option bufsize=16m
#pragma D option dynvarsize=16m
#pragma D option aggrate=0
#pragma D option cleanrate=50Hz

dtrace:::BEGIN
{
  tracing_pid[$1] = 1;
}

proc:::create
/tracing_pid[args[1]->p_pid] == 1/
{
  childpid = args[0]->p_pid;
  tracing_pid[childpid] = 1;
  time[childpid] = timestamp;
  p_pid[childpid] = args[0]->p_pid;
  p_ppid[childpid] = args[1]->p_pid;
  p_name[childpid] = execname;
  p_exec[childpid] = "";
  printf("%s:%d has created child %d\n",  p_name[p_ppid[childpid]], p_ppid[childpid], p_pid[childpid]);
}

proc:::exec
/tracing_pid[pid] == 1/
{
  p_exec[pid] = args[0];
  printf("exec occurred: %s, %d\n", p_exec[pid], pid);
}

/*
proc:::exit
/tracing_pid[pid] == 1/
{
  printf("%s (%d) executed %s (%d) for %d microseconds\n",
      p_name[p_ppid[pid]], p_ppid[pid], p_exec[pid], pid, (timestamp - time[pid])/1000);
}
*/

syscall::open*:entry
/tracing_pid[pid] == 1/
{
  printf("%s %s", execname, copyinstr(arg0));
}
