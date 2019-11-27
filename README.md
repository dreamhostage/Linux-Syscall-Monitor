# Linux Syscall Monitor

Linux Syscall Monitor (LSM) - Downloadable kernel module which makes monitoring system calls of kernel mode. Communication with the module is carried out through the procfs interface.

# Requirements:

- Linux kernel version 4.4 and higher
- CONFIG_FTRACE
- CONFIG_KALLSYMS
- CONFIG_DYNAMIC_FTRACE_WITH_REGS
- CONFIG_HAVE_FENTRY
- Processor architecture x86_64

# Opportunities:

  System calls monitoring with 3 levels of functions:

level 1: 
- sys_open
- sys_openat
- sys_open_by_handle_at
- sys_write
- sys_writev
- sys_pwrite64
- sys_pwritev
- sys_pwritev2

level 2:
- sys_chown
- sys_lchown
- sys_fchown
- sys_fchownat
- sys_chmod
- sys_fchmod
- sys_fchmodat

level 3:
- sys_fork
- sys_vfork
- sys_execve
- sys_execveat

  Blocking the start of the specified process;
  
  Forbidding of module unloading (optional).

# Console commands:

- startlogging----------start logging
- stoplogging----------stop logging
- setlogginglevel n-----set (n) level of logging
- block PATH------------block process launching by PATH;
- unblock----------------unblock process launching
- allowunload 1/0-------permit (0) / forbid (1) unloading of module

Project also included GUI interface (LSMView) with intuitive design which helps to use kernel module without console window.
