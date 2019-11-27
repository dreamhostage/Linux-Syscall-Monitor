
void (*write_to_procfs_str32)(const char* str);
char BlockedProcess32[1000];
char exe_path32 [1000];
char procmes32[1024];

struct ftrace_hook32 {
    const char *name;
    void *function;
    void *original;

    unsigned long address;
    struct ftrace_ops ops;
};

static char * getFilePathByFd32(unsigned int fd) {
    char *tmp;
    char *pathname;
    struct file *file;
    struct path *path;

    spin_lock(&current->files->file_lock);
    file = fcheck_files(current->files, fd);

    if (!file) {
        spin_unlock(&current->files->file_lock);
        return NULL;
    }

    path = &file->f_path;
    path_get(path);
    spin_unlock(&current->files->file_lock);
    tmp = (char *) __get_free_page(GFP_KERNEL);

    if (!tmp) {
        path_put(path);
        return NULL;
    }

    pathname = d_path(path, tmp, PAGE_SIZE);

    if (IS_ERR(pathname)) {
        free_page((unsigned long) tmp);
        return NULL;
    }

    path_put(path);
    free_page((unsigned long) tmp);
    return pathname;
}

static char* get_process_name_by_pid32(char* exe_path32) {
    char * exepathp;
    struct file * exe_file;
    struct mm_struct *mm;

    mm = get_task_mm(current);
    down_read(&mm->mmap_sem);
    exe_file = mm->exe_file;
    if (exe_file) get_file(exe_file);
    up_read(&mm->mmap_sem);

    exepathp = d_path(&(exe_file->f_path), exe_path32, 1000);
    return exepathp;
}

static int fh_32_resolve_hook_address(struct ftrace_hook32 *hook) {
    hook->address = kallsyms_lookup_name(hook->name);

    if (!hook->address) {
        printk("<LSM><check_engine32> unresolved symbol: %s\n", hook->name);
        return -ENOENT;
    }

#if USE_FENTRY_OFFSET
    *((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
    *((unsigned long*) hook->original) = hook->address;
#endif

    return 0;
}

static void notrace fh_32_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                       struct ftrace_ops *ops, struct pt_regs *regs) {
    struct ftrace_hook32 *hook = container_of(ops, struct ftrace_hook32, ops);

#if USE_FENTRY_OFFSET
    regs->ip = (unsigned long) hook->function;
#else
    if (!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long) hook->function;
#endif
}

int fh_32_install_hook(struct ftrace_hook32 *hook) {
    int err;

    err = fh_32_resolve_hook_address(hook);
    if (err) {
        printk("<LSM><check_engine32> fh_32_install_hook ERROR while (fh_32_resolve_hook_address): %s\n", hook->name);
        return err;
    }

    hook->ops.func = fh_32_ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
            | FTRACE_OPS_FL_RECURSION_SAFE
            | FTRACE_OPS_FL_IPMODIFY;

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (err) {
        printk("<LSM><check_engine32> fh_32_install_hook ERROR while (ftrace_set_filter_ip): %s\n", hook->name);
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if (err) {
        printk("<LSM><check_engine32> fh_32_install_hook ERROR while (register_ftrace_function): %s\n", hook->name);
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
        return err;
    }

    return 0;
}

void fh_32_remove_hook(struct ftrace_hook32 *hook) {
    int err;

    err = unregister_ftrace_function(&hook->ops);
    if (err) {
        printk("<LSM><check_engine32> fh_32_remove_hook ERROR while (unregister_ftrace_function): %s\n", hook->name);
    }

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    if (err) {
        printk("<LSM><check_engine32> fh_32_remove_hook ERROR while (ftrace_set_filter_ip): %s\n", hook->name);
    }
}

int fh_32_install_hooks(struct ftrace_hook32 *hooks, size_t count) {
    int err;
    size_t i;

    for (i = 0; i < count; i++) {
        err = fh_32_install_hook(&hooks[i]);
        if (err) {
            printk("<LSM><check_engine32> fh_32_install_hooks ERROR while (fh_32_install_hook): %s\n", hooks[i].name);
            goto error;
        } else
            printk("<LSM><check_engine32> OK.......... %s\n", hooks[i].name);
    }

    return 0;

error:
    while (i != 0) {
        fh_32_remove_hook(&hooks[--i]);
    }

    return err;
}

void fh_32_remove_hooks(struct ftrace_hook32 *hooks, size_t count) {
    size_t i;

    for (i = 0; i < count; i++)
        fh_32_remove_hook(&hooks[i]);
}
#define CONFIG_X86_64
#ifndef CONFIG_X86_64
#error Currently only x86_64 architecture is supported
#endif

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif
#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0))
#define ALLOW_PWRITEV2 1
#endif
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

static char *duplicate_filename32(const char __user *filename) {
    char *kernel_filename;

    kernel_filename = kmalloc(4096, GFP_KERNEL);
    if (!kernel_filename)
        return NULL;

    if (strncpy_from_user(kernel_filename, filename, 4096) < 0) {
        kfree(kernel_filename);
        return NULL;
    }

    return kernel_filename;
}
/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_delete_module:
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_32_sys_delete_module)(struct pt_regs *regs);

static asmlinkage long fh_32_sys_delete_module(struct pt_regs *regs) {
    char *kernel_filename;
    kernel_filename = duplicate_filename32((void*) regs->di);
    if (forbidUnloading) {
        if (strcmp(kernel_filename, "LSM") == 0) {
            long ret = 0;
            printk("%s\n", "<LSM><ALL32><sys_delete_module> UNLOADING of module LSM.ko was forbidden!");
            write_to_procfs_str32("<LSM><ALL32><sys_delete_module> UNLOADING of module LSM.ko was forbidden!");
            kfree(kernel_filename);
            return ret;
        } else {
            printk("%s\n", "<LSM><ALL32><sys_delete_module> UNLOADING MODULE LSM.ko");
            write_to_procfs_str32("<LSM><ALL32><sys_delete_module> UNLOADING MODULE LSM.ko");
            kfree(kernel_filename);
            return real_32_sys_delete_module(regs);
        }
    }
    printk("%s\n", "<LSM><ALL32><sys_delete_module> UNLOADING MODULE LSM.ko");
    write_to_procfs_str32("<LSM><ALL32><sys_delete_module> UNLOADING MODULE LSM.ko");
    kfree(kernel_filename);
    return real_32_sys_delete_module(regs);
}
#else
static asmlinkage long (*real_32_sys_delete_module)(const char __user *name_user,
                                                    unsigned int flags);

static asmlinkage long fh_32_sys_delete_module(const char __user *name_user,
                                               unsigned int flags) {
    char *kernel_filename;
    kernel_filename = duplicate_filename32(name_user);
    if (forbidUnloading) {
        if (strcmp(kernel_filename, "LSM") == 0) {
            long ret = 0;
            printk("%s\n", "<LSM><ALL32><sys_delete_module> UNLOADING of module LSM.ko was forbidden!");
            write_to_procfs_str32("<LSM><ALL32><sys_delete_module> UNLOADING of module LSM.ko was forbidden!");
            kfree(kernel_filename);
            return ret;
        } else {
            printk("%s\n", "<LSM><ALL32><sys_delete_module> UNLOADING MODULE LSM.ko");
            write_to_procfs_str32("<LSM><ALL32><sys_delete_module> UNLOADING MODULE LSM.ko");
            kfree(kernel_filename);
            return real_32_sys_delete_module(name_user,flags);
        }
    }
    printk("%s\n", "<LSM><ALL32><sys_delete_module> UNLOADING MODULE LSM.ko");
    write_to_procfs_str32("<LSM><ALL32><sys_delete_module> UNLOADING MODULE LSM.ko");
    kfree(kernel_filename);
    return real_32_sys_delete_module(name_user,flags);
}
#endif
/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_execve:
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_32_sys_execve)(struct pt_regs *regs);

static asmlinkage long fh_32_sys_execve(struct pt_regs *regs) {
    long ret = 0;
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid32(exe_path32);
    kernel_filename = duplicate_filename32((void*) regs->di);

    if (strstr(BlockedProcess32, kernel_filename) != 0) {
        sprintf(procmes32, "%s%s%s%s", "<LSM><ALL32><sys_execve> THREAD: ", ppath, " BLOCKED PROCESS: ", kernel_filename);
        printk("%s\n", procmes32);
        write_to_procfs_str32(procmes32);
        kfree(kernel_filename);
        return ret;
    } else {
        sprintf(procmes32, "%s%s%s%s", "<LSM><ALL32><sys_execve> THREAD: ", ppath, " OPENED: ", kernel_filename);
        printk("%s\n", procmes32);
        write_to_procfs_str32(procmes32);
        kfree(kernel_filename);
        return real_32_sys_execve(regs);
    }
}
#else
static asmlinkage long (*real_32_sys_execve)(const char __user *filename,
                                             const char __user *const __user *argv,
                                             const char __user *const __user *envp);

static asmlinkage long fh_32_sys_execve(const char __user *filename,
                                        const char __user *const __user *argv,
                                        const char __user *const __user *envp){
    long ret = 0;
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid32(exe_path32);
    kernel_filename = duplicate_filename32(filename);

    if (strstr(BlockedProcess32, kernel_filename) != 0) {
        sprintf(procmes32, "%s%s%s%s", "<LSM><ALL32><sys_execve> THREAD: ", ppath, " BLOCKED PROCESS: ", kernel_filename);
        printk("%s\n", procmes32);
        write_to_procfs_str32(procmes32);
        kfree(kernel_filename);
        return ret;
    } else {
        sprintf(procmes32, "%s%s%s%s", "<LSM><ALL32><sys_execve> THREAD: ", ppath, " OPENED: ", kernel_filename);
        printk("%s\n", procmes32);
        write_to_procfs_str32(procmes32);
        kfree(kernel_filename);
        return real_32_sys_execve(filename,argv,envp);
    }
}
#endif
//////////////////////////////////////////////////////////////////////////////////////////////////////////fh_32_level 1///////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_open:
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_32_sys_open)(struct pt_regs *regs);

static asmlinkage long fh_32_sys_open(struct pt_regs *regs) {
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid32(exe_path32);

    kernel_filename = duplicate_filename32((void*) regs->di);

    sprintf(procmes32, "%s%s%s%s", "<LSM><ALL32><sys_open> THREAD: ", ppath, " OPENED: ", kernel_filename);
    printk("%s\n", procmes32);
    write_to_procfs_str32(procmes32);

    kfree(kernel_filename);
    return real_32_sys_open(regs);
}
#else
static asmlinkage long (*real_32_sys_open)(const char __user *filename,
                                           int flags, umode_t mode);
static asmlinkage long fh_32_sys_open(const char __user *filename,
                                      int flags, umode_t mode)
{
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid32(exe_path32);

    kernel_filename = duplicate_filename32(filename);

    sprintf(procmes32, "%s%s%s%s", "<LSM><ALL32><sys_open> THREAD: ", ppath, " OPENED: ", kernel_filename);
    printk("%s\n", procmes32);
    write_to_procfs_str32(procmes32);

    kfree(kernel_filename);
    return real_32_sys_open(filename,flags,mode);
}
#endif
/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_openat:
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_32_sys_openat)(struct pt_regs *regs);

static asmlinkage long fh_32_sys_openat(struct pt_regs *regs) {
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid32(exe_path32);

    kernel_filename = duplicate_filename32((void*) regs->si);

    if (strcmp(current->comm, "systemd-journal")) {
        sprintf(procmes32, "%s%s%s%s", "<LSM><ALL32><sys_openat> THREAD: ", ppath, " OPENED: ", kernel_filename);
        printk("%s\n", procmes32);
        write_to_procfs_str32(procmes32);
    }

    kfree(kernel_filename);

    return real_32_sys_openat(regs);
}
#else
static asmlinkage long (*real_32_sys_openat)(int dfd, const char __user *filename, int flags,
                                             umode_t mode);

static asmlinkage long fh_32_sys_openat(int dfd, const char __user *filename, int flags,
                                        umode_t mode) {
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid32(exe_path32);

    kernel_filename = duplicate_filename32(filename);

    if (strcmp(current->comm, "systemd-journal")) {
        sprintf(procmes32, "%s%s%s%s", "<LSM><ALL32><sys_openat> THREAD: ", ppath, " OPENED: ", kernel_filename);
        printk("%s\n", procmes32);
        write_to_procfs_str32(procmes32);
    }

    kfree(kernel_filename);

    return real_32_sys_openat(dfd,filename,flags,mode);
}
#endif
/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_open_by_handle_at:
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_32_sys_open_by_handle_at)(struct pt_regs *regs);

static asmlinkage long fh_32_sys_open_by_handle_at(struct pt_regs *regs) {
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid32(exe_path32);

    kernel_filename = duplicate_filename32((void*) regs->si);

    sprintf(procmes32, "%s%s%s%s", "<LSM><ALL32><sys_open_by_handle_at> THREAD: ", ppath, " OPENED: ", kernel_filename);
    printk("%s\n", procmes32);
    write_to_procfs_str32(procmes32);

    kfree(kernel_filename);

    return real_32_sys_open_by_handle_at(regs);
}
#else
//!!!!!NOT SURE
static asmlinkage long (*real_32_sys_open_by_handle_at)(int mountdirfd,
                                                        struct file_handle __user *handle,
                                                        int flags);

static asmlinkage long fh_32_sys_open_by_handle_at(int mountdirfd,
                                                   struct file_handle __user *handle,
                                                   int flags) {
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid32(exe_path32);
    int temp=handle->f_handle;
    char* fdstr=getFilePathByFd32(temp);
    sprintf(procmes32, "%s%s%s%s", "<LSM><ALL32><sys_open_by_handle_at> THREAD: ", ppath, " OPENED: ", fdstr);
    printk("%s\n", procmes32);
    write_to_procfs_str32(procmes32);
    return real_32_sys_open_by_handle_at(mountdirfd,handle,flags);
}
#endif
/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_write:
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_32_sys_write)(struct pt_regs *regs);

static asmlinkage long fh_32_sys_write(struct pt_regs *regs) {
    char *fdstr;
    unsigned int temp;
    char *ppath;

    temp = regs->di;
    fdstr = getFilePathByFd32(temp);
    ppath = get_process_name_by_pid32(exe_path32);
    sprintf(procmes32, "%s%s%s%s", "<LSM><ALL32><sys_write> THREAD: ", ppath, " WROTE TO: ", fdstr);
    printk("%s\n", procmes32);
    write_to_procfs_str32(procmes32);
    return real_32_sys_write(regs);
}
#else
static asmlinkage long (*real_32_sys_write)(unsigned int fd, const char __user *buf,
                                            size_t count);

static asmlinkage long fh_32_sys_write(unsigned int fd, const char __user *buf,
                                       size_t count) {
    char *fdstr;
    char *ppath;
    fdstr = getFilePathByFd32(fd);
    ppath = get_process_name_by_pid32(exe_path32);
    sprintf(procmes32, "%s%s%s%s", "<LSM><ALL32><sys_write> THREAD: ", ppath, " WROTE TO: ", fdstr);
    printk("%s\n", procmes32);
    write_to_procfs_str32(procmes32);
    return real_32_sys_write(fd,buf,count);
}
#endif
/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_writev:
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_32_sys_writev)(struct pt_regs *regs);

static asmlinkage long fh_32_sys_writev(struct pt_regs *regs) {
    unsigned int temp = regs->di;
    char *ppath;
    ppath = get_process_name_by_pid32(exe_path32);
    char *fdstr = getFilePathByFd32(temp);
    sprintf(procmes32, "%s%s%s%s", "<LSM><ALL32><sys_writev> THREAD: ", ppath, " WROTE TO: ", fdstr);
    printk("%s\n", procmes32);
    write_to_procfs_str32(procmes32);
    return real_32_sys_writev(regs);
}
#else
static asmlinkage long (*real_32_sys_writev)(unsigned long fd,
                                             const struct iovec __user *vec,
                                             unsigned long vlen);

static asmlinkage long fh_32_sys_writev(unsigned long fd,
                                        const struct iovec __user *vec,
                                        unsigned long vlen) {
    char *ppath;
    ppath = get_process_name_by_pid32(exe_path32);
    char *fdstr = getFilePathByFd32(fd);
    sprintf(procmes32, "%s%s%s%s", "<LSM><ALL32><sys_writev> THREAD: ", ppath, " WROTE TO: ", fdstr);
    printk("%s\n", procmes32);
    write_to_procfs_str32(procmes32);
    return real_32_sys_writev(fd,vec,vlen);
}
#endif
/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_pwrite64:
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_32_sys_pwrite64)(struct pt_regs *regs);

static asmlinkage long fh_32_sys_pwrite64(struct pt_regs *regs) {
    char *ppath;
    ppath = get_process_name_by_pid32(exe_path32);
    unsigned int temp = regs->di;
    char *fdstr = getFilePathByFd32(temp);
    sprintf(procmes32, "%s%s%s%s", "<LSM><ALL32><sys_pwrite64> THREAD: ", ppath, " WROTE TO: ", fdstr);
    printk("%s\n", procmes32);
    write_to_procfs_str32(procmes32);
    return real_32_sys_pwrite64(regs);
}
#else
static asmlinkage long (*real_32_sys_pwrite64)(unsigned int fd, const char __user *buf,
                                               size_t count, loff_t pos);

static asmlinkage long fh_32_sys_pwrite64(unsigned int fd, const char __user *buf,
                                          size_t count, loff_t pos) {
    char *ppath;
    ppath = get_process_name_by_pid32(exe_path32);
    char *fdstr = getFilePathByFd32(fd);
    sprintf(procmes32, "%s%s%s%s", "<LSM><ALL32><sys_pwrite64> THREAD: ", ppath, " WROTE TO: ", fdstr);
    printk("%s\n", procmes32);
    write_to_procfs_str32(procmes32);
    return real_32_sys_pwrite64(fd,buf,count,pos);
}
#endif
/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_pwritev:
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_32_sys_pwritev)(struct pt_regs *regs);

static asmlinkage long fh_32_sys_pwritev(struct pt_regs *regs) {
    unsigned int temp = regs->di;
    char *ppath;
    ppath = get_process_name_by_pid32(exe_path32);
    char *fdstr = getFilePathByFd32(temp);
    sprintf(procmes32, "%s%s%s%s", "<LSM><ALL32><sys_pwritev> THREAD: ", ppath, " WROTE TO: ", fdstr);
    printk("%s\n", procmes32);
    write_to_procfs_str32(procmes32);
    return real_32_sys_pwritev(regs);
}
#else
static asmlinkage long (*real_32_sys_pwritev)(unsigned int fd, const char __user *buf,
                                              size_t count, loff_t pos);

static asmlinkage long fh_32_sys_pwritev(unsigned int fd, const char __user *buf,
                                         size_t count, loff_t pos){
    char *ppath;
    ppath = get_process_name_by_pid32(exe_path32);
    char *fdstr = getFilePathByFd32(fd);
    sprintf(procmes32, "%s%s%s%s", "<LSM><ALL32><sys_pwritev> THREAD: ", ppath, " WROTE TO: ", fdstr);
    printk("%s\n", procmes32);
    write_to_procfs_str32(procmes32);
    return real_32_sys_pwritev(fd,buf,count,pos);
}
#endif
/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_pwritev2:
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_32_sys_pwritev2)(struct pt_regs *regs);

static asmlinkage long fh_32_sys_pwritev2(struct pt_regs *regs) {
    unsigned int temp = regs->di;
    char *ppath;
    ppath = get_process_name_by_pid32(exe_path32);
    char *fdstr = getFilePathByFd32(temp);
    sprintf(procmes32, "%s%s%s%s", "<LSM><ALL32><sys_pwritev2> THREAD: ", ppath, " WROTE TO: ", fdstr);
    printk("%s\n", procmes32);
    write_to_procfs_str32(procmes32);
    return real_32_sys_pwritev2(regs);
}
#endif
#ifdef  ALLOW_PWRITEV2
//!!!!!STARTS FROM 4.6!!!!!!!!!!!
static asmlinkage long (*real_32_sys_pwritev2)(unsigned long fd, const struct iovec __user *vec,
                                               unsigned long vlen, unsigned long pos_l, unsigned long pos_h,
                                               int flags);

static asmlinkage long fh_32_sys_pwritev2(unsigned long fd, const struct iovec __user *vec,
                                          unsigned long vlen, unsigned long pos_l, unsigned long pos_h,
                                          int flags){
    char *ppath;
    ppath = get_process_name_by_pid32(exe_path32);
    char *fdstr = getFilePathByFd32(fd);
    sprintf(procmes32, "%s%s%s%s", "<LSM><ALL32><sys_pwritev2> THREAD: ", ppath, " WROTE TO: ", fdstr);
    printk("%s\n", procmes32);
    write_to_procfs_str32(procmes32);
    return real_32_sys_pwritev2(fd,vec,vlen,pos_l,pos_h,flags);
}
#endif
//////////////////////////////////////////////////////////////////////////////////////////////////////////fh_32_level 2///////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_chown:
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_32_sys_chown)(struct pt_regs *regs);

static asmlinkage long fh_32_sys_chown(struct pt_regs *regs) {
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid32(exe_path32);
    kernel_filename = duplicate_filename32((void*) regs->di);
    sprintf(procmes32, "%s%s%s%s", "<LSM><ALL32><sys_chown> THREAD: ", ppath, " FILE: ", kernel_filename);
    printk("%s\n", procmes32);
    write_to_procfs_str32(procmes32);
    kfree(kernel_filename);
    return real_32_sys_chown(regs);
}
#else
static asmlinkage long (*real_32_sys_chown)(const char __user *filename,
                                            uid_t user, gid_t group);

static asmlinkage long fh_32_sys_chown(const char __user *filename,
                                       uid_t user, gid_t group) {
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid32(exe_path32);
    kernel_filename = duplicate_filename32(filename);
    sprintf(procmes32, "%s%s%s%s", "<LSM><ALL32><sys_chown> THREAD: ", ppath, " FILE: ", kernel_filename);
    printk("%s\n", procmes32);
    write_to_procfs_str32(procmes32);
    kfree(kernel_filename);
    return real_32_sys_chown(filename,user,group);
}
#endif
/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_lchown:
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_32_sys_lchown)(struct pt_regs *regs);

static asmlinkage long fh_32_sys_lchown(struct pt_regs *regs) {
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid32(exe_path32);
    kernel_filename = duplicate_filename32((void*) regs->di);
    sprintf(procmes32, "%s%s%s%s", "<LSM><ALL32><sys_lchown> THREAD: ", ppath, " FILE: ", kernel_filename);
    printk("%s\n", procmes32);
    write_to_procfs_str32(procmes32);
    kfree(kernel_filename);
    return real_32_sys_lchown(regs);
}
#else
static asmlinkage long (*real_32_sys_lchown)(const char __user *filename,
                                             uid_t user, gid_t group);

static asmlinkage long fh_32_sys_lchown(const char __user *filename,
                                        uid_t user, gid_t group) {
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid32(exe_path32);
    kernel_filename = duplicate_filename32(filename);
    sprintf(procmes32, "%s%s%s%s", "<LSM><ALL32><sys_lchown> THREAD: ", ppath, " FILE: ", kernel_filename);
    printk("%s\n", procmes32);
    write_to_procfs_str32(procmes32);
    kfree(kernel_filename);
    return real_32_sys_lchown(filename,user,group);
}
#endif
/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_fchown:
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_32_sys_fchown)(struct pt_regs *regs);

static asmlinkage long fh_32_sys_fchown(struct pt_regs *regs) {
    unsigned int temp = regs->di;
    char *ppath;
    ppath = get_process_name_by_pid32(exe_path32);
    char *fdstr = getFilePathByFd32(temp);
    sprintf(procmes32, "%s%s%s%s", "<LSM><ALL32><sys_fchown> THREAD: ", ppath, " FILE: ", fdstr);
    printk("%s\n", procmes32);
    write_to_procfs_str32(procmes32);
    return real_32_sys_fchown(regs);
}
#else
static asmlinkage long (*real_32_sys_fchown)(unsigned int fd, uid_t user, gid_t group);

static asmlinkage long fh_32_sys_fchown(unsigned int fd, uid_t user, gid_t group) {
    char *ppath;
    ppath = get_process_name_by_pid32(exe_path32);
    char *fdstr = getFilePathByFd32(fd);
    sprintf(procmes32, "%s%s%s%s", "<LSM><ALL32><sys_fchown> THREAD: ", ppath, " FILE: ", fdstr);
    printk("%s\n", procmes32);
    write_to_procfs_str32(procmes32);
    return real_32_sys_fchown(fd,user,group);
}
#endif
/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_fchownat:
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_32_sys_fchownat)(struct pt_regs *regs);

static asmlinkage long fh_32_sys_fchownat(struct pt_regs *regs) {
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid32(exe_path32);
    kernel_filename = duplicate_filename32((void*) regs->si);
    sprintf(procmes32, "%s%s%s%s", "<LSM><ALL32><sys_fchownat> THREAD: ", ppath, " FILE: ", kernel_filename);
    printk("%s\n", procmes32);
    write_to_procfs_str32(procmes32);
    kfree(kernel_filename);
    return real_32_sys_fchownat(regs);
}
#else
static asmlinkage long (*real_32_sys_fchownat)(int dfd, const char __user *filename, uid_t user,
                                               gid_t group, int flag);
static asmlinkage long fh_32_sys_fchownat(int dfd, const char __user *filename, uid_t user,
                                          gid_t group, int flag){
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid32(exe_path32);
    kernel_filename = duplicate_filename32(filename);
    sprintf(procmes32, "%s%s%s%s", "<LSM><ALL32><sys_fchownat> THREAD: ", ppath, " FILE: ", kernel_filename);
    printk("%s\n", procmes32);
    write_to_procfs_str32(procmes32);
    kfree(kernel_filename);
    return real_32_sys_fchownat(dfd,filename,user,group,flag);
}
#endif
/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_chmod:
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_32_sys_chmod)(struct pt_regs *regs);

static asmlinkage long fh_32_sys_chmod(struct pt_regs *regs) {
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid32(exe_path32);
    kernel_filename = duplicate_filename32((void*) regs->di);
    sprintf(procmes32, "%s%s%s%s", "<LSM><ALL32><sys_chmod> THREAD: ", ppath, " FILE: ", kernel_filename);
    printk("%s\n", procmes32);
    write_to_procfs_str32(procmes32);
    kfree(kernel_filename);
    return real_32_sys_chmod(regs);
}
#else
static asmlinkage long (*real_32_sys_chmod)(const char __user *filename, umode_t mode);

static asmlinkage long fh_32_sys_chmod(const char __user *filename, umode_t mode){
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid32(exe_path32);
    kernel_filename = duplicate_filename32(filename);
    sprintf(procmes32, "%s%s%s%s", "<LSM><ALL32><sys_chmod> THREAD: ", ppath, " FILE: ", kernel_filename);
    printk("%s\n", procmes32);
    write_to_procfs_str32(procmes32);
    kfree(kernel_filename);
    return real_32_sys_chmod(filename,mode);
}
#endif
/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_fchmod:
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_32_sys_fchmod)(struct pt_regs *regs);

static asmlinkage long fh_32_sys_fchmod(struct pt_regs *regs) {
    char *ppath;
    unsigned int temp = regs->di;
    char *fdstr = getFilePathByFd32(temp);
    ppath = get_process_name_by_pid32(exe_path32);
    sprintf(procmes32, "%s%s%s%s", "<LSM><ALL32><sys_fchmod> THREAD: ", ppath, " FILE: ", fdstr);
    printk("%s\n", procmes32);
    write_to_procfs_str32(procmes32);
    return real_32_sys_fchmod(regs);
}
#else
static asmlinkage long (*real_32_sys_fchmod)(unsigned int fd, umode_t mode);

static asmlinkage long fh_32_sys_fchmod(unsigned int fd, umode_t mode){
    char *ppath;
    char *fdstr = getFilePathByFd32(fd);
    ppath = get_process_name_by_pid32(exe_path32);
    sprintf(procmes32, "%s%s%s%s", "<LSM><ALL32><sys_fchmod> THREAD: ", ppath, " FILE: ", fdstr);
    printk("%s\n", procmes32);
    write_to_procfs_str32(procmes32);
    return real_32_sys_fchmod(fd,mode);
}
#endif
/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_fchmodat:
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_32_sys_fchmodat)(struct pt_regs *regs);

static asmlinkage long fh_32_sys_fchmodat(struct pt_regs *regs) {
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid32(exe_path32);
    kernel_filename = duplicate_filename32((void*) regs->si);
    sprintf(procmes32, "%s%s%s%s", "<LSM><ALL32><sys_fchmodat> THREAD: ", ppath, " FILE: ", kernel_filename);
    printk("%s\n", procmes32);
    write_to_procfs_str32(procmes32);
    kfree(kernel_filename);
    return real_32_sys_fchmodat(regs);
}
#else
static asmlinkage long (*real_32_sys_fchmodat)(int dfd, const char __user * filename,
                                               umode_t mode);

static asmlinkage long fh_32_sys_fchmodat(int dfd, const char __user * filename,
                                          umode_t mode) {
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid32(exe_path32);
    kernel_filename = duplicate_filename32(filename);
    sprintf(procmes32, "%s%s%s%s", "<LSM><ALL32><sys_fchmodat> THREAD: ", ppath, " FILE: ", kernel_filename);
    printk("%s\n", procmes32);
    write_to_procfs_str32(procmes32);
    kfree(kernel_filename);
    return real_32_sys_fchmodat(dfd,filename,mode);
}
#endif
/////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////fh_32_level 3///////////////////////////////////
// sys_fork:
static asmlinkage long (*real_32_sys_fork)(void);

static asmlinkage long fh_32_sys_fork(void) {
    char *ppath;
    ppath = get_process_name_by_pid32(exe_path32);
    sprintf(procmes32, "%s%s", "<LSM><ALL32><sys_fork> THREAD: ", ppath);
    printk("%s\n", procmes32);
    write_to_procfs_str32(procmes32);
    return real_32_sys_fork();
}

/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_vfork:
static asmlinkage long (*real_32_sys_vfork)(struct pt_regs *regs);

static asmlinkage long fh_32_sys_vfork(struct pt_regs *regs) {
    char *ppath;
    ppath = get_process_name_by_pid32(exe_path32);

    sprintf(procmes32, "%s%s", "<LSM><ALL32><sys_vfork> THREAD: ", ppath);
    printk("%s\n", procmes32);
    write_to_procfs_str32(procmes32);

    return real_32_sys_vfork(regs);
}
/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_execveat:
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_32_stub_execveat)(struct pt_regs *regs);

static asmlinkage long fh_32_stub_execveat(struct pt_regs *regs) {
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid32(exe_path32);
    kernel_filename = duplicate_filename32((void*) regs->si);
    sprintf(procmes32, "%s%s%s%s", "<LSM><ALL32><sys_execveat> THREAD: ", ppath, " FILE: ", kernel_filename);
    printk("%s\n", procmes32);
    write_to_procfs_str32(procmes32);
    kfree(kernel_filename);
    return real_32_stub_execveat(regs);
}
#else
static asmlinkage long (*real_32_stub_execveat)(int dfd, const char __user *filename,
                                                const char __user *const __user *argv,
                                                const char __user *const __user *envp, int flags);

static asmlinkage long fh_32_stub_execveat(int dfd, const char __user *filename,
                                           const char __user *const __user *argv,
                                           const char __user *const __user *envp, int flags) {
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid32(exe_path32);
    kernel_filename = duplicate_filename32(filename);
    sprintf(procmes32, "%s%s%s%s", "<LSM><ALL32><sys_execveat> THREAD: ", ppath, " FILE: ", kernel_filename);
    printk("%s\n", procmes32);
    write_to_procfs_str32(procmes32);
    kfree(kernel_filename);
    return real_32_stub_execveat(dfd,filename,argv,envp,flags);
}
#endif
/////////////////////////////////////////////////////////////////////////////////////////////////

#ifdef PTREGS_SYSCALL_STUBS
#define SYSCALL_NAME32(name) ("__ia32_" name)
#else
#define SYSCALL_NAME32(name) (name)
#endif

#define HOOK32(_name, _function, _original) \
{     \
    .name = SYSCALL_NAME32(_name), \
    .function = (_function), \
    .original = (_original), \
    }



static struct ftrace_hook32 fh_32_level1[] = {
    HOOK32("sys_open", fh_32_sys_open, &real_32_sys_open),
    HOOK32("sys_openat", fh_32_sys_openat, &real_32_sys_openat),
    HOOK32("sys_open_by_handle_at", fh_32_sys_open_by_handle_at, &real_32_sys_open_by_handle_at),
    HOOK32("sys_write", fh_32_sys_write, &real_32_sys_write),
    HOOK32("sys_writev", fh_32_sys_writev, &real_32_sys_writev),
    HOOK32("sys_pwrite64", fh_32_sys_pwrite64, &real_32_sys_pwrite64),
    HOOK32("sys_pwritev", fh_32_sys_pwritev, &real_32_sys_pwritev),
#ifdef  ALLOW_PWRITEV2
    HOOK32("sys_pwritev2", fh_32_sys_pwritev2, &real_32_sys_pwritev2),
#endif
};

static struct ftrace_hook32 fh_32_level2[] = {
    HOOK32("sys_chown", fh_32_sys_chown, &real_32_sys_chown),
    HOOK32("sys_lchown", fh_32_sys_lchown, &real_32_sys_lchown),
    HOOK32("sys_fchown", fh_32_sys_fchown, &real_32_sys_fchown),
    HOOK32("sys_fchownat", fh_32_sys_fchownat, &real_32_sys_fchownat),
    HOOK32("sys_chmod", fh_32_sys_chmod, &real_32_sys_chmod),
    HOOK32("sys_fchmod", fh_32_sys_fchmod, &real_32_sys_fchmod),
    HOOK32("sys_fchmodat", fh_32_sys_fchmodat, &real_32_sys_fchmodat),
};

static struct ftrace_hook32 fh_32_level3[] = {
    HOOK32("sys_fork", fh_32_sys_fork, &real_32_sys_fork),
    HOOK32("sys_vfork", fh_32_sys_vfork, &real_32_sys_vfork),
    HOOK32("sys_execveat", fh_32_stub_execveat, &real_32_stub_execveat),
};

static int fh_32_init(void(*func_for_write_to_pfs_str)(const char *)) {
    write_to_procfs_str32 = func_for_write_to_pfs_str;
    int err;
    printk("%s\n", "<LSM><check_engine32> LSM.ko LOADED");
    return 0;
}

static void fh_32_exit(void) {
    printk("%s\n", "<LSM><check_engine32> LSM.ko UNLOADED");
}



