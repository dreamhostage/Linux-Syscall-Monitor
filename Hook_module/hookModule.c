#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/sched/mm.h>
#include <linux/fdtable.h>
#include <linux/fs.h> 
#include <linux/fs_struct.h>
#include <linux/string.h>
#define USE_FENTRY_OFFSET 1
#define proc_size 16

void (*write_to_procfs_str)(const char* str);
char BlockedProcess[1000];
bool forbidUnloading;
char exe_path [1000];
char procmes[1024];
char processes[proc_size][20] = 
{
    "grep",
    "dmesg",
    "gnome-terminal-",
    "rs:main Q:Reg",
    "gdbus",
    "ibus-daemon",
    "gnome-shell",
    "gmain",
    "ibus-engine-sim",
    "InputThread",
    "Xorg",
    "LSMView",
    "qtcreator",
    "QXcbEventReader",
    "QDBusConnection",
    "at-spi2-registr",
};

_Bool proc_check(char *proc)
{
    int i = 0;
    while(i < proc_size)
    {
        if(!strcmp(processes[i], proc))
            return 0;
        ++i;
    }
    return 1;
}

struct ftrace_hook {
    const char *name;
    void *function;
    void *original;

    unsigned long address;
    struct ftrace_ops ops;
};
static char * getFilePathByFd(unsigned int fd)
{
    char *tmp;
    char *pathname;
    struct file *file;
    struct path *path;

    spin_lock(&current->files->file_lock);
    file = fcheck_files(current->files, fd);

    if (!file)
    {
        spin_unlock(&current->files->file_lock);
        return NULL;
    }

    path = &file->f_path;
    path_get(path);
    spin_unlock(&current->files->file_lock);
    tmp = (char *)__get_free_page(GFP_KERNEL);

    if (!tmp)
    {
        path_put(path);
        return NULL;
    }

    pathname = d_path(path, tmp, PAGE_SIZE);

    if (IS_ERR(pathname))
    {
        free_page((unsigned long)tmp);
        return NULL;
    }

    path_put(path);
    free_page((unsigned long)tmp);
    return pathname;
}

static char* get_process_name_by_pid(char* exe_path)
{
    char * exepathp;
    struct file * exe_file;
    struct mm_struct *mm;

    mm = get_task_mm(current);
    down_read(&mm->mmap_sem);
    exe_file = mm->exe_file;
    if (exe_file) get_file(exe_file);
    up_read(&mm->mmap_sem);

    exepathp = d_path( &(exe_file->f_path), exe_path, 1000);
    return exepathp;
}

static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
    hook->address = kallsyms_lookup_name(hook->name);

    if (!hook->address)
    {
        printk("<LSM><check_engine> unresolved symbol: %s\n", hook->name);
        return -ENOENT;
    }

#if USE_FENTRY_OFFSET
    *((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
    *((unsigned long*) hook->original) = hook->address;
#endif

    return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                    struct ftrace_ops *ops, struct pt_regs *regs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
    regs->ip = (unsigned long) hook->function;
#else
    if (!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long) hook->function;
#endif
}

int fh_install_hook(struct ftrace_hook *hook)
{
    int err;

    err = fh_resolve_hook_address(hook);
    if (err)
    {
        printk("<LSM><check_engine> fh_install_hook ERROR while (fh_resolve_hook_address): %s\n", hook->name);
        return err;
    }

    hook->ops.func = fh_ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
            | FTRACE_OPS_FL_RECURSION_SAFE
            | FTRACE_OPS_FL_IPMODIFY;

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (err)
    {
        printk("<LSM><check_engine> fh_install_hook ERROR while (ftrace_set_filter_ip): %s\n", hook->name);
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if (err)
    {
        printk("<LSM><check_engine> fh_install_hook ERROR while (register_ftrace_function): %s\n", hook->name);
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
        return err;
    }

    return 0;
}


void fh_remove_hook(struct ftrace_hook *hook)
{
    int err;

    err = unregister_ftrace_function(&hook->ops);
    if (err)
    {
        printk("<LSM><check_engine> fh_remove_hook ERROR while (unregister_ftrace_function): %s\n", hook->name);
    }

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    if (err)
    {
        printk("<LSM><check_engine> fh_remove_hook ERROR while (ftrace_set_filter_ip): %s\n", hook->name);
    }
}


int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
    int err;
    size_t i;

    for (i = 0; i < count; i++)
    {
        err = fh_install_hook(&hooks[i]);
        if (err)
        {
            printk("<LSM><check_engine> fh_install_hooks ERROR while (fh_install_hook): %s\n", hooks[i].name);
            goto error;
        }
        else
            printk("<LSM><check_engine> OK.......... %s\n", hooks[i].name);
    }

    return 0;

error:
    while (i != 0) {
        fh_remove_hook(&hooks[--i]);
    }

    return err;
}


void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
    size_t i;

    for (i = 0; i < count; i++)
        fh_remove_hook(&hooks[i]);
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

static char *duplicate_filename(const char __user *filename)
{
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
static asmlinkage long (*real_sys_delete_module)(struct pt_regs *regs);

static asmlinkage long fh_sys_delete_module(struct pt_regs *regs) {
    char *kernel_filename;
    kernel_filename = duplicate_filename((void*) regs->di);
    if (forbidUnloading) {
        if (strcmp(kernel_filename, "LSM") == 0) {
            long ret = 0;
            printk("%s\n", "<LSM><ALL><sys_delete_module> UNLOADING of module LSM.ko was forbidden!");
            write_to_procfs_str("<LSM><ALL><sys_delete_module> UNLOADING of module LSM.ko was forbidden!");
            kfree(kernel_filename);
            return ret;
        } else {
            printk("%s\n", "<LSM><ALL><sys_delete_module> UNLOADING MODULE LSM.ko");
            write_to_procfs_str("<LSM><ALL><sys_delete_module> UNLOADING MODULE LSM.ko");
            kfree(kernel_filename);
            return real_sys_delete_module(regs);
        }
    }
    printk("%s\n", "<LSM><ALL><sys_delete_module> UNLOADING MODULE LSM.ko");
    write_to_procfs_str("<LSM><ALL><sys_delete_module> UNLOADING MODULE LSM.ko");
    kfree(kernel_filename);
    return real_sys_delete_module(regs);
}
#else
static asmlinkage long (*real_sys_delete_module)(const char __user *name_user,
                                                 unsigned int flags);

static asmlinkage long fh_sys_delete_module(const char __user *name_user,
                                            unsigned int flags) {
    char *kernel_filename;
    kernel_filename = duplicate_filename(name_user);
    if (forbidUnloading) {
        if (strcmp(kernel_filename, "LSM") == 0) {
            long ret = 0;
            printk("%s\n", "<LSM><ALL><sys_delete_module> UNLOADING of module LSM.ko was forbidden!");
            write_to_procfs_str("<LSM><ALL><sys_delete_module> UNLOADING of module LSM.ko was forbidden!");
            kfree(kernel_filename);
            return ret;
        } else {
            printk("%s\n", "<LSM><ALL><sys_delete_module> UNLOADING MODULE LSM.ko");
            write_to_procfs_str("<LSM><ALL><sys_delete_module> UNLOADING MODULE LSM.ko");
            kfree(kernel_filename);
            return real_sys_delete_module(name_user,flags);
        }
    }
    printk("%s\n", "<LSM><ALL><sys_delete_module> UNLOADING MODULE LSM.ko");
    write_to_procfs_str("<LSM><ALL><sys_delete_module> UNLOADING MODULE LSM.ko");
    kfree(kernel_filename);
    return real_sys_delete_module(name_user,flags);
}
#endif
/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_execve:
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_execve)(struct pt_regs *regs);

static asmlinkage long fh_sys_execve(struct pt_regs *regs) {
    long ret = 0;
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid(exe_path);
    kernel_filename = duplicate_filename((void*) regs->di);

    if (strstr(BlockedProcess, kernel_filename) != 0) {
        sprintf(procmes, "%s%s%s%s", "<LSM><ALL><sys_execve> THREAD: ", ppath, " BLOCKED PROCESS: ", kernel_filename);
        printk("%s\n", procmes);
        write_to_procfs_str(procmes);
        kfree(kernel_filename);
        return ret;
    } else {
        sprintf(procmes, "%s%s%s%s", "<LSM><ALL><sys_execve> THREAD: ", ppath, " OPENED: ", kernel_filename);
        printk("%s\n", procmes);
        write_to_procfs_str(procmes);
        kfree(kernel_filename);
        return real_sys_execve(regs);
    }
}
#else
static asmlinkage long (*real_sys_execve)(const char __user *filename,
                                          const char __user *const __user *argv,
                                          const char __user *const __user *envp);

static asmlinkage long fh_sys_execve(const char __user *filename,
                                     const char __user *const __user *argv,
                                     const char __user *const __user *envp){
    long ret = 0;
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid(exe_path);
    kernel_filename = duplicate_filename(filename);

    if (strstr(BlockedProcess, kernel_filename) != 0) {
        sprintf(procmes, "%s%s%s%s", "<LSM><ALL><sys_execve> THREAD: ", ppath, " BLOCKED PROCESS: ", kernel_filename);
        printk("%s\n", procmes);
        write_to_procfs_str(procmes);
        kfree(kernel_filename);
        return ret;
    } else {
        sprintf(procmes, "%s%s%s%s", "<LSM><ALL><sys_execve> THREAD: ", ppath, " OPENED: ", kernel_filename);
        printk("%s\n", procmes);
        write_to_procfs_str(procmes);
        kfree(kernel_filename);
        return real_sys_execve(filename,argv,envp);
    }
}
#endif
//////////////////////////////////////////////////////////////////////////////////////////////////////////Level 1///////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_open:
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_open)(struct pt_regs *regs);

static asmlinkage long fh_sys_open(struct pt_regs *regs)
{
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid(exe_path);

    kernel_filename = duplicate_filename((void*) regs->di);

    sprintf(procmes, "%s%s%s%s", "<LSM><ALL><sys_open> THREAD: ", ppath, " OPENED: ", kernel_filename);
    printk("%s\n", procmes);
    write_to_procfs_str(procmes);

    kfree(kernel_filename);
    return real_sys_open(regs);
}
#else
static asmlinkage long (*real_sys_open)(const char __user *filename,
                                        int flags, umode_t mode);
static asmlinkage long fh_sys_open(const char __user *filename,
                                   int flags, umode_t mode)
{
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid(exe_path);

    kernel_filename = duplicate_filename(filename);

    sprintf(procmes, "%s%s%s%s", "<LSM><ALL><sys_open> THREAD: ", ppath, " OPENED: ", kernel_filename);
    printk("%s\n", procmes);
    write_to_procfs_str(procmes);

    kfree(kernel_filename);
    return real_sys_open(filename,flags,mode);
}
#endif
/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_openat:
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_openat)(struct pt_regs *regs);

static asmlinkage long fh_sys_openat(struct pt_regs *regs) {
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid(exe_path);

    kernel_filename = duplicate_filename((void*) regs->si);

    if (strcmp(current->comm, "systemd-journal")) {
        sprintf(procmes, "%s%s%s%s", "<LSM><ALL><sys_openat> THREAD: ", ppath, " OPENED: ", kernel_filename);
        printk("%s\n", procmes);
        write_to_procfs_str(procmes);
    }

    kfree(kernel_filename);

    return real_sys_openat(regs);
}
#else
static asmlinkage long (*real_sys_openat)(int dfd, const char __user *filename, int flags,
                                          umode_t mode);

static asmlinkage long fh_sys_openat(int dfd, const char __user *filename, int flags,
                                     umode_t mode) {
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid(exe_path);

    kernel_filename = duplicate_filename(filename);

    if (strcmp(current->comm, "systemd-journal")) {
        sprintf(procmes, "%s%s%s%s", "<LSM><ALL><sys_openat> THREAD: ", ppath, " OPENED: ", kernel_filename);
        printk("%s\n", procmes);
        write_to_procfs_str(procmes);
    }

    kfree(kernel_filename);

    return real_sys_openat(dfd,filename,flags,mode);
}
#endif
/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_open_by_handle_at:
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_open_by_handle_at)(struct pt_regs *regs);

static asmlinkage long fh_sys_open_by_handle_at(struct pt_regs *regs) {
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid(exe_path);

    kernel_filename = duplicate_filename((void*) regs->si);

    sprintf(procmes, "%s%s%s%s", "<LSM><ALL><sys_open_by_handle_at> THREAD: ", ppath, " OPENED: ", kernel_filename);
    printk("%s\n", procmes);
    write_to_procfs_str(procmes);

    kfree(kernel_filename);

    return real_sys_open_by_handle_at(regs);
}
#else
//!!!!!NOT SURE
static asmlinkage long (*real_sys_open_by_handle_at)(int mountdirfd,
                                                     struct file_handle __user *handle,
                                                     int flags);

static asmlinkage long fh_sys_open_by_handle_at(int mountdirfd,
                                                struct file_handle __user *handle,
                                                int flags) {
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid(exe_path);
    int temp=handle->f_handle;
    char* fdstr=getFilePathByFd(temp);
    sprintf(procmes, "%s%s%s%s", "<LSM><ALL><sys_open_by_handle_at> THREAD: ", ppath, " OPENED: ", fdstr);
    printk("%s\n", procmes);
    write_to_procfs_str(procmes);
    return real_sys_open_by_handle_at(mountdirfd,handle,flags);
}
#endif
/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_write:
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_write)(struct pt_regs *regs);

static asmlinkage long fh_sys_write(struct pt_regs *regs)
{	
    char *fdstr;
    unsigned int temp;
    char *ppath;

    temp = regs->di;
    fdstr = getFilePathByFd(temp);
    ppath = get_process_name_by_pid(exe_path);

    if(proc_check(current->comm))
    {
        sprintf(procmes, "%s%s%s%s", "<LSM><ALL><sys_write> THREAD: ", ppath, " WROTE TO: ", fdstr);
        printk("%s\n", procmes);
        write_to_procfs_str(procmes);
    }

    return real_sys_write(regs);
}
#else
static asmlinkage long (*real_sys_write)(unsigned int fd, const char __user *buf,
                                         size_t count);

static asmlinkage long fh_sys_write(unsigned int fd, const char __user *buf,
                                    size_t count) {
    char *fdstr;
    char *ppath;
    fdstr = getFilePathByFd(fd);
    ppath = get_process_name_by_pid(exe_path);
    if(proc_check(current->comm))
    {
        sprintf(procmes, "%s%s%s%s", "<LSM><ALL><sys_write> THREAD: ", ppath, " WROTE TO: ", fdstr);
        printk("%s\n", procmes);
        write_to_procfs_str(procmes);
    }
    return real_sys_write(fd,buf,count);
}
#endif
/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_writev:
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_writev)(struct pt_regs *regs);

static asmlinkage long fh_sys_writev(struct pt_regs *regs) {
    unsigned int temp = regs->di;
    char *ppath;
    ppath = get_process_name_by_pid(exe_path);
    char *fdstr = getFilePathByFd(temp);
    if(proc_check(current->comm))
    {
        sprintf(procmes, "%s%s%s%s", "<LSM><ALL><sys_writev> THREAD: ", ppath, " WROTE TO: ", fdstr);
        printk("%s\n", procmes);
        write_to_procfs_str(procmes);
    }
    return real_sys_writev(regs);
}
#else
static asmlinkage long (*real_sys_writev)(unsigned long fd,
                                          const struct iovec __user *vec,
                                          unsigned long vlen);

static asmlinkage long fh_sys_writev(unsigned long fd,
                                     const struct iovec __user *vec,
                                     unsigned long vlen) {
    char *ppath;
    ppath = get_process_name_by_pid(exe_path);
    if(proc_check(current->comm))
    {
        char *fdstr = getFilePathByFd(fd);
        sprintf(procmes, "%s%s%s%s", "<LSM><ALL><sys_writev> THREAD: ", ppath, " WROTE TO: ", fdstr);
        printk("%s\n", procmes);
        write_to_procfs_str(procmes);
    }
    return real_sys_writev(fd,vec,vlen);
}
#endif
/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_pwrite64:
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_pwrite64)(struct pt_regs *regs);

static asmlinkage long fh_sys_pwrite64(struct pt_regs *regs)
{	
    char *ppath;
    ppath = get_process_name_by_pid(exe_path);
    unsigned int temp = regs->di;
    char *fdstr=getFilePathByFd(temp);

    if(proc_check(current->comm))
    {
        sprintf(procmes, "%s%s%s%s", "<LSM><ALL><sys_pwrite64> THREAD: ", ppath, " WROTE TO: ", fdstr);
        printk("%s\n", procmes);
        write_to_procfs_str(procmes);
    }

    return real_sys_pwrite64(regs);
}
#else
static asmlinkage long (*real_sys_pwrite64)(unsigned int fd, const char __user *buf,
                                            size_t count, loff_t pos);

static asmlinkage long fh_sys_pwrite64(unsigned int fd, const char __user *buf,
                                       size_t count, loff_t pos) {
    if(proc_check(current->comm))
    {
        char *ppath;
        ppath = get_process_name_by_pid(exe_path);
        char *fdstr = getFilePathByFd(fd);
        sprintf(procmes, "%s%s%s%s", "<LSM><ALL><sys_pwrite64> THREAD: ", ppath, " WROTE TO: ", fdstr);
        printk("%s\n", procmes);
        write_to_procfs_str(procmes);
    }
    return real_sys_pwrite64(fd,buf,count,pos);
}
#endif
/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_pwritev:
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_pwritev)(struct pt_regs *regs);

static asmlinkage long fh_sys_pwritev(struct pt_regs *regs)
{	
    unsigned int temp = regs->di;
    char *ppath;
    ppath = get_process_name_by_pid(exe_path);
    char *fdstr=getFilePathByFd(temp);

    if(proc_check(current->comm))
    {
        sprintf(procmes, "%s%s%s%s", "<LSM><ALL><sys_pwritev> THREAD: ", ppath, " WROTE TO: ", fdstr);
        printk("%s\n", procmes);
        write_to_procfs_str(procmes);
    }

    return real_sys_pwritev(regs);
}
#else
static asmlinkage long (*real_sys_pwritev)(unsigned int fd, const char __user *buf,
                                           size_t count, loff_t pos);

static asmlinkage long fh_sys_pwritev(unsigned int fd, const char __user *buf,
                                      size_t count, loff_t pos){
    if(proc_check(current->comm))
    {
        char *ppath;
        ppath = get_process_name_by_pid(exe_path);
        char *fdstr = getFilePathByFd(fd);
        sprintf(procmes, "%s%s%s%s", "<LSM><ALL><sys_pwritev> THREAD: ", ppath, " WROTE TO: ", fdstr);
        printk("%s\n", procmes);
        write_to_procfs_str(procmes);
    }
    return real_sys_pwritev(fd,buf,count,pos);
}
#endif
/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_pwritev2:
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_pwritev2)(struct pt_regs *regs);

static asmlinkage long fh_sys_pwritev2(struct pt_regs *regs)
{	
    unsigned int temp = regs->di;
    char *ppath;
    ppath = get_process_name_by_pid(exe_path);
    char *fdstr=getFilePathByFd(temp);

    if(proc_check(current->comm))
    {
        sprintf(procmes, "%s%s%s%s", "<LSM><ALL><sys_pwritev2> THREAD: ", ppath, " WROTE TO: ", fdstr);
        printk("%s\n", procmes);
        write_to_procfs_str(procmes);
    }

    return real_sys_pwritev2(regs);
}
#endif
//!!!!!STARTS FROM 4.6!!!!!!!!!!!
#ifdef  ALLOW_PWRITEV2
static asmlinkage long (*real_sys_pwritev2)(unsigned long fd, const struct iovec __user *vec,
                                            unsigned long vlen, unsigned long pos_l, unsigned long pos_h,
                                            int flags);

static asmlinkage long fh_sys_pwritev2(unsigned long fd, const struct iovec __user *vec,
                                       unsigned long vlen, unsigned long pos_l, unsigned long pos_h,
                                       int flags){
    if(proc_check(current->comm))
    {
        char *ppath;
        ppath = get_process_name_by_pid(exe_path);
        char *fdstr = getFilePathByFd(fd);
        sprintf(procmes, "%s%s%s%s", "<LSM><ALL><sys_pwritev2> THREAD: ", ppath, " WROTE TO: ", fdstr);
        printk("%s\n", procmes);
        write_to_procfs_str(procmes);
    }
    return real_sys_pwritev2(fd,vec,vlen,pos_l,pos_h,flags);
}
#endif
//////////////////////////////////////////////////////////////////////////////////////////////////////////Level 2///////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_chown:
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_chown)(struct pt_regs *regs);

static asmlinkage long fh_sys_chown(struct pt_regs *regs)
{	
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid(exe_path);
    kernel_filename = duplicate_filename((void*) regs->di);
    sprintf(procmes, "%s%s%s%s", "<LSM><ALL><sys_chown> THREAD: ", ppath, " FILE: ", kernel_filename);
    printk("%s\n", procmes);
    write_to_procfs_str(procmes);
    kfree(kernel_filename);
    return real_sys_chown(regs);
}
#else
static asmlinkage long (*real_sys_chown)(const char __user *filename,
                                         uid_t user, gid_t group);

static asmlinkage long fh_sys_chown(const char __user *filename,
                                    uid_t user, gid_t group) {
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid(exe_path);
    kernel_filename = duplicate_filename(filename);
    sprintf(procmes, "%s%s%s%s", "<LSM><ALL><sys_chown> THREAD: ", ppath, " FILE: ", kernel_filename);
    printk("%s\n", procmes);
    write_to_procfs_str(procmes);
    kfree(kernel_filename);
    return real_sys_chown(filename,user,group);
}
#endif
/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_lchown:
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_lchown)(struct pt_regs *regs);

static asmlinkage long fh_sys_lchown(struct pt_regs *regs)
{	
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid(exe_path);
    kernel_filename = duplicate_filename((void*) regs->di);
    sprintf(procmes, "%s%s%s%s", "<LSM><ALL><sys_lchown> THREAD: ", ppath, " FILE: ", kernel_filename);
    printk("%s\n", procmes);
    write_to_procfs_str(procmes);
    kfree(kernel_filename);
    return real_sys_lchown(regs);
}
#else
static asmlinkage long (*real_sys_lchown)(const char __user *filename,
                                          uid_t user, gid_t group);

static asmlinkage long fh_sys_lchown(const char __user *filename,
                                     uid_t user, gid_t group) {
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid(exe_path);
    kernel_filename = duplicate_filename(filename);
    sprintf(procmes, "%s%s%s%s", "<LSM><ALL><sys_lchown> THREAD: ", ppath, " FILE: ", kernel_filename);
    printk("%s\n", procmes);
    write_to_procfs_str(procmes);
    kfree(kernel_filename);
    return real_sys_lchown(filename,user,group);
}
#endif
/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_fchown:
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_fchown)(struct pt_regs *regs);

static asmlinkage long fh_sys_fchown(struct pt_regs *regs)
{	
    unsigned int temp = regs->di;
    char *ppath;
    ppath = get_process_name_by_pid(exe_path);
    char *fdstr=getFilePathByFd(temp);
    sprintf(procmes, "%s%s%s%s", "<LSM><ALL><sys_fchown> THREAD: ", ppath, " FILE: ", fdstr);
    printk("%s\n", procmes);
    write_to_procfs_str(procmes);
    return real_sys_fchown(regs);
}
#else
static asmlinkage long (*real_sys_fchown)(unsigned int fd, uid_t user, gid_t group);

static asmlinkage long fh_sys_fchown(unsigned int fd, uid_t user, gid_t group) {
    char *ppath;
    ppath = get_process_name_by_pid(exe_path);
    char *fdstr = getFilePathByFd(fd);
    sprintf(procmes, "%s%s%s%s", "<LSM><ALL><sys_fchown> THREAD: ", ppath, " FILE: ", fdstr);
    printk("%s\n", procmes);
    write_to_procfs_str(procmes);
    return real_sys_fchown(fd,user,group);
}
#endif
/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_fchownat:
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_fchownat)(struct pt_regs *regs);

static asmlinkage long fh_sys_fchownat(struct pt_regs *regs)
{	
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid(exe_path);
    kernel_filename = duplicate_filename((void*) regs->si);
    sprintf(procmes, "%s%s%s%s", "<LSM><ALL><sys_fchownat> THREAD: ", ppath, " FILE: ", kernel_filename);
    printk("%s\n", procmes);
    write_to_procfs_str(procmes);
    kfree(kernel_filename);
    return real_sys_fchownat(regs);
}
#else
static asmlinkage long (*real_sys_fchownat)(int dfd, const char __user *filename, uid_t user,
                                            gid_t group, int flag);
static asmlinkage long fh_sys_fchownat(int dfd, const char __user *filename, uid_t user,
                                       gid_t group, int flag){
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid(exe_path);
    kernel_filename = duplicate_filename(filename);
    sprintf(procmes, "%s%s%s%s", "<LSM><ALL><sys_fchownat> THREAD: ", ppath, " FILE: ", kernel_filename);
    printk("%s\n", procmes);
    write_to_procfs_str(procmes);
    kfree(kernel_filename);
    return real_sys_fchownat(dfd,filename,user,group,flag);
}
#endif
/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_chmod:
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_chmod)(struct pt_regs *regs);

static asmlinkage long fh_sys_chmod(struct pt_regs *regs)
{	
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid(exe_path);
    kernel_filename = duplicate_filename((void*) regs->di);
    sprintf(procmes, "%s%s%s%s", "<LSM><ALL><sys_chmod> THREAD: ", ppath, " FILE: ", kernel_filename);
    printk("%s\n", procmes);
    write_to_procfs_str(procmes);
    kfree(kernel_filename);
    return real_sys_chmod(regs);
}
#else
static asmlinkage long (*real_sys_chmod)(const char __user *filename, umode_t mode);
static asmlinkage long fh_sys_chmod(const char __user *filename, umode_t mode){
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid(exe_path);
    kernel_filename = duplicate_filename(filename);
    sprintf(procmes, "%s%s%s%s", "<LSM><ALL><sys_chmod> THREAD: ", ppath, " FILE: ", kernel_filename);
    printk("%s\n", procmes);
    write_to_procfs_str(procmes);
    kfree(kernel_filename);
    return real_sys_chmod(filename,mode);
}
#endif
/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_fchmod:
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_fchmod)(struct pt_regs *regs);

static asmlinkage long fh_sys_fchmod(struct pt_regs *regs)
{	
    char *ppath;
    unsigned int temp = regs->di;
    char *fdstr=getFilePathByFd(temp);
    ppath = get_process_name_by_pid(exe_path);
    sprintf(procmes, "%s%s%s%s", "<LSM><ALL><sys_fchmod> THREAD: ", ppath, " FILE: ", fdstr);
    printk("%s\n", procmes);
    write_to_procfs_str(procmes);
    return real_sys_fchmod(regs);
}
#else
static asmlinkage long (*real_sys_fchmod)(unsigned int fd, umode_t mode);

static asmlinkage long fh_sys_fchmod(unsigned int fd, umode_t mode){
    char *ppath;
    char *fdstr = getFilePathByFd(fd);
    ppath = get_process_name_by_pid(exe_path);
    sprintf(procmes, "%s%s%s%s", "<LSM><ALL><sys_fchmod> THREAD: ", ppath, " FILE: ", fdstr);
    printk("%s\n", procmes);
    write_to_procfs_str(procmes);
    return real_sys_fchmod(fd,mode);
}
#endif

/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_fchmodat:
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_fchmodat)(struct pt_regs *regs);

static asmlinkage long fh_sys_fchmodat(struct pt_regs *regs)
{	
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid(exe_path);
    kernel_filename = duplicate_filename((void*) regs->si);
    sprintf(procmes, "%s%s%s%s", "<LSM><ALL><sys_fchmodat> THREAD: ", ppath, " FILE: ", kernel_filename);
    printk("%s\n", procmes);
    write_to_procfs_str(procmes);
    kfree(kernel_filename);
    return real_sys_fchmodat(regs);
}
#else
static asmlinkage long (*real_sys_fchmodat)(int dfd, const char __user * filename,
                                            umode_t mode);

static asmlinkage long fh_sys_fchmodat(int dfd, const char __user * filename,
                                       umode_t mode) {
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid(exe_path);
    kernel_filename = duplicate_filename(filename);
    sprintf(procmes, "%s%s%s%s", "<LSM><ALL><sys_fchmodat> THREAD: ", ppath, " FILE: ", kernel_filename);
    printk("%s\n", procmes);
    write_to_procfs_str(procmes);
    kfree(kernel_filename);
    return real_sys_fchmodat(dfd,filename,mode);
}
#endif

/////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////Level 3///////////////////////////////////
// sys_fork:
static asmlinkage long (*real_sys_fork)(void);

static asmlinkage long fh_sys_fork(void)
{
    char *ppath;
    ppath = get_process_name_by_pid(exe_path);
    sprintf(procmes, "%s%s", "<LSM><ALL><sys_fork> THREAD: ", ppath);
    printk("%s\n", procmes);
    write_to_procfs_str(procmes);
    return real_sys_fork();
}
/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_vfork:
static asmlinkage long (*real_sys_vfork)(struct pt_regs *regs);

static asmlinkage long fh_sys_vfork(struct pt_regs *regs)
{
    char *ppath;
    ppath = get_process_name_by_pid(exe_path);

    sprintf(procmes, "%s%s", "<LSM><ALL><sys_vfork> THREAD: ", ppath);
    printk("%s\n", procmes);
    write_to_procfs_str(procmes);

    return real_sys_vfork(regs);
}
/////////////////////////////////////////////////////////////////////////////////////////////////
// sys_execveat:
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_stub_execveat)(struct pt_regs *regs);

static asmlinkage long fh_stub_execveat(struct pt_regs *regs)
{	
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid(exe_path);
    kernel_filename = duplicate_filename((void*) regs->si);
    sprintf(procmes, "%s%s%s%s", "<LSM><ALL><sys_execveat> THREAD: ", ppath, " FILE: ", kernel_filename);
    printk("%s\n", procmes);
    write_to_procfs_str(procmes);
    kfree(kernel_filename);
    return real_stub_execveat(regs);
}
#else
static asmlinkage long (*real_stub_execveat)(int dfd, const char __user *filename,
                                             const char __user *const __user *argv,
                                             const char __user *const __user *envp, int flags);

static asmlinkage long fh_stub_execveat(int dfd, const char __user *filename,
                                        const char __user *const __user *argv,
                                        const char __user *const __user *envp, int flags) {
    char *kernel_filename;
    char *ppath;
    ppath = get_process_name_by_pid(exe_path);
    kernel_filename = duplicate_filename(filename);
    sprintf(procmes, "%s%s%s%s", "<LSM><ALL><sys_execveat> THREAD: ", ppath, " FILE: ", kernel_filename);
    printk("%s\n", procmes);
    write_to_procfs_str(procmes);
    kfree(kernel_filename);
    return real_stub_execveat(dfd,filename,argv,envp,flags);
}
#endif
/////////////////////////////////////////////////////////////////////////////////////////////////

#ifdef PTREGS_SYSCALL_STUBS
#define SYSCALL_NAME(name) ("__x64_" name)
#else
#define SYSCALL_NAME(name) (name)
#endif

#define HOOK(_name, _function, _original)	\
{					\
    .name = SYSCALL_NAME(_name),	\
    .function = (_function),	\
    .original = (_original),	\
    }
static struct ftrace_hook terminate_process = HOOK("sys_execve", fh_sys_execve, &real_sys_execve);
static struct ftrace_hook forbid_unload_module = HOOK("sys_delete_module", fh_sys_delete_module, &real_sys_delete_module);

static struct ftrace_hook level1[] = 
{
    HOOK("sys_open", fh_sys_open, &real_sys_open),
    HOOK("sys_openat", fh_sys_openat, &real_sys_openat),
    HOOK("sys_open_by_handle_at", fh_sys_open_by_handle_at, &real_sys_open_by_handle_at),
    HOOK("sys_write", fh_sys_write, &real_sys_write),
    HOOK("sys_writev", fh_sys_writev, &real_sys_writev),
    HOOK("sys_pwrite64", fh_sys_pwrite64, &real_sys_pwrite64),
    HOOK("sys_pwritev", fh_sys_pwritev, &real_sys_pwritev),
#ifdef  ALLOW_PWRITEV2
    HOOK("sys_pwritev2", fh_sys_pwritev2, &real_sys_pwritev2),
#endif
};

static struct ftrace_hook level2[] = 
{
    HOOK("sys_chown", fh_sys_chown, &real_sys_chown),
    HOOK("sys_lchown", fh_sys_lchown, &real_sys_lchown),
    HOOK("sys_fchown", fh_sys_fchown, &real_sys_fchown),
    HOOK("sys_fchownat", fh_sys_fchownat, &real_sys_fchownat),
    HOOK("sys_chmod", fh_sys_chmod, &real_sys_chmod),
    HOOK("sys_fchmod", fh_sys_fchmod, &real_sys_fchmod),
    HOOK("sys_fchmodat", fh_sys_fchmodat, &real_sys_fchmodat),
};

static struct ftrace_hook level3[] = 
{
    HOOK("sys_fork", fh_sys_fork, &real_sys_fork),
    HOOK("sys_vfork", fh_sys_vfork, &real_sys_vfork),
    HOOK("sys_execveat", fh_stub_execveat, &real_stub_execveat),
};

static int fh_init(void(*func_for_write_to_pfs_str)(const char *))
{
    write_to_procfs_str=func_for_write_to_pfs_str;
    int err;
    forbidUnloading = false;

    err = fh_install_hook(&terminate_process);
    if (err)
    {
        printk("%s\n","<LSM><check_engine> ERROR of installing terminate_process HOOK");
        return err;
    }

    err = fh_install_hook(&forbid_unload_module);
    if (err)
    {
        printk("%s\n","<LSM><check_engine> ERROR of installing forbid_unload_module HOOK");
        return err;
    }

    printk("%s\n", "<LSM><check_engine> LSM.ko LOADED");

    return 0;
}

static void fh_exit(void)
{
    fh_remove_hook(&terminate_process);
    fh_remove_hook(&forbid_unload_module);

    printk("%s\n", "<LSM><check_engine> LSM.ko UNLOADED");
}



