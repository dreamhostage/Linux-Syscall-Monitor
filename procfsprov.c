#include <linux/proc_fs.h>
#include "syscallregister.c"

#define BUFSIZE  100
#define MAX_ONE_RECORD_LENGTH 100
const char * cmdStartLogging = "startlogging";
const char * cmdStopLogging = "stoplogging";
const char * cmdSetLoggingLevel = "setlogginglevel";
const char * cmdBlockFile = "block";
const char * cmdUnBlockFIle = "unblock";
const char * cmdForbidUnloading = "allowunload";
const char * cmd32Enable = "startlogging32";
const char * cmd32Disable = "stoplogging32";

bool isBufWasFull = false;
char* buffer_for_read[BUFSIZE];
unsigned int buf_pos = 0;
static struct proc_dir_entry *ent;
static void pfs_write_to_procfs_str(const char* str_to_write);

static void pfs_write_to_log(const char * str) {
    if (str == NULL) return;
    pfs_write_to_procfs_str(str);
}
//Offset amount of words after searched text =-1 for unlimited

static bool m_prfs_check_str(const char* strReaded, const char*strToComp, unsigned int offset) {
    char *firstInner = strstr(strReaded, strToComp);
    if (firstInner == strReaded) {
        if (((strlen(strReaded) == strlen(strToComp) + offset) || strchr(strReaded, '\n') == strReaded + strlen(strToComp) + offset)
                || (offset == -1)) {
            return true;
        }
    }
    return false;

}

static ssize_t m_pfs_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos) {
    int num;
    const char buf[count];
    if (*ppos > 0 || count > BUFSIZE)
        return -EFAULT;
    if (copy_from_user(buf, ubuf, count))
        return -EFAULT;
    char *firstInner = strstr(buf, cmdSetLoggingLevel);
    *ppos = strlen(buf);
    //check the string is eqaul from the start
    if (m_prfs_check_str(buf, cmdSetLoggingLevel, 2)) {
        int logLev = (int) buf[strlen(cmdSetLoggingLevel) + 1] - '0';
        if (!srg_set_log_level(logLev)) pfs_write_to_log("<LSM><ALL><COMMAND> Error set level\n");
        else pfs_write_to_log("<LSM><ALL><COMMAND> Set new log levevl\n");
        return *ppos;
    }

    firstInner = strstr(buf, cmdBlockFile);
    if (m_prfs_check_str(buf, cmdBlockFile, -1)) {
        firstInner = strchr(buf, ' ');
        //if there is space 
        if (firstInner != cmdBlockFile + strlen(cmdBlockFile)) {
            if (filp_open(firstInner, O_RDONLY, 0) == NULL)
                pfs_write_to_log("<LSM><ALL><COMMAND> Cant block file. No such file\n");
            else {

                pfs_write_to_log("<LSM><ALL><COMMAND> Start blocking file:\n");
                strcpy(BlockedProcess, firstInner);
            }
        }
        return *ppos;
    }
    if (m_prfs_check_str(buf, cmdUnBlockFIle, 0)) {
        pfs_write_to_log("<LSM><ALL><COMMAND> Unblcok file\n");
        strcpy(BlockedProcess, "");
        return *ppos;
    }
    if (m_prfs_check_str(buf, cmdStartLogging, 0)) {
        pfs_write_to_log("<LSM><ALL><COMMAND> Start logging\n");
        srg_enable_logging(true);
        return *ppos;
    }
    if (m_prfs_check_str(buf, cmdStopLogging, 0)) {
        pfs_write_to_log("<LSM><ALL><COMMAND> Stop logging\n");
        srg_enable_logging(false);
        return *ppos;
    }
    if (m_prfs_check_str(buf, cmdForbidUnloading, 2)) {
        int allowUnload = (int) buf[strlen(cmdForbidUnloading) + 1] - '0';
        if (allowUnload == 1) {
            forbidUnloading = true;
            pfs_write_to_log("<LSM><ALL><COMMAND> Set forbid unloading true\n");
        } else if (allowUnload == 0) {
            forbidUnloading = false;
            pfs_write_to_log("<LSM><ALL><COMMAND> Set forbid unloading false\n");
        } else
            pfs_write_to_log("<LSM><ALL><COMMAND> Error set forbid unloading wrong parameter\n");
        return *ppos;
    }
    if (m_prfs_check_str(buf, cmd32Enable, 0)) {
        pfs_write_to_log("<LSM><ALL><COMMAND> Start logging32\n");
        srg_enable_logging32bit(true);
        return *ppos;
    }
    if (m_prfs_check_str(buf, cmd32Disable, 0)) {
        pfs_write_to_log("<LSM><ALL><COMMAND> Stop logging32\n");
        srg_enable_logging32bit(false);
        return *ppos;
    }

    pfs_write_to_log(buf);
    return *ppos;
}

static void pfs_write_to_procfs_str(const char* str_to_write) {
    unsigned int size_of_str = strlen(str_to_write);
    int addonSize = 1;
    if (size_of_str < 1) return;
    if (size_of_str > MAX_ONE_RECORD_LENGTH) size_of_str = MAX_ONE_RECORD_LENGTH;
    bool addEnd = false;
    if (str_to_write[size_of_str - 1] != '\n') {
        addEnd = true;
        addonSize = 2;
    }
    if (isBufWasFull)
        buffer_for_read[buf_pos] = krealloc(buffer_for_read[buf_pos], (size_of_str + addonSize) * sizeof (char), GFP_KERNEL);
    else
        buffer_for_read[buf_pos] = kmalloc((size_of_str + addonSize) * sizeof (char), GFP_KERNEL);
    if (!buffer_for_read[buf_pos]) {
        printk("<LSM><SYSTEM> Cant alloc mememory");
        return;
    }
    strncpy(buffer_for_read[buf_pos], str_to_write, size_of_str);
    if (addEnd) {
        *(buffer_for_read[buf_pos] + size_of_str * sizeof (char)) = '\n';
        *(buffer_for_read[buf_pos]+(size_of_str + 1) * sizeof (char)) = '\0';
    } else {
        *(buffer_for_read[buf_pos] + size_of_str * sizeof (char)) = '\0';
    }
    buf_pos++;
    if (buf_pos == BUFSIZE) {
        isBufWasFull = true;
        buf_pos = 0;
    }


}

static ssize_t m_pfs_read(struct file *file, char __user *ubuf, size_t count, loff_t *ppos) {
    int len = 0;

    if (*ppos > 0)
        return 0;
    int i = 0;
    if (isBufWasFull) {
        for (i = buf_pos; i < BUFSIZE; i++) {
            if (copy_to_user(ubuf + len, buffer_for_read[i], strlen(buffer_for_read[i])))
                return -EFAULT;
            len += strlen(buffer_for_read[i]);
        }
    }
    for (i = 0; i < buf_pos; ++i) {
        if (copy_to_user(ubuf + len, buffer_for_read[i], strlen(buffer_for_read[i])))
            return -EFAULT;
        len += strlen(buffer_for_read[i]);

    }

    *ppos = len;
    return len;
}

static struct file_operations myops ={
    .owner = THIS_MODULE,
    .read = m_pfs_read,
    .write = m_pfs_write,
};

static void m_pfs_clear_buffer(void) {

    int i, lastElem;
    if (isBufWasFull)
        lastElem = BUFSIZE;
    else
        lastElem = buf_pos;
    for (i = 0; i < lastElem; i++)
        if (buffer_for_read[i])
            kfree(buffer_for_read[i]);
}

static int pfs_init(void) {
    ent = proc_create("ActMon", 0777, NULL, &myops);
    printk(KERN_ALERT "<LSM><ALL><COMMAND> LSM procfs started...\n");
    fh_init(pfs_write_to_log);
    fh_32_init(pfs_write_to_log);
    return 0;
}

static void pfs_exit(void) {
    proc_remove(ent);
    m_pfs_clear_buffer();
    srg_set_log_level(0);
    fh_exit();
    fh_32_exit();
    printk(KERN_ALERT "<LSM><ALL><COMMAND> LSM procfs stoped ...\n");
}



