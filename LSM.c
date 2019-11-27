/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include <linux/module.h>


#include "procfsprov.c"
#define DEBUG_MMODE
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Linux Syscall Monitor");

static int module_start(void)
{
    pfs_init();
    printk( "<LSM><ALL> Syscall Monitor started...\n");
    return 0;
}

static void module_close(void)
{
    pfs_exit();
    printk( "<LSM><ALL> Syscall Monitor stopped ...\n");
}

module_init(module_start);
module_exit(module_close);

