#include "type.h"
#include "stdio.h"
#include "const.h"
#include "protect.h"
#include "string.h"
#include "fs.h"
#include "proc.h"
#include "tty.h"
#include "console.h"
#include "global.h"
#include "proto.h"
#include <time.h>
#include <string.h>

#define MAXIMUS 10

/*****************************************************************************
 *                               kernel_main
 *****************************************************************************/
/**
 * jmp from kernel.asm::_start. 
 * 
 *****************************************************************************/

//char __path[128][128];
//int __pathCount;

PUBLIC int kernel_main()
{
	//disp_str("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");

	int i, j, eflags, prio;
        u8  rpl;
        u8  priv; /* privilege */

	struct task * t;
	struct proc * p = proc_table;

	char * stk = task_stack + STACK_SIZE_TOTAL;

	for (i = 0; i < NR_TASKS + NR_PROCS; i++,p++,t++) {
		if (i >= NR_TASKS + NR_NATIVE_PROCS) {
			p->p_flags = FREE_SLOT;
			continue;
		}

	        if (i < NR_TASKS) {     /* TASK */
                        t	= task_table + i;
                        priv	= PRIVILEGE_TASK;
                        rpl     = RPL_TASK;
                        eflags  = 0x1202;/* IF=1, IOPL=1, bit 2 is always 1 */
			prio    = 15;
                }
                else {                  /* USER PROC */
                        t	= user_proc_table + (i - NR_TASKS);
                        priv	= PRIVILEGE_USER;
                        rpl     = RPL_USER;
                        eflags  = 0x202;	/* IF=1, bit 2 is always 1 */
			prio    = 5;
                }

		strcpy(p->name, t->name);	/* name of the process */
		p->p_parent = NO_TASK;

		if (strcmp(t->name, "INIT") != 0) {
			p->ldts[INDEX_LDT_C]  = gdt[SELECTOR_KERNEL_CS >> 3];
			p->ldts[INDEX_LDT_RW] = gdt[SELECTOR_KERNEL_DS >> 3];

			/* change the DPLs */
			p->ldts[INDEX_LDT_C].attr1  = DA_C   | priv << 5;
			p->ldts[INDEX_LDT_RW].attr1 = DA_DRW | priv << 5;
		}
		else {		/* INIT process */
			unsigned int k_base;
			unsigned int k_limit;
			int ret = get_kernel_map(&k_base, &k_limit);
			assert(ret == 0);
			init_desc(&p->ldts[INDEX_LDT_C],
				  0, /* bytes before the entry point
				      * are useless (wasted) for the
				      * INIT process, doesn't matter
				      */
				  (k_base + k_limit) >> LIMIT_4K_SHIFT,
				  DA_32 | DA_LIMIT_4K | DA_C | priv << 5);

			init_desc(&p->ldts[INDEX_LDT_RW],
				  0, /* bytes before the entry point
				      * are useless (wasted) for the
				      * INIT process, doesn't matter
				      */
				  (k_base + k_limit) >> LIMIT_4K_SHIFT,
				  DA_32 | DA_LIMIT_4K | DA_DRW | priv << 5);
		}

		p->regs.cs = INDEX_LDT_C << 3 |	SA_TIL | rpl;
		p->regs.ds =
			p->regs.es =
			p->regs.fs =
			p->regs.ss = INDEX_LDT_RW << 3 | SA_TIL | rpl;
		p->regs.gs = (SELECTOR_KERNEL_GS & SA_RPL_MASK) | rpl;
		p->regs.eip	= (u32)t->initial_eip;
		p->regs.esp	= (u32)stk;
		p->regs.eflags	= eflags;

		p->ticks = p->priority = prio;

		p->p_flags = 0;
		p->p_msg = 0;
		p->p_recvfrom = NO_TASK;
		p->p_sendto = NO_TASK;
		p->has_int_msg = 0;
		p->q_sending = 0;
		p->next_sending = 0;

		for (j = 0; j < NR_FILES; j++)
			p->filp[j] = 0;

		stk -= t->stacksize;
	}

	k_reenter = 0;
	ticks = 0;

	p_proc_ready	= proc_table;

	init_clock();
        init_keyboard();

	restart();

	while(1){}
}


/*****************************************************************************
 *                                get_ticks
 *****************************************************************************/
PUBLIC int get_ticks()
{
	MESSAGE msg;
	reset_msg(&msg);
	msg.type = GET_TICKS;
	send_recv(BOTH, TASK_SYS, &msg);
	return msg.RETVAL;
}


/**
 * @struct posix_tar_header
 * Borrowed from GNU `tar'
 */
struct posix_tar_header
{				/* byte offset */
	char name[100];		/*   0 */
	char mode[8];		/* 100 */
	char uid[8];		/* 108 */
	char gid[8];		/* 116 */
	char size[12];		/* 124 */
	char mtime[12];		/* 136 */
	char chksum[8];		/* 148 */
	char typeflag;		/* 156 */
	char linkname[100];	/* 157 */
	char magic[6];		/* 257 */
	char version[2];	/* 263 */
	char uname[32];		/* 265 */
	char gname[32];		/* 297 */
	char devmajor[8];	/* 329 */
	char devminor[8];	/* 337 */
	char prefix[155];	/* 345 */
	/* 500 */
};

/*****************************************************************************
 *                                untar
 *****************************************************************************/
/**
 * Extract the tar file and store them.
 * 
 * @param filename The tar file.
 *****************************************************************************/
void untar(const char * filename)
{
	printf("[extract `%s'\n", filename);
	int fd = open(filename, O_RDWR);
	assert(fd != -1);

	char buf[SECTOR_SIZE * 16];
	int chunk = sizeof(buf);
	int i = 0;
	int bytes = 0;

	while (1) {
		bytes = read(fd, buf, SECTOR_SIZE);
		assert(bytes == SECTOR_SIZE); /* size of a TAR file
					       * must be multiple of 512
					       */
		if (buf[0] == 0) {
			if (i == 0)
				printf("    need not unpack the file.\n");
			break;
		}
		i++;

		struct posix_tar_header * phdr = (struct posix_tar_header *)buf;

		/* calculate the file size */
		char * p = phdr->size;
		int f_len = 0;
		while (*p)
			f_len = (f_len * 8) + (*p++ - '0'); /* octal */

		int bytes_left = f_len;
		int fdout = open(phdr->name, O_CREAT | O_RDWR | O_TRUNC);
		if (fdout == -1) {
			printf("    failed to extract file: %s\n", phdr->name);
			printf(" aborted]\n");
			close(fd);
			return;
		}
		printf("    %s\n", phdr->name);
		while (bytes_left) {
			int iobytes = min(chunk, bytes_left);
			read(fd, buf,
			     ((iobytes - 1) / SECTOR_SIZE + 1) * SECTOR_SIZE);
			bytes = write(fdout, buf, iobytes);
			assert(bytes == iobytes);
			bytes_left -= iobytes;
		}
		close(fdout);
	}

	if (i) {
		lseek(fd, 0, SEEK_SET);
		buf[0] = 0;
		bytes = write(fd, buf, 1);
		assert(bytes == 1);
	}

	close(fd);

	printf(" done, %d files extracted]\n", i);
}

/*****************************************************************************
 *                                shabby_shell
 *****************************************************************************/
/**
 * A very very simple shell.
 * 
 * @param tty_name  TTY file name.
 *****************************************************************************/
/*void shabby_shell(const char * tty_name)
{
	int fd_stdin  = open(tty_name, O_RDWR);
	assert(fd_stdin  == 0);
	int fd_stdout = open(tty_name, O_RDWR);
	assert(fd_stdout == 1);

	char rdbuf[128];

	while (1) {
		write(1, "$ ", 2);
		int r = read(0, rdbuf, 70);
		rdbuf[r] = 0;

		int argc = 0;
		char * argv[PROC_ORIGIN_STACK];
		char * p = rdbuf;
		char * s;
		int word = 0;
		char ch;
		do {
			ch = *p;
			if (*p != ' ' && *p != 0 && !word) {
				s = p;
				word = 1;
			}
			if ((*p == ' ' || *p == 0) && word) {
				word = 0;
				argv[argc++] = s;
				*p = 0;
			}
			p++;
		} while(ch);
		argv[argc] = 0;

		int fd = open(argv[0], O_RDWR);
		if (fd == -1) {
			if (rdbuf[0]) {
				write(1, "{", 1);
				write(1, rdbuf, r);
				write(1, "}\n", 2);
			}
		}
		else {
			close(fd);
			int pid = fork();
			if (pid != 0) { 
 //parent 
				int s;
				wait(&s);
			}
			else {	
// child 
				execv(argv[0], argv);
			}
		}
	}

	close(1);
	close(0);
} */
char* findpass(char *src)
{
    char *pass;
    int flag = 0;
    char *p1, *p2;

    p1 = src;
    p2 = pass;

    while (p1 && *p1 != ' ')
    {
        if (*p1 == ':')
            flag = 1;

        if (flag && *p1 != ':')
        {
            *p2 = *p1;
            p2++;
        }
        p1++;
    }
    *p2 = '\0';

    return pass;
}

char * strstr(char * in, const char *str)
{
    //不存在空密码的情况
    char *p1 = in, *temp1, *temp2;

    int t = 0;

    int len = strlen(str);
    //循环p2
    while (p1 != 0 && *p1 != '\0')
    {
        //指到开头
        temp1 = p1;
        temp2 = str;

        while (temp1!=0 && temp2!=0 && *temp1 == *temp2)
        {
            temp1++;
            temp2++;
        }
        //temp2指向了空，表示成功
        if (!temp2 || *temp2 == '\0')
            return p1;
        p1++;
    }

    return 0;
}


void login(int fd_stdin, int fd_stdout, int *isLogin, char *user, char *pass)
{
    char username[128];
    char password[128];
    int step = 0;
    int fd;

    char passwd[1024];
    char passFilename[128] = "passwd";

    clearArr(username, 128);
    clearArr(password, 128);
    clearArr(passwd, 1024);

    /*初始化密码文件*/
    fd = open(passFilename, O_CREAT | O_RDWR);
    if (fd == -1)
    {
        //文件已存在，什么都不要做
    }
    else
    {
        //文件不存在，写一个空的进去
        char temp[1024] = {0};
        write(fd, temp, 1);
        close(fd);
        //给文件赋值
        fd = open(passFilename, O_RDWR);
        write(fd, "root:admin", 1024);
        close(fd);
    }
    //然后读密码文件
    fd = open(passFilename, O_RDWR);
    read(fd, passwd, 1024);
    close(fd);

    /*printl(passwd);
    printl("\n");*/

    while (1)
    {
        if (*isLogin)
            return;
        if (step == 0)
        {
            printl("Welcome to OS-master!\n");
            printl("Please login first...\n");
            printl("login: ");
            int r = read(fd_stdin, username, 128);
            if (strcmp(username, "") == 0)
                continue;

            /*printl(username);*/
            /*printl("\n");*/
            step = 1;
        }
        else if (step == 1)
        {
            printl("Password: ");
            int r = read(fd_stdin, password, 128);

            /*printl(password);*/
            /*printl("\n");*/

            if (strcmp(username, "") == 0)
                continue;

            char tempArr[128];
            memcpy(tempArr, username, 128);
            strcat(tempArr, ":");
            char *temp = strstr(passwd, tempArr);

            if (!temp)
            {
                printl("Login incorrect\n\n");
            }
            else
            {
                char *myPass = findpass(temp);

                /*printl(myPass);*/
                /*printl("\n");*/

                if (strcmp(myPass, password) == 0)
                {
                    *isLogin = 1;
                    memcpy(user, username, 128);
                    memcpy(pass, password, 128);
                    printTitle();
                }
                else
                {
                    printl("Login incorrect\n\n");
                }
            }

            clearArr(username, 128);
            clearArr(password, 128);

            step = 0;
        }
    }
}

/*删除用户*/
void doUserDel(char *username)
{
    char passwd[1024];
    char passFilename[128] = "passwd";
    char *p1, *p2;

    //获取密码文件
    int fd;
    fd = open(passFilename, O_RDWR);
    read(fd, passwd, 1024);
    close(fd);

    //定位到那个位置
    char *temp = strcat(username, ":");
    temp = strstr(passwd, temp);

    if (!temp)
    {
        //用户不存在，不用删除
        printl("User not exists");
        printl("\n");
    }
    else
    {
        //处理这一堆鬼
        p1 = temp;
        p2 = temp;

        while (p1 && *p1 != ' ')
        {
            p1++;
        }
        p1++;

        while (p1 && *p1 != '\0')
        {
            *p2 = *p1;
            p1++;
            p2++;
        }

        /*做尾处理*/
        while (p2 != p1)
        {
            *p2 = '\0';
            p2++;
        }
        *p2 = '\0';

        fd = open(passFilename, O_RDWR);
        write(fd, passwd, 1024);
        close(fd);
    }

    /*printl(passwd);*/
    /*printl("\n");*/
}

void doUserAdd(char *username, char *password)
{
    char passwd[1024];
    char passFilename[128] = "passwd";
    char *p1, *p2;

    //获取密码文件
    int fd;
    fd = open(passFilename, O_RDWR);
    read(fd, passwd, 1024);
    close(fd);

    char *newUser = strcat(username, ":");
    strcat(newUser, password);
    strcat(newUser, " ");

    strcat(passwd, newUser);

    printl(passwd);
    printl("\n");

    fd = open(passFilename, O_RDWR);
    write(fd, passwd, 1024);
    close(fd);
}

void doPassWd(char *username, char *password, int fd_stdin)
{
    char currentPassword[128];
    char newPassword[128];

    int step = 0;
    while(1)
    {
        if (step == 0)
        {
            printl("Please input your current password:");
            int r = read(fd_stdin, currentPassword, 128);
            if (strcmp(currentPassword, "") == 0)
                continue;
            step = 1;
        }
        else if (step == 1)
        {
            if (strcmp(password, currentPassword) == 0)
            {
                printl("Please input your new password:");
                int r = read(fd_stdin, newPassword, 128);
                if (strcmp(newPassword, "") == 0)
                    continue;
                step = 2;
            }
            else
            {
                printl("Verify failed\n");
                return;
            }
        }
        else if (step == 2)
        {
            doUserDel(username);
            doUserAdd(username, newPassword);
            printl("Your password changed successfully\n");
            return;
        }
    }
}

/*****************************************************************************
 *                                Init
 *****************************************************************************/
/**
 * The hen.
 * 
 *****************************************************************************/

void TestA()
{
	 //0号终端
    char tty_name[] = "/dev_tty0";
    char username[128];
    char password[128];
    int fd;

    int isLogin = 0;

    char rdbuf[128];
    char cmd[128];
    char arg1[128];
    char arg2[128];
    char buf[1024];

    int fd_stdin  = open(tty_name, O_RDWR);
    assert(fd_stdin  == 0);
    int fd_stdout = open(tty_name, O_RDWR);
    assert(fd_stdout == 1);

    //printl("OS v1.0.0 tty0\n\n");

    clearArr(__path,128*128);
    __pathCount = 0;

    while (1) {
        login(fd_stdin, fd_stdout, &isLogin, username, password);
        //必须要清空数组
        clearArr(rdbuf, 128);
        clearArr(cmd, 128);
        clearArr(arg1, 128);
        clearArr(arg2, 128);
        clearArr(buf, 1024);

        int t = 0;
        printl("%s@OS:~", username);
        for(t=0;t<__pathCount;t++){
            printl("/%s", __path[t]);
        }
        printl("$ ");

        int r = read(fd_stdin, rdbuf, 128);

        if (strcmp(rdbuf, "") == 0)
            continue;

        //解析命令
        int i = 0;
        int j = 0;
        while(rdbuf[i] != ' ' && rdbuf[i] != 0)
        {
            cmd[i] = rdbuf[i];
            i++;
        }
        i++;
        while(rdbuf[i] != ' ' && rdbuf[i] != 0)
        {
            arg1[j] = rdbuf[i];
            i++;
            j++;
        }
        i++;
        j = 0;
        while(rdbuf[i] != ' ' && rdbuf[i] != 0)
        {
            arg2[j] = rdbuf[i];
            i++;
            j++;
        }
        
        //清空缓冲区
        rdbuf[r] = 0;

        if (strcmp(cmd, "menu") == 0)
        {
            menu();
        }
        else if (strcmp(cmd, "2048") == 0)
        {
            /*TTT(fd_stdin, fd_stdout);*/
            game(fd_stdin);
        }
	else if (strcmp(cmd, "Gobang") == 0)
        {
            /*TTT(fd_stdin, fd_stdout);*/
            Gobang(fd_stdin);
        }
        else if (strcmp(cmd, "clear") == 0)
        {
            printTitle();
        }
        else if (strcmp(cmd, "ls") == 0)
        {
            ls();
        }
        else if(strcmp(cmd, "cd") == 0)
        {
            if(arg1[0] == 0)
            {
                clearArr(__path,128*128);
                __pathCount = 0;
            }
            else
            {
                strcpy(__path[__pathCount], arg1);
                __pathCount++;
            }
        }
        else if (strcmp(cmd, "mkdir") == 0)
        {
            fd = open_dir(arg1, O_CREAT | O_RDWR);
            if (fd == -1)
            {
                printl("Failed to create directory! Please check the directory!\n");
                continue ;
            }
            write(fd, buf, 1);
            printl("Directory created: %s (fd %d)\n", arg1, fd);
            close(fd);
        }
        else if (strcmp(cmd, "touch") == 0)
        {
            fd = open(arg1, O_CREAT | O_RDWR);
            if (fd == -1)
            {
                printl("Failed to create file! Please check the filename!\n");
                continue ;
            }
            write(fd, buf, 1);
            printl("File created: %s (fd %d)\n", arg1, fd);
            close(fd);
        }
        else if (strcmp(cmd, "cat") == 0)
        {
            fd = open(arg1, O_RDWR);
            if (fd == -1)
            {
                printl("Failed to open file! Please check the filename!\n");
                continue ;
            }
            /*if (!verifyFilePass(arg1, fd_stdin))
            {
                printf("Authorization failed\n");
                continue;
            }*/
            read(fd, buf, 1024);
            close(fd);
            printl("%s\n", buf);
        }
        else if (strcmp(cmd, "vim") == 0)
        {
            fd = open(arg1, O_RDWR);
            if (fd == -1)
            {
                printl("Failed to open file! Please check the filename!\n");
                continue ;
            }
            /*if (!verifyFilePass(arg1, fd_stdin))
            {
                printf("Authorization failed\n");
                continue;
            }*/
            int tail = read(fd_stdin, rdbuf, 128);
            rdbuf[tail] = 0;

            write(fd, rdbuf, tail+1);
            close(fd);
        }
        else if (strcmp(cmd, "del") == 0)
        {
            /*
            if (!verifyFilePass(arg1, fd_stdin))
            {
                printf("Authorization failed\n");
                continue;
            }*/
            int result;
            result = unlink(arg1);
            if (result == 0)
            {
                printl("File deleted!\n");
                continue;
            }
            else
            {
                printl("Failed to delete file! Please check the filename!\n");
                continue;
            }
        }
        else if (strcmp(cmd, "cp") == 0)
        {
            //首先获得文件内容
                        fd = open(arg1, O_RDWR);
            if (fd == -1)
            {
                printf("File not exists! Please check the filename!\n");
                continue ;
            }
           /* if (!verifyFilePass(arg1, fd_stdin))
            {
                printf("Authorization failed\n");
                continue;
            }*/
            int tail = read(fd, buf, 1024);
            close(fd);
            
            fd = open(arg2, O_CREAT | O_RDWR);
            if (fd == -1)
            {
                //文件已存在，什么都不要做
            }
            else
            {
                //文件不存在，写一个空的进去
                char temp[1024];
                temp[0] = 0;
                write(fd, temp, 1);
                close(fd);
            }
            //给文件赋值
            fd = open(arg2, O_RDWR);
            write(fd, buf, tail+1);
            close(fd);
         
        }
        else if (strcmp(cmd, "mv") == 0)
        {
            //首先获得文件内容
            fd = open(arg1, O_RDWR);
            if (fd == -1)
            {
                printl("File not exists! Please check the filename!\n");
                continue ;
            }
            /*if (!verifyFilePass(arg1, fd_stdin))
            {
                printf("Authorization failed\n");
                continue;
            }*/
            int tail = read(fd, buf, 1024);
            close(fd);
            
            fd = open(arg2, O_CREAT | O_RDWR);
            if (fd == -1)
            {
                //文件已存在，什么都不要做
            }
            else
            {
                //文件不存在，写一个空的进去
                char temp[1024];
                temp[0] = 0;
                write(fd, temp, 1);
                close(fd);
            }
            //给文件赋值
            fd = open(arg2, O_RDWR);
            write(fd, buf, tail+1);
            close(fd);
            //最后删除文件
            unlink(arg1);
        }
        else if (strcmp(cmd, "useradd") == 0)
        {
            doUserAdd(arg1, arg2);
        }
        else if (strcmp(cmd, "userdel") == 0)
        {
            doUserDel(arg1);
        }
        else if (strcmp(cmd, "passwd") == 0)
        {
            doPassWd(username, password, fd_stdin);
        }
        else if (strcmp(cmd, "logout") == 0)
        {
            isLogin = 0;
            clearArr(username, 128);
            clearArr(password, 128);

            //clear();
            //printl("OS v1.0.0 tty0\n\n");
        }
        else if (strcmp(cmd, "untar") == 0)
        {
            fd = open(arg1, O_RDWR);
            if (fd == -1)
            {
                printl("File not exists! Please check the filename!\n");
                continue ;
            }
            /*if (!verifyFilePass(arg1, fd_stdin))
            {
                printf("Authorization failed\n");
                continue;
            }*/
            untar(arg1);
        }
        else if(strcmp(cmd,"calculator") == 0)
        {
            char exp[100];
            char cal[200];

            while(1)
            {
                clearArr(exp,100);
                clearArr(cal,200);

                printl(">");
                read(fd_stdin, exp,100);
                if(strcmp(exp,"q") == 0)
                    break;
                trans(exp,cal);
                printl("%d\n",calculate(cal));
            }
        }
        else
            printl("Command not found, please check!\n");
    }

}

int ls()
{
    MESSAGE msg;
    msg.type = LS;

    send_recv(BOTH, TASK_FS, &msg);

    return msg.RETVAL;
}

int open_dir(const char *pathname, int flags)
{
	MESSAGE msg;

	msg.type	= OPEN_DIR;

	msg.PATHNAME	= (void*)pathname;
	msg.FLAGS	= flags;
	msg.NAME_LEN	= strlen(pathname);

	send_recv(BOTH, TASK_FS, &msg);
	assert(msg.type == SYSCALL_RET);

	return msg.FD;
}

/*****************************************************************************
                           Command Analysis and Execution
 *****************************************************************************/
/*void TestA()
{
	for(;;);
}*/

void printTitle()
{
    //clear();

    disp_pos = 0;
    printl("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
/*    printl(" ^      /| \n" ); 
    printl("　/\\7　　<_/ \n");
    printl(" /　|　　 /　/ \n");
    printl("│　Z __,<　/　　 /`\ \n");
    printl("│　　　　　\　　 /　　> \n");
    printl(" Y　　　　　`　 /　　/ \n");
    printl("　|●　､　●　　<>〈　　/ \n");
    printl("　()　 >　　　　|　\〈 \n");
    printl("　>ｰ `_　 ィ　 │ // \n");
    printl(" / へ　　 /　)＜| \\ \n");
    printl(" \_)　　(_/　 │// \n");
    printl("　7　　　　　　　|/ \n");
    printl("　>_r---`ｰ___\n");*/
    printl("  ___    ____            _________   ___   ____  ______ ____  ____  \n" ); 
	printl(" /  _ \\/ ___|          /  _   _  \ / _ \ / ___||_  __||  __|| __ \ \n");
	printl(" | | | \\___ \    |---|  | | | | | |/ /_\ \\___ \  | |  | |__|| |_) ) \n");
	printl(" | |_| |___) |  |---|  | | | | | ||  _  ||___)|  | |  | |__ |  __ \  \n");
	printl(" \\___/ |____/          |_| |_| |_||_| |_||____/  |_|  |____||_|  \_\  \n");
    printl("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    printl("\n\n");

}

void clear()
{
    clear_screen(0,console_table[current_console].cursor);
    console_table[current_console].crtc_start = 0;
    console_table[current_console].cursor = 0;
}

void clearArr(char *arr, int length)
{
    int i;
    for (i = 0; i < length; i++)
        arr[i] = 0;
}

/*void tar(char *path, int fd_stdin)
{
    char name[128] = {0};

    char command[512] = {0};

    strcat(command, "tar -cf ");

    printl("Please input the tar file name: ");
    read(fd_stdin, name, 128);

    if (strcmp(name, "") == 0)
    {
        printl("Blank!\n");
        return;
    }
    strcat(command, name);
    strcat(command, ".tar ");
    strcat(command, path);
    //调用shell进行压缩
    system(command);
}*/

#define MAXSIZE 100  
typedef struct stack
{
    int top;
    char s[MAXSIZE];
}stack;
typedef struct numstack
{
    int top;
    int num[MAXSIZE];
}numstack;
void gettop(stack s, char *outch)
{
    *outch = s.s[s.top];
}
int IntoStack(stack *st, char in)
{
    if (st->top == MAXSIZE - 1)return -1;
    st->s[(st->top)++] = in;
    return 0;
}
int OutStack(stack *st, char *out)
{
    if (st->top == 0)return -1;
    *out = st->s[--(st->top)];
    return 0;
}
int  trans(char *exp, char *cal)
{
    char ch, temp;
    int i = 0, j = 0;
    ch = exp[0];
    stack st;
    st.top = 0;
    while (ch != '\0')
    {
        switch (ch)
        {
        case '(':
            IntoStack(&st, ch);
            break;
        case '+':
        case '-':
            while (st.top != 0 && st.s[st.top - 1] != '(')
            {
                OutStack(&st, &temp);
                cal[j++] = temp;
            }
            IntoStack(&st, ch);
            break;
        case '*':
        case '/':
            while (st.top != 0 && st.s[st.top - 1] != '(' &&
                (st.s[st.top - 1] == '*' || st.s[st.top - 1] == '/'))
            {
                OutStack(&st, &temp);
                cal[j++] = temp;
            }
            IntoStack(&st, ch);
            break;
        case ')':
            while (st.top != 0)
            {
                OutStack(&st, &temp);
                if (temp != '(')
                    cal[j++] = temp;
                else
                    break;
            }
            break;
        case ' ':
            break;
        default:
            while (ch >= '0'&&ch <= '9')
            {
                cal[j++] = ch;
                ch = exp[++i];
            }
            i--;
            cal[j++] = '#';
            break;
        }
        ch = exp[++i];
    }
    while (st.top != 0)
    {
        cal[j++] = st.s[--(st.top)];
    }
    cal[j] = '\0';
    return 0;
}
int calculate(char exp[])
{
    int i = 0, temp, a, b;
    numstack numst;
    numst.top = 0;
    while (exp[i] != '\0')
    {
        temp = 0;
        while (exp[i] >= '0'&&exp[i] <= '9')
        {
            temp = temp * 10 + (exp[i++] - '0');
        }
        if (exp[i] == '#')
        {
            i++;
            numst.num[numst.top++] = temp;
        }
        else
        {
            b = numst.num[--(numst.top)];
            a = numst.num[--(numst.top)];
            switch (exp[i++])
            {
            case '+': numst.num[(numst.top)++] = a + b; break;
            case '-':numst.num[(numst.top)++] = a - b; break;
            case '*':numst.num[(numst.top)++] = a*b; break;
            case '/':numst.num[(numst.top)++] = a / b; break;
            }
        }
    }
    return numst.num[--(numst.top)];
}


/*****************************************************************************
 *                                Command List
 *****************************************************************************/

void menu()
{
    printf("=============================================================================\n");
    printf("\n");
    printf("Command List\n");
    printf("\n");
    printf("1.  menu                           : Command menu\n");
    printf("2.  clear                          : Clear the screen\n");
    printf("3.  ls                             : List files under current path\n");
    printf("4.  cd        [path]               : Change current directory to input one\n");
    printf("5.  touch     [file]               : Create a new file named after the input\n");
    printf("6.  mkdir     [file]               : Create a new directory\n");
    printf("7.  cat       [file]               : Print the content of the input file\n");
    printf("8.  vim       [file]               : Modify the content of the input file\n");
    printf("9.  del       [file]               : Delete a file\n");
    printf("10. untar     [file]               : Decompress a file compressed in tar format\n");
    printf("11. cp        [SOURCE] [DEST]      : Copy a file[SOURCE] to new directory[DEST]\n");
    printf("12. mv        [SOURCE] [DEST]      : Move a file[SOURCE] to new directory[DEST]\n");
    printf("13. useradd   [USERNAME] [PASSWORD]: Add a new user\n");
    printf("14. userdel   [USERNAME]           : Delete a user\n");
    printf("15. passwd    [USERNAME]           : Change your user password\n");
    printf("16. logout                         : Logout\n");
    printf("17. 2048                           : 2048 Game\n");
    printf("18. Gobang                         : Gobang(five-in-a-row) Game\n");
    printf("19. calculator                     : Calculator\n");
    printf("\n");
    printf("==============================================================================\n");
}

/*****************************************************************************
 *                                Game Lib(2048 and gobang)
 *****************************************************************************/

//2048
unsigned int _seed2 = 0xDEADBEEF;

void srand(unsigned int seed){
    _seed2 = seed;
}

int rand() {
    unsigned int next = _seed2;
    unsigned int result;

    next *= 1103515245;
    next += 12345;
    result = ( unsigned int  ) ( next / 65536 ) % 2048;

    next *= 1103515245;
    next += 12345;
    result <<= 10;
    result ^= ( unsigned int ) ( next / 65536 ) % 1024;

    next *= 1103515245;
    next += 12345;
    result <<= 10;
    result ^= ( unsigned int ) ( next / 65536 ) % 1024;

    _seed2 = next;

    return result;
}


#define SIZE 4
int square[SIZE][SIZE];
int row[SIZE*SIZE];
int col[SIZE*SIZE];

//generate 2 or 4 at random place in the square, cnt represents for count of blank area
void generateNumber(int cnt)
{
	//int num = rand() / double(RAND_MAX) < 0.9 ? 2 : 4;
	int pos = rand() % cnt;
	square[row[pos]][col[pos]] = 2<<(rand()%2);
}

int recordBlank()
{
	int cnt=0;
	int i = 0, j = 0;
	for (i = 0; i < SIZE; ++i){
		for (j = 0; j < SIZE; ++j){
			if (square[i][j] == 0){
				row[cnt] = i;
				col[cnt] = j;
				++cnt;
			}
		}
	}
	return cnt;
}

//flag=false means the square has not been changed
int moveDown()
{
	int block[SIZE][SIZE];
	int i = 0, j = 0;
	for (i=0; i < SIZE; ++i){
		for (j=0; j < SIZE; ++j)
			block[i][j] = 1;
	}
	int flag = 0;
	for (i = 1; i < SIZE; ++i){
		for (j = 0; j < SIZE; ++j){
			if (square[i][j]==0)
				continue;
			int tmp = i - 1;
			for (; tmp >= 0 && square[tmp][j] == 0; --tmp);

			if (tmp < 0 || block[tmp][j]==0 || square[tmp][j] != square[i][j]){
				square[tmp + 1][j] = square[i][j];
				if (tmp + 1 != i){
					square[i][j] = 0;
					flag = 1;
				}
			}

			else if (square[tmp][j] == square[i][j]&&block[tmp][j]==1){
				square[tmp][j] *= 2;
				square[i][j] = 0;
				block[tmp][j] = 0;
				flag = 1;
			}
		}
	}
	return flag;
}

int moveUp()
{
	int block[SIZE][SIZE];
	int i = 0, j = 0;
	for (i=0; i < SIZE; ++i){
		for (j=0; j < SIZE; ++j)
			block[i][j] = 1;
	}
	int flag = 0;
	for (i = SIZE - 2; i >= 0;--i){
		for (j = 0; j < SIZE; ++j){
			if (square[i][j] == 0)
				continue;
			int tmp = i + 1;
			for (; tmp <SIZE && square[tmp][j] == 0; ++tmp);
			if (tmp >= SIZE || block[tmp][j]==0|| square[tmp][j] != square[i][j])
				square[tmp - 1][j] = square[i][j];
			else if (square[tmp][j] == square[i][j] && block[tmp][j]==1){
				square[tmp][j] *= 2;
				square[i][j] = 0;
				block[tmp][j] = 0;
				flag = 1;
			}

			if (tmp - 1 != i){
				square[i][j] = 0;
				flag = 1;
			}

		}
	}
	return flag;
}

int moveLeft()
{
	int block[SIZE][SIZE];
	int i = 0, j = 0;
	for (i=0; i < SIZE; ++i){
		for (j=0; j < SIZE; ++j)
			block[i][j] = 1;
	}
	int flag = 0;
	for (j = 1; j < SIZE; ++j){
		for (i = 0; i < SIZE; ++i){
			if (square[i][j] == 0)
				continue;
			int tmp = j - 1;
			for (; tmp >= 0 && square[i][tmp] == 0; --tmp);

			if (tmp < 0 || block[i][tmp]==0 || square[i][tmp] != square[i][j]){
				square[i][tmp + 1] = square[i][j];
				if (tmp + 1 != j){
					square[i][j] = 0;
					flag = 1;
				}
			}
			else if (square[i][tmp] == square[i][j] && block[i][tmp]==1){
				square[i][tmp] *= 2;
				square[i][j] = 0;
				block[i][tmp] = 0;
				flag = 1;
			}
		}
	}
	return flag;
}

int moveRight()
{
	int block[SIZE][SIZE];
	int i = 0, j = 0;
	for (i=0; i < SIZE; ++i){
		for (j=0; j < SIZE; ++j)
			block[i][j] = 1;
	}
	int flag = 0;
	for (j = SIZE - 2; j >= 0; --j){
		for (i = 0; i < SIZE; ++i){
			if (square[i][j] == 0)
				continue;
			int tmp = j + 1;
			for (; tmp < SIZE && square[i][tmp] == 0; ++tmp);

			if (tmp >= SIZE || block[i][tmp]==0 || square[i][tmp] != square[i][j]){
				square[i][tmp - 1] = square[i][j];
				if (tmp - 1 != j){
					square[i][j] = 0;
					flag = 1;
				}
			}
			else if (square[i][tmp] == square[i][j] && block[i][tmp]==1){
				square[i][tmp] *= 2;
				square[i][j] = 0;
				block[i][tmp] = 0;
				flag = 1;
			}


		}
	}
	return flag;
}

void printSquare()
{
	printf("----------------------\n");
	int i = SIZE - 1, j = 0;
	for (i = SIZE-1; i >=0; --i){
		printf("|");
		for (j = 0; j < SIZE; ++j){
			if (square[i][j] == 0)
				printf("    *");
			else
				printf("%5d", square[i][j]);
		}
		printf("|");
		printf("\n\n");
	}
	printf("----------------------\n");
}

void initialGame()
{
	int cnt = 0;
	cnt = recordBlank();
	generateNumber(cnt);
	cnt = recordBlank();
	generateNumber(cnt);
}

int gameWin()
{
	int i = 0, j = 0;
	for (i=0; i < SIZE; ++i){
		for (j=0; j < SIZE; ++j){
			if (square[i][j] == 2048)
				return 1;
		}
	}
	return 0;
}

int gameLose()
{
	int i = 0, j = 0;
	for (i=0; i < SIZE; ++i){
		for (j=0; j < SIZE; ++j){
			int curr = square[i][j];
			if ((i > 0 && square[i - 1][j] == curr) || (i < SIZE - 1 && square[i + 1][j] == curr) || 
				(j>0 && square[i][j - 1] == curr) || (j < SIZE - 1 && square[i][j + 1] == curr))
				return 0;
		}
	}
	return 1;
}

int game(int fd_stdin){
	//clear();
   	printl("================================game 2048=======================================\n");
	printl("\n");
	printl("                    --->      ShuaiB's 2048      <-----\n");
	printl("\n");
	printl("                          1. 'W' for move up\n");
	printl("                          2. 'A' for move left\n");
	printl("                          3. 'S' for move down\n");
	printl("                          4. 'D' for move right\n");
	printl("                          5. 'Q' for quit\n");
	printl("\n");
	printl("================================================================================\n");
	initialGame();
	printSquare();
	//char direction;
	int cnt = 0;
	int flag = 0;
	int result = 0;
	char keys[128];
	while (1){
		//scanf("%c", &direction);
		clearArr(keys,128);
		read(fd_stdin, keys, 128);

		if (strcmp(keys, "a") == 0)
            	{
                flag = moveLeft();
            	}
            	else if (strcmp(keys, "s") == 0)
            	{
                flag = moveDown();
            	}
            	else if (strcmp(keys, "w") == 0)
            	{
                flag = moveUp();
            	}
            	else if (strcmp(keys, "d") == 0)
            	{
                flag = moveRight();
            	}
            	else if (strcmp(keys, "q") == 0)
            	{
                return 0;
            	}
            	else
            	{
            	    printl("w for move up, a for move left, s for move down, d for move right, q for quit, ? for help\n");
            	    continue;
            	}
		cnt = recordBlank();
		if (flag==1&&cnt>0)
			generateNumber(cnt);
		cnt -= 1;
		if (cnt == 0 && gameLose()){
			printl("Oops, game over...\n");
			return 0;
		}
		
		printSquare();
		result = gameWin();
		if (result == 1){
			printl("Congratulations! You win!\n");
			return 0;
		}
	}
	
	return 0;
}

//Gobang
static char ch[11][4] = {"", "", "", "", "", "", "", "", "", "*", "o"};//玩家黑子9， ai白子10
char Default[10][10] = {
    0, 1, 1, 1, 1, 1, 1, 1, 1, 2,
    3, 4, 4, 4, 4, 4, 4, 4, 4, 5,
    3, 4, 4, 4, 4, 4, 4, 4, 4, 5,
    3, 4, 4, 4, 4, 4, 4, 4, 4, 5,
    3, 4, 4, 4, 4, 4, 4, 4, 4, 5,
    3, 4, 4, 4, 4, 4, 4, 4, 4, 5,
    3, 4, 4, 4, 4, 4, 4, 4, 4, 5,
    3, 4, 4, 4, 4, 4, 4, 4, 4, 5,
    3, 4, 4, 4, 4, 4, 4, 4, 4, 5,
    6, 7, 7, 7, 7, 7, 7, 7, 7, 8};
char chessBoard[10][10];
int playerBoard[10][10] = {}, aiBoard[10][10] = {};
int ai = 0, totalCount = 0, maxX = 0, maxY = 0;
int Score[10][10], mark[10][10];

void assign(char assign[10][10], char assigned[10][10]){
    for (int i = 0; i<10; i++) {
        for (int j = 0; j < 10; j++) {
            assigned[i][j] = assign[i][j];
        }
    }
}

void Empty(){
    memset(playerBoard,0,sizeof(playerBoard));
    memset(aiBoard,0,sizeof(aiBoard));
    memset(Score, 0, sizeof(Score));
    memset(mark, 0, sizeof(mark));
    assign(Default, chessBoard);
}

void PrintChessBoard(int x, int y, int init, int ai, int pl){
    if (init == 1) {
        assign(Default, chessBoard);
        Empty();
    }else{
        if(ai == 1 && pl == 0){
            chessBoard[x][y] = 10;
        }
        if(pl == 1 && ai == 0){
            chessBoard[x][y] = 9;
        }
    }
    printf("  ");
    for (int i = 0; i<11; i++){
        for(int j = 0; j<11; j++){
            if (i == 0 && j!=0) {
                printl("%d ", j-1);
            }
            else if(i != 0 && j == 0){
                printl("%d ", i-1);
            }
            else if(i != 0 && j != 0){
                printl("%s ", ch[chessBoard[i-1][j-1]]);
            }
        }
        printl("\n");
    }
    
}

void Start(){
    printl("*******************************game FiveInRow*********************************");
    printl("\n\n");
    printl("                           --->    MENU    <---                                   \n");
    printl("                           1. '*' for YOU and 'o' for ROBOT\n");
    printl("                           2. Enter 'E' and enter 'xy' to enter the cordinates \n");
    printl("                           3. Enter 'M' for menu\n");
    printl("                           4. Enter 'R' for restart\n");
    printl("                           5. Enter 'Q' for quit\n");
    printl("\n\n");
    Empty();
}



int checkLine(int Cx, int Cy, int isPlayer, int Count){
    int w=1,x=1,y=1,z=1,i;//累计横竖正斜反邪四个方向的连续相同棋子数目
    for(i=1;i<5;i++){
        if(Cy+i<=MAXIMUS){
            if ((isPlayer&&chessBoard[Cx][Cy+i]==9)||(!isPlayer&&chessBoard[Cx][Cy+i]==10)) {
                w++;
            }
            else break;
        }
        else break;
    }
    for(i=1;i<5;i++){//XIA
        if(Cy-i>=0){
            if ((isPlayer&&chessBoard[Cx][Cy-i]==9)||(!isPlayer&&chessBoard[Cx][Cy-i]==10)) {
                w++;
            }
            else break;
        }
        else break;
    }
    if(w>=5)
        return 1;
    for(i=1;i<5;i++){//you
        if(Cx+i<=MAXIMUS){
            if ((isPlayer&&chessBoard[Cx+i][Cy]==9)||(!isPlayer&&chessBoard[Cx+i][Cy]==10)) {
                x++;
            }
            else break;
        }
        else break;
    }
    for(i=1;i<5;i++){//zuo
        if(Cx-i>=0){
            if ((isPlayer&&chessBoard[Cx+i][Cy]==9)||(!isPlayer&&chessBoard[Cx+i][Cy]==10)) {
                x++;
            }
            else break;
        }
        else break;
    }
    if(x>=5)
        return 1;//youxia
    for(i=1;i<5;i++){//you
        if(Cx+i<=MAXIMUS&&Cy+i<=MAXIMUS){
            if ((isPlayer&&chessBoard[Cx+i][Cy+i]==9)||(!isPlayer&&chessBoard[Cx+i][Cy+i]==10)) {
                y++;
            }
            else break;
        }
        else break;
    }
    for(i=1;i<5;i++){//zuoshang
        if(Cx-i>=0&&Cy-i>=0){
            if ((isPlayer&&chessBoard[Cx-i][Cy-i]==9)||(!isPlayer&&chessBoard[Cx-i][Cy-i]==10)) {
                y++;
            }
            else break;
        }
        else break;
    }
    if(y>=5)
        return 1;//若果达到5个则判断当前走子玩家为赢家
    for(i=1;i<5;i++){//youshang
        if(Cx+i<=MAXIMUS && Cy-i>=0){
            if ((isPlayer&&chessBoard[Cx+i][Cy-i]==9)||(!isPlayer&&chessBoard[Cx+i][Cy-i]==10)) {
                z++;
            }
            else break;
        }
        else break;
    }
    for(i=1;i<5;i++){//zuoxia
        if(Cx-i>=0&&Cy+i<=MAXIMUS){
            if ((isPlayer&&chessBoard[Cx-i][Cy+i]==9)||(!isPlayer&&chessBoard[Cx-i][Cy+i]==10)) {
                z++;
            }
            else break;
        }
        else break;
    }
    if(z>=5)
        return 1;//若果达到5个则判断当前走子玩家为赢家
    
    
    return 0;
}

void Robot(){
    memset(Score, 0, sizeof(Score));
    int empty = 0, player = 0, ai = 0, a = 0, b = 0;
    for (int i = 0; i < 10; i++) {
        for (int j = 0; j < 10; j++) {
            if (chessBoard[i][j] != 9 && chessBoard[i][j] != 10) {
                for (int a = -1; a < 2; a++) {
                    for (int b = -1; b < 2; b++) {
                        if (chessBoard[a][b] == 9) {
                            player++;
                        }else if(chessBoard[a][b] == 10){
                            ai++;
                        }else{
                            empty++;
                        }
                    }
                }
                
            
                if (player == 1) {
                    Score[i][j] += 1;
                }
                else if(player == 2){
                    if (empty == 1) {
                        Score[i][j] += 5;
                    }else{
                        Score[i][j] += 10;
                    }
                }
                else if(player == 3){
                    if (empty == 1) {
                        Score[i][j] += 20;
                    }else if(empty >= 2){
                        Score[i][j] += 100;
                    }
                }
                else if (player >= 4){
                    Score[i][j] += 1000;
                }
                
                if (ai == 0){
                    Score[i][j] += 1;
                }
                else if (ai == 1){
                    Score[i][j] += 2;
                }
                else if (ai == 2){
                    if (empty == 1) {
                        Score[i][j] += 8;
                    }
                    else if (empty >= 2){
                        Score[i][j] += 30;
                    }
                }
                else if (ai == 3){
                    if (empty == 1) {
                        Score[i][j] += 50;
                    }
                    else if (empty >= 2){
                        Score[i][j] += 200;
                    }
                }
                else if (ai >= 4){
                    if (empty >= 1) {
                        Score[i][j] += 10000;
                    }
                }
            }
            int max = 0;
            for (a = 0; a < 10; a++) {
                for (b = 0; b < 10; b++) {
                    if (Score[a][b] > max){
                        max = Score[a][b];
                        maxY = a;
                        maxY = b;
                    }
                }
            }
            //chessBoard[a][b] = 10;
        }
    }
    PrintChessBoard(maxX, maxY, 0, 1, 0);
}

int Gobang(int fd_stdin) {
    Start();
    PrintChessBoard(-1, -1, 1, ai, 0);
    char in = 'M';
    int x = 0, y = 0;
    char keys[128];

    while (1) {
        //printf("%c", in);
		clearArr(keys,128);
		read(fd_stdin, keys, 128);

		if (strcmp(keys, "M") == 0)
            	{
                	printl("\n\n");
                	printl("                           --->    MENU    <---                                   \n");
                	printl("                           1. '*' for YOU and 'o' for ROBOT\n");
                	printl("                           2. 'E' for enter the cordinates 'x' 'ENTER' 'y'");
                	printl("                           3. 'M' for menu\n");
                	printl("                           4. 'R' for restart\n");
                	printl("                           5. 'Q' for quit\n");
                	printl("\n\n");
            	}
            	else if (strcmp(keys, "Q") == 0)
            	{
                	return 0;
            	}
            	else if (strcmp(keys, "R") == 0)
            	{
                	Empty();
                	PrintChessBoard(-1, -1, 1, ai, 0);
            	}
            	else if (strcmp(keys, "E") == 0)
            	{
		    read(fd_stdin, keys, 128);
		    x = keys[0];
		    read(fd_stdin, keys, 128);
		    y = keys[0];
		    
                    if (x < -1 || y <-1 || chessBoard[x][y] == 9 || chessBoard[x][y] == 10 || x > 9 || y > 9){
                    printl("WRONG CORDINATES!\n");
                    
                }
                playerBoard[x][y] = 1;
                printl("Your turn: \n");
                PrintChessBoard(x, y, 0, 0, 1);
                if (checkLine(x, y, 1, 1) == 1) {
                    printl("YOU WIN!!!!!!!!\n");
                    Start();
                    return 0;
                }
                printl("Robot's turn: \n");
                Robot();
                if (checkLine(maxX, maxY, 0, 1) == 1) {
                    printl("YOU LOSE ^^!!!!!!!!\n");
                    Start();
                }
            	}
            	else
		{
			printl("                           1. '*' for YOU and 'o' for ROBOT\n");
                	printl("                           2. 'E' for enter the cordinates 'x' 'ENTER' 'y'\n");
                	printl("                           3. 'M' for menu\n");
                	printl("                           4. 'R' for restart\n");
                	printl("                           5. 'Q' for quit\n");
                	printl("\n\n");
		}
        }
    
    
    
    return 0;
}






/*======================================================================*
                               TestB
 *======================================================================*/
void TestB()
{
	for(;;);
}

/*======================================================================*
                               TestB
 *======================================================================*/
void TestC()
{
	for(;;);
}

/*****************************************************************************
 *                                panic
 *****************************************************************************/
PUBLIC void panic(const char *fmt, ...)
{
	int i;
	char buf[256];

	/* 4 is the size of fmt in the stack */
	va_list arg = (va_list)((char*)&fmt + 4);

	i = vsprintf(buf, fmt, arg);

	printl("%c !!panic!! %s", MAG_CH_PANIC, buf);

	/* should never arrive here */
	__asm__ __volatile__("ud2");
}

