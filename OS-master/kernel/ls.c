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

PUBLIC int ls();

/*****************************************************************************
 *                                ls
 *****************************************************************************/
/**
 * Write to a file descriptor.
 *
 *****************************************************************************/
PUBLIC int ls()
{
    MESSAGE msg;
    msg.type = LS;

    send_recv(BOTH, TASK_FS, &msg);

    return msg.RETVAL;
}
