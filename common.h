/*
// C Interface: common
//
// Description: TDHCP common definitions
//
//
// Author: Konrad Rosenbaum <konrad@silmor.de>, (C) 2009
//
// Copyright: See COPYING file that comes with this distribution
//
*/

#ifndef TDHCP_COMMON_H
#define TDHCP_COMMON_H

/*enterprise number*/
extern const unsigned long PEN;

/*side ID, allocated in server.c (as 0x00) and client.c (as 0x01) respectively*/
extern const unsigned char SIDEID;
#define SIDE_CLIENT 0x01
#define SIDE_SERVER 0x00

/*local id hash*/
extern unsigned char LOCALID[16];

/*local DUID*/
extern int DUIDLEN;
extern unsigned char DUID[1024];

/*calculate local id from querying the system for its identifier*/
void initlocalid();
/*set local id from string (calculates MD5 of this string)*/
void setlocalid(const char*);
/*set DUID directly from hex string*/
void setduid(const char*);

#define LOGDEBUG 0
#define LOGINFO 1
#define LOGWARN 2
#define LOGERROR 3
#define LOGNONE 0xffff

/*set log level with symbolic string "debug" "info" "warn" "error" or "none"*/
void setloglevel(const char*);

/*logging function (uses syslog or stderr)*/
void td_log(int,const char*,...);

/*tells the log function what level to log (default: LOGINFO)*/
extern int loglevel;

/*switches to syslog*/
void activatesyslog();


/*emulate C++ boolean type*/
#define bool int
#define true 1
#define false 0

/*wrappers around some memory handling*/
void* Malloc(int);
void* Realloc(void*,int);
void Free(void*);

void* Memcpy(void*,void*,int);
void* Memzero(void*,int);
int Memcmp(void*,void*,int);

char* Strcpy(char*,const char*);
char* Strncpy(char*,const char*,int);

#endif
