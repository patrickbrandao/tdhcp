/*
*  C Implementation: common
*
* Description: TDHCP common components
*
*
* Author: Konrad Rosenbaum <konrad@silmor.de>, (C) 2009
*
* Copyright: See COPYING file that comes with this distribution
*
*/

#include "common.h"
#include "md5.h"

#include <stdarg.h>
#include <syslog.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <stdlib.h>

const unsigned long PEN=34360;

unsigned char LOCALID[16]={0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};
int DUIDLEN;
unsigned char DUID[1024];

static void dumpduid()
{
	int i;
	char dd[4096];
	static const char hex[]="0123456789ABCDEF";
	for(i=0;i<DUIDLEN;i++){
		dd[i*3]=hex[DUID[i]>>4];
		dd[i*3+1]=hex[DUID[i]&0xf];
		dd[i*3+2]='-';
	}
	dd[DUIDLEN*3-1]=0;
	td_log(LOGINFO,"Using local DUID %s",dd);
}

static void calcduid()
{
	DUIDLEN=25;
	DUID[0]=0;
	DUID[1]=2; /*byte 0+1: DUID Type 0x0002*/
	DUID[2]=(PEN>>24)&0xff;
	DUID[3]=(PEN>>16)&0xff;
	DUID[4]=(PEN>>8)&0xff;
	DUID[5]=PEN&0xff; /*byte 2-5: enterprise number*/
	DUID[6]=0;
	DUID[7]=0;/*byte 6,7: project ID 0*/
	DUID[8]=SIDEID; /*byte 8: client or server*/
	Memcpy(DUID+9,LOCALID,16);/*byte 9-24: hash*/
	dumpduid();
}


void initlocalid()
{
	MD5_CTX ctx;
	char s[1024];
	struct hostent*he;
	
	MD5Init(&ctx);
	gethostname(s,sizeof(s));
	
	he=gethostbyname(s);
	if(he && he->h_name){
		td_log(LOGDEBUG,"FQDN=%s",he->h_name);
		MD5Update(&ctx,(void*)he->h_name,strlen(he->h_name));
	}else{
		td_log(LOGDEBUG,"host=%s",s);
		MD5Update(&ctx,(void*)s,strlen(s)+1);
		getdomainname(s,sizeof(s));
		td_log(LOGDEBUG,"domain=%s",s);
		MD5Update(&ctx,(void*)s,strlen(s));
	}
	MD5Final(LOCALID,&ctx);
	calcduid();
}

void setlocalid(const char*s)
{
	MD5_CTX ctx;
	MD5Init(&ctx);
	td_log(LOGDEBUG,"local id=%s",s);
	MD5Update(&ctx,(void*)s,strlen(s));
	MD5Final(LOCALID,&ctx);
	calcduid();
}

void setduid(const char*hx)
{
	int i,k;
	DUIDLEN=0;
	memset(DUID,0,sizeof(DUID));
	for(i=k=0;hx[i] && DUIDLEN<1024;i++){
		int c=-1;
		if(hx[i]>='0' && hx[i]<='9')c=hx[i]-'0';else
		if(hx[i]>='a' && hx[i]<='f')c=hx[i]-'a'+10;else
		if(hx[i]>='A' && hx[i]<='F')c=hx[i]-'A'+10;
		else continue;
		if(k){/*k==1: lsb nibble*/
			DUID[DUIDLEN++]|=c;
			k=0;
		}else{/*k==0: msb nibble*/
			DUID[DUIDLEN]=c<<4;
			k=1;
		}
	}
	dumpduid();
}

static int usesyslog=0;
int loglevel=LOGWARN;

void setloglevel(const char*l)
{
	if(!strcmp("none",l))loglevel=LOGNONE;else
	if(!strcmp("error",l))loglevel=LOGERROR;else
	if(!strcmp("err",l))loglevel=LOGERROR;else
	if(!strcmp("warn",l))loglevel=LOGWARN;else
	if(!strcmp("warning",l))loglevel=LOGWARN;else
	if(!strcmp("info",l))loglevel=LOGINFO;else
	if(!strcmp("debug",l))loglevel=LOGDEBUG;
}

void td_log(int prio,const char*fmt,...)
{
	va_list ap;
	if(prio<loglevel)return;
	va_start(ap,fmt);
	if(usesyslog){
		int p2=LOG_INFO;
		switch(prio){
			case LOGDEBUG:p2=LOG_DEBUG;break;
			case LOGINFO:p2=LOG_NOTICE;break;
			case LOGWARN:p2=LOG_WARNING;break;
			case LOGERROR:p2=LOG_ERR;break;
		}
		vsyslog(p2,fmt,ap);
	}else{
		char fmt2[1024];
		switch(prio){
			case LOGDEBUG:snprintf(fmt2,sizeof(fmt2),"Debug: %s\n",fmt);break;
			case LOGINFO:snprintf(fmt2,sizeof(fmt2),"Info: %s\n",fmt);break;
			case LOGWARN:snprintf(fmt2,sizeof(fmt2),"Warning: %s\n",fmt);break;
			case LOGERROR:snprintf(fmt2,sizeof(fmt2),"Error: %s\n",fmt);break;
			default:snprintf(fmt2,sizeof(fmt2),"%s\n",fmt);break;
		}
		vfprintf(stderr,fmt2,ap);
	}
}

void activatesyslog()
{
	if(SIDEID==SIDE_SERVER)
		openlog("tdhcpd",LOG_NDELAY|LOG_PID,LOG_DAEMON);
	else
		openlog("tdhcpc",LOG_NDELAY|LOG_PID,LOG_USER);
	usesyslog=1;
}

#ifdef ALLOCPANIC
#define LOGALLOC LOGERROR
#define PANIC exit(1)
#else
#define LOGALLOC LOGWARN
#define PANIC
#endif

void* Malloc(int s)
{
	if(s<=0)return 0;
	void*r=malloc(s);
	if(r==0){
		td_log(LOGALLOC,"unable to allocate %i bytes",s);
		PANIC;
	}
	return r;
}
void* Realloc(void*o,int s)
{
	if(s<=0){
		if(o)Free(o);
		return 0;
	}
	if(o==0){
		return Malloc(s);
	}
	void*r=realloc(o,s);
	if(r==0){
		td_log(LOGALLOC,"unable to reallocate mem 0x%llx to %i bytes",(long long)o,s);
		PANIC;
	}
	return r;
}
void Free(void*o)
{
	if(o==0)return;
	free(o);
}

void* Memcpy(void*d,void*s,int l)
{
	if(d==0){
		td_log(LOGWARN,"trying to copy to non-allocated pointer, ignoring");
		return 0;
	}
	if(s==0){
		td_log(LOGWARN,"trying to copy non-allocated pointer to mem 0x%llx, zeroing it instead",(long long)d);
		return Memzero(d,l);
	}else return memcpy(d,s,l);
}

void* Memzero(void*d,int l)
{
	if(d==0){
		td_log(LOGWARN,"trying to zero non-allocated pointer, ignoring it");
		return 0;
	}
	memset(d,0,l);
	return d;
}

char* Strcpy(char*d,const char*s)
{
	if(d==0){
		td_log(LOGWARN,"trying to copy to non-allocated string, ignoring it");
		return 0;
	}
	if(s==0){
		td_log(LOGWARN,"trying to copy from non-existent string, setting to empty string instead");
		*d=0;
		return d;
	}
	return strcpy(d,s);
}

char* Strncpy(char*d,const char*s,int l)
{
	if(d==0){
		td_log(LOGWARN,"trying to copy to non-allocated string, ignoring it");
		return 0;
	}
	if(s==0){
		td_log(LOGWARN,"trying to copy from non-existent string, setting to empty string instead");
		*d=0;
		return d;
	}
	return strncpy(d,s,l);
}

int Memcmp(void*a,void*b,int l)
{
	if(l<=0)return 0;
	if(a==0 && b==0)return 0;
	if(a==0)return -1;
	if(b==0)return 1;
	return memcmp(a,b,l);
}
