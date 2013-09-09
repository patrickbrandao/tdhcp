/*
*  C Implementation: server
*
* Description: 
*
*
* Author: Konrad Rosenbaum <konrad@silmor.de>, (C) 2009
*
* Copyright: See COPYING file that comes with this distribution
*
*/

#include "common.h"
#include "sock.h"
#include "message.h"

#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/*side ID, allocated in server.c (0x00) and client.c (0x01) respectively*/
const unsigned char SIDEID=SIDE_SERVER;


char shortopt[]="hl:p:a:d:D:u:L:fP:";
struct option longopt[]= {
 {"local-id",1,0,'l'},
 {"log-level",1,0,'L'},
 {"prefix",1,0,'p'},
 {"address",1,0,'a'},
 {"dns-server",1,0,'d'},
 {"dns-name",1,0,'D'},
 {"no-fork",0,0,'f'},
 {"foreground",0,0,'f'},
 {"pid-file",1,0,'P'},
 {"help",0,0,'h'},
 {"duid",1,0,'u'},
 {0,0,0,0}
};

#include "svnrev.h"
#define HELP \
 "Usage: %s [options] device\n" \
 "TDHCPc - Tunnel/Tiny DHCP server, revision " SVNREV "\n"\
 "(c) Konrad Rosenbaum, 2009\n"\
 "this program is protected under the GNU GPLv3 or at your option any newer\n"\
 "\n"\
 "TDHCP server parameters:\n"\
 "  device: a network device (eg. eth0, ppp0, tun0)\n" \
 "\n"\
 "TDHCP server options:\n" \
 "  -h | --help\n" \
 "    displays this help text and exit\n" \
 \
 "  -p prefix/length | --prefix=prefix/length\n" \
 "    sets a prefix that is sent via prefix delegation\n" \
 \
 "  -a addr | --address=addr\n" \
 "    sets the address that is delegated to the client\n" \
 \
 "  -d dnsaddr| --dns-server=dnsaddr\n  -D domain| --dns-name=domain\n"\
 "    sets the address of a DNS server (-d) or\n" \
 "    sets a search domain name (-D) for the client\n" \
 \
 "  -l ID | --local-id=ID\n" \
 "    set the local ID from which the DUID is calculated\n" \
 \
 "  -u DUID | --duid=DUID\n" \
 "    set hex string as explicit DUID (overrides -l)\n" \
 \
 "  -f | --no-fork | --foreground\n" \
 "    do not fork and log to stderr instead for syslog (good for debugging)\n" \
 \
 "  -P pidfile | --pid-file=pidfile\n" \
 "    print the server PID to pidfile (default: none)\n" \
 \
 "  -L level | --log-level=level\n" \
 "    set the log level (default is warn), must be one of:\n" \
 "    none, error, warn, info, debug\n"

static char*argv0=0,*localid=0,*device=0,*pidfile=0;
static int dofork=1;

/*output the help text*/
static void printhelp()
{
	fprintf(stderr,HELP,argv0);
}


/*maximum amount of any item that we can handle: 16 is sensitive for addresses, prefixes and DNS settings*/
#define MAXITEMS 16

static struct in6_addr addresses[MAXITEMS], prefixes[MAXITEMS], dnsservers[MAXITEMS];
static char **dnsnames;
static unsigned char prefixlens[MAXITEMS];
static struct in6_addr NULLADDR;
static int addresscnt=0,prefixcnt=0,dnsservercnt=0,dnsnamecnt=0;

static void inititems()
{
	dnsnames=Malloc(MAXITEMS*sizeof(char*));
	Memzero(dnsnames,MAXITEMS*sizeof(char*));
	Memzero(addresses,16*MAXITEMS);
	Memzero(prefixes,16*MAXITEMS);
	Memzero(dnsservers,16*MAXITEMS);
	Memzero(prefixlens,MAXITEMS);
	Memzero(&NULLADDR,16);
}

static void countitems()
{
	int i;
	for(i=0;i<MAXITEMS;i++)if(Memcmp(&addresses[i],&NULLADDR,16)==0)break;addresscnt=i;
	for(i=0;i<MAXITEMS;i++)if(Memcmp(&prefixes[i],&NULLADDR,16)==0)break;prefixcnt=i;
	for(i=0;i<MAXITEMS;i++)if(Memcmp(&dnsservers[i],&NULLADDR,16)==0)break;dnsservercnt=i;
	for(i=0;i<MAXITEMS;i++)if(dnsnames[i]==0)break;dnsnamecnt=i;
}


static int addaddr(struct in6_addr*list,const char*addr,const char*atype)
{
	int i;
	struct in6_addr itm;
	if(!inet_pton(AF_INET6,addr,&itm)){
		td_log(LOGERROR,"while parsing %s \"%s\" - not a valid IPv6 address",atype,addr);
		return -1;
	}
	/*do nothing if it is a null addr*/
	if(Memcmp(&itm,&NULLADDR,16)==0){
		td_log(LOGWARN,"cannot add a null address (%s) as %s",addr,atype);
		return -1;
	}
	/*go through list...*/
	for(i=0;i<MAXITEMS;i++){
		/*if the current one is a null addr, insert it here*/
		if(Memcmp(&list[i],&NULLADDR,16)==0){
			Memcpy(&list[i],&itm,16);
			return i;
		}
		/*otherwise: check whether it is already known*/
		if(Memcmp(&list[i],&itm,16)==0)
			return i;
	}
	/*no free space*/
	td_log(LOGWARN,"unable to add yet another %s (%s), a maximum of %i is allowed",atype,addr,MAXITEMS);
	return -1;
}

static int addprefix(const char*pre)
{
	/*copy*/
	char buf[1024],*p,*e;
	int i,j;
	Strncpy(buf,pre,sizeof(buf));
	/*find slash, get prefix length*/
	p=strchr(buf,'/');
	if(p){
		*p++=0;
		i=strtol(p,&e,10);
		if(e && *e!=0){
			td_log(LOGERROR,"invalid prefix length in %s, ignoring it",pre);
			return -1;
		}
		if(i<1 || i>128){
			td_log(LOGERROR,"prefix length must be between 1<=pl<=128 in %s, ignoring it",pre);
			return -1;
		}
	}else{
		td_log(LOGWARN,"no prefix length in prefix %s, assuming /64",pre);
		i=64;
	}
	/*add prefix*/
	j=addaddr(prefixes,buf,"prefix");
	if(j>=0)prefixlens[j]=i;
	return j;
}

static int adddomain(const char*itm)
{
	int i;
	/*check for null items*/
	if(!itm)return -1;
	if(*itm==0)return -1;
	/*go through list...*/
	for(i=0;i<MAXITEMS;i++){
		/*if current position is empty, insert here*/
		if(!dnsnames[i]){
			dnsnames[i]=Malloc(strlen(itm)+1);
			Strcpy(dnsnames[i],itm);
			return i;
		}
		/*otherwise: check whether item is known*/
		if(strcmp(dnsnames[i],itm)==0)
			return i;
	}
	/*no free space*/
	td_log(LOGWARN,"unable to add yet another domain (%s) to the search list, a maximum of %i is allowed",itm,MAXITEMS);
	return -1;
}

/*parse the response message and manipulate the send message*/
static void handlemessage(struct dhcp_msg*rmsg)
{
	int i,j,p;
	struct dhcp_msg*smsg;
	/*create reply*/
	if(rmsg->msg_type==MSG_SOLICIT)
		smsg=newmessage(MSG_ADVERTISE);
	else
		smsg=newmessage(MSG_REPLY);
	/*copy...*/
	smsg->msg_id=rmsg->msg_id;
	Memcpy(&smsg->msg_peer,&rmsg->msg_peer,sizeof(rmsg->msg_peer));
	messageaddopt(smsg,OPT_SERVERID);
	p=messagefindoption(rmsg,OPT_CLIENTID);
	if(p>=0)
		messageappendopt(smsg,&rmsg->msg_opt[p]);
	if(messagefindoption(rmsg,OPT_RAPIDCOMMIT)>=0)
		messageaddopt(smsg,OPT_RAPIDCOMMIT);
	/*find DNS info*/
	if(dnsservercnt && messagehasoptionrequest(rmsg,OPT_DNS_SERVER)){
		p=messageaddopt(smsg,OPT_DNS_SERVER);
		smsg->msg_opt[p].opt_dns_server.num_dns=dnsservercnt;
		smsg->msg_opt[p].opt_dns_server.addr=Malloc(dnsservercnt*sizeof(struct in6_addr));
		Memcpy(smsg->msg_opt[p].opt_dns_server.addr,dnsservers,dnsservercnt*sizeof(struct in6_addr));
	}
	if(dnsnamecnt && messagehasoptionrequest(rmsg,OPT_DNS_NAME)){
		p=messageaddopt(smsg,OPT_DNS_NAME);
		smsg->msg_opt[p].opt_dns_name.num_dns=dnsnamecnt;
		smsg->msg_opt[p].opt_dns_name.namelist=Malloc(dnsnamecnt*sizeof(char*));
		for(i=0;i<dnsnamecnt;i++){
			smsg->msg_opt[p].opt_dns_name.namelist[i]=Malloc(strlen(dnsnames[i])+1);
			Strcpy(smsg->msg_opt[p].opt_dns_name.namelist[i],dnsnames[i]);
		}
	}
	/*find PREFIX info*/
	if(prefixcnt && (j=messagefindoption(rmsg,OPT_IAPD))>=0){
		struct dhcp_opt pref;
		Memzero(&pref,sizeof(pref));
		/*create opt, copy IAID*/
		p=messageaddopt(smsg,OPT_IAPD);
		smsg->msg_opt[p].opt_iapd.iaid=rmsg->msg_opt[j].opt_iapd.iaid;
		/*insert prefixes*/
		pref.opt_type=OPT_IAPREFIX;
		pref.opt_iaprefix.preferred_lifetime=0xffffffff;
		pref.opt_iaprefix.valid_lifetime=0xffffffff;
		for(i=0;i<prefixcnt;i++){
			pref.opt_iaprefix.prefixlen=prefixlens[i];
			Memcpy(&pref.opt_iaprefix.prefix,&prefixes[i],16);
			optappendopt(&smsg->msg_opt[p],&pref);
		}
	}
	/*find IANA info*/
	if(addresscnt && (j=messagefindoption(rmsg,OPT_IANA))>=0){
		struct dhcp_opt addr;
		Memzero(&addr,sizeof(addr));
		/*create opt, copy IAID*/
		p=messageaddopt(smsg,OPT_IANA);
		smsg->msg_opt[p].opt_iana.iaid=rmsg->msg_opt[j].opt_iana.iaid;
		/*insert prefixes*/
		addr.opt_type=OPT_IAADDR;
		addr.opt_iaaddress.preferred_lifetime=0xffffffff;
		addr.opt_iaaddress.valid_lifetime=0xffffffff;
		for(i=0;i<addresscnt;i++){
			Memcpy(&addr.opt_iaaddress.addr,&addresses[i],16);
			optappendopt(&smsg->msg_opt[p],&addr);
		}
	}
	/*free received msg*/
	freemessage(rmsg);
	/*send*/
	sendmessage(smsg);
	/*free sent msg*/
	freemessage(smsg);
}

/*switch to daemon mode*/
static void daemonize()
{
	int pid,tfd;
	char buf[32];
	/*make sure we have a sane mask*/
	umask(022);
	/*do we really switch?*/
	if(dofork){
		/*become session leader and lose controlling tty*/
		if((pid=fork())<0){
			fprintf(stderr,"Unable to fork. Giving up.\n");
			exit(1);
		}
		if(pid!=0)exit(0);
		setsid();
		/*fork again to make sure we will never have ctty's*/
		if((pid=fork())<0){
			fprintf(stderr,"Unable to fork. Giving up.\n");
			exit(1);
		}
		if(pid!=0)exit(0);
		/*activate syslog*/
		activatesyslog();
		/*replace stdin/out/err with /dev/null*/
		close(0);close(1);close(2);
		open("/dev/null",O_RDWR);
		dup(0);dup(0);
	}
	/*write my PID*/
	if(pidfile){
		snprintf(buf,sizeof(buf),"%i",getpid());
		tfd=open(pidfile,O_CREAT|O_TRUNC|O_WRONLY|O_NOCTTY,0644);
		write(tfd,buf,strlen(buf));
		close(tfd);
	}
	/*change to root dir*/
	chdir("/");
}

/*main loop, message sender, etc.pp.*/
int main(int argc,char**argv)
{
	int c,optindex=1;
	/*init my own stuff*/
	inititems();
	/*parse options*/
	argv0=*argv;
        while(1){
                c=getopt_long(argc,argv,shortopt,longopt,&optindex);
                if(c==-1)break;
                switch(c){
                        case 'p':addprefix(optarg);break;
                        case 'a':addaddr(addresses,optarg,"address");break;
                        case 'd':addaddr(dnsservers,optarg,"DNS server address");break;
                        case 'D':adddomain(optarg);break;
                        case 'l':localid=optarg;break;
                        case 'u':setduid(optarg);break;
                        case 'L':setloglevel(optarg);break;
                        case 'f':dofork=0;break;
                        case 'P':pidfile=optarg;break;
                        default:
                                fprintf(stderr,"Syntax error in arguments.\n");
                                printhelp();
                                return 1;
                                break;
                        case 'h':
                                printhelp();
                                return 0;
                                break;
                }
        }
        if((optind+1)!=argc){
        	fprintf(stderr,"Syntax error.\n");
        	printhelp();
        	return 1;
	}
	device=argv[optind];
	/*check for DUID*/
	if(DUIDLEN==0){
		if(localid)
			setlocalid(localid);
		else
			initlocalid();
	}
	/*count my options*/
	countitems();
	/*switch to daemon mode*/
	daemonize();
	/*init socket*/
	initsocket(DHCP_SERVERPORT,device);
	if(sockfd<0){
		td_log(LOGERROR,"unable to allocate socket, exiting.");
		return 1;
	}
	joindhcp();
	if(sockfd<0){
		td_log(LOGERROR,"unable to joind DHCP multicast group, exiting.");
		return 1;
	}
	/*init filter*/
	clearrecvfilter();
	addrecvfilter(MSG_SOLICIT);
	addrecvfilter(MSG_REQUEST);
	addrecvfilter(MSG_IREQUEST);
	/*start main loop*/
	while(1){
		fd_set rfd,xfd;
		int sret;
		struct timeval tv;
		//wait for event
		FD_ZERO(&rfd);
		FD_ZERO(&xfd);
		FD_SET(sockfd,&rfd);
		FD_SET(sockfd,&xfd);
		tv.tv_sec=1;tv.tv_usec=0;
		sret=select(sockfd+1,&rfd,0,&xfd,&tv);
		//check for errors
		if(sret<0){
			int e=errno;
			if(e==EAGAIN)continue;
			td_log(LOGERROR,"Error caught: %s",strerror(e));
			return 1;
		}
		//check for event
		if(sret>0){
			if(FD_ISSET(sockfd,&rfd)){
				struct dhcp_msg*msg2;
				msg2=readmessage();
				if(msg2)
					handlemessage(msg2);
			}
			if(FD_ISSET(sockfd,&xfd)){
				td_log(LOGERROR,"Exception on socket caught.");
				return 1;
			}
		}
		//check that the interface still exists
		if(!checkiface()){
			td_log(LOGERROR,"Interface lost, exiting.");
			return 1;
		}
	}
	/*should not be reachable*/
	td_log(LOGDEBUG,"hmm, Konrad needs better coffee - this line should not be reachable");
	return 0;
}
