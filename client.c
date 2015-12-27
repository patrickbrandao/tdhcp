/*
*  C Implementation: client
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

/*side ID, allocated in server.c (0x00) and client.c (0x01) respectively*/
const unsigned char SIDEID=SIDE_CLIENT;


char shortopt[]="hl:pPaAdDcCr:u:L:";
struct option longopt[]= {
 {"local-id",1,0,'l'},
 {"log-level",1,0,'L'},
 {"prefix",0,0,'p'},
 {"no-prefix",0,0,'P'},
 {"address",0,0,'a'},
 {"no-addres",0,0,'A'},
 {"dns",0,0,'d'},
 {"no-dns",0,0,'D'},
 {"rapid-commit",0,0,'c'},
 {"no-rapid-commit",0,0,'C'},
 {"retries",1,0,'r'},
 {"help",0,0,'h'},
 {"duid",1,0,'u'},
 {0,0,0,0}
};

#include "svnrev.h"
#define HELP \
 "Usage: %s [options] device script\n" \
 "TDHCPc - Tunnel/Tiny DHCP client, revision " SVNREV "\n"\
 "(c) Konrad Rosenbaum, 2009\n"\
 "this program is protected under the GNU GPLv3 or at your option any newer\n"\
 "\n"\
 "TDHCP client parameters:\n"\
 "  device: a network device (eg. eth0, ppp0, tun0)\n" \
 "  script: a script that is executed after fetching parameters\n" \
 "   the script receives environment variables depending on what data has\n"\
 "   been requested and received from the server:\n"\
 "    $DNSSRV - space-separated list of DNS servers\n"\
 "    $DNSDOM - space-separated list of DNS search domain names\n"\
 "    $IPADDR - space-separated list of assigned IP addresses\n"\
 "    $PREFIX - space-separated list of assigned prefixes\n"\
 "    $DHCPSRV - the address of the DHCPv6 server that responded\n"\
 "\n"\
 "TDHCP client options:\n" \
 "  -h | --help\n" \
 "    displays this help text and exit\n" \
 \
 "  -p | --prefix\n  -P | --no-prefix\n" \
 "    enables (-p) or disables (-P) fetching a prefix\n" \
 \
 "  -a | --address\n  -A | --no-address\n" \
 "    enables (-a) or disables (-A) fetching an address\n" \
 \
 "  -d | --dns\n  -D | --no-dns\n"\
 "    enables (-d) or disables (-D) fetching DNS server addresses\n" \
 \
 "  -c | --rapid-commit\n  -C | --no-rapid-commit\n"\
 "    enables (-c) or disables (-C) rapid commit\n"\
 "    when enabled, the client attempts to use the quicker\n"\
 "    two-phase rapid commit exchange, when disable it uses\n"\
 "    the normal four-phase exchange\n"\
 "    not all DHCPv6 servers support rapid commit\n"\
 \
 "  -l ID | --local-id=ID\n" \
 "    set the local ID from which the DUID is calculated\n" \
 \
 "  -r num | --retries=num\n" \
 "     number of retries before the client gives up\n" \
 \
 "  -u DUID | --duid=DUID\n" \
 "    set hex string as explicit DUID (overrides -l)\n" \
 \
 "  -L level | --log-level=level\n" \
 "    set the log level (default is warn), must be one of:\n" \
 "    none, error, warn, info, debug\n" \
 "\n"\
 "Defaults: %sget prefix, %sget address, %sget DNS,\n"\
 "          %suse rapid commit, %i retries\n"

static char*argv0=0,*localid=0,*device=0,*script=0;
static int getprefix=0,getaddress=0,getdns=1,retries=10,userapid=1;

/*output the help text*/
static void printhelp()
{
	fprintf(stderr,HELP,
		argv0,
		getprefix?"":"don't ",
		getaddress?"":"don't ",
		getdns?"":"don't ",
		userapid?"":"don't ",
		retries
	);
}


/*maximum amount of any item that we can handle: 16 is sensitive for addresses, prefixes and DNS settings*/
#define MAXITEMS 16

static struct in6_addr addresses[MAXITEMS], prefixes[MAXITEMS], dnsservers[MAXITEMS], dhcpserver;
static char **dnsnames;
static unsigned char prefixlens[MAXITEMS];
static struct in6_addr NULLADDR;

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


static int addaddr(struct in6_addr*list,struct in6_addr itm)
{
	int i;
	/*do nothing if it is a null addr*/
	if(Memcmp(&itm,&NULLADDR,16)==0)return -1;
	/*go through list...*/
	for(i=0;i<MAXITEMS;i++){
		/*if the current one is a null addr, insert it here*/
		if(Memcmp(&list[i],&NULLADDR,16)==0){
			Memcpy(&list[i],&itm,16);
			return i;
		}
		/*otherwise: check whether it is already known*/
		if(Memcmp(&list[i],&itm,16)==0)
			return -1;
	}
	/*no free space*/
	return -1;
}

static void adddomain(const char*itm)
{
	int i;
	/*check for null items*/
	if(!itm)return;
	if(*itm==0)return;
	/*go through list...*/
	for(i=0;i<MAXITEMS;i++){
		/*if current position is empty, insert here*/
		if(!dnsnames[i]){
			dnsnames[i]=Malloc(strlen(itm)+1);
			Strcpy(dnsnames[i],itm);
			return;
		}
		/*otherwise: check whether item is known*/
		if(strcmp(dnsnames[i],itm)==0)
			return;
	}
}

/*parse the response message and manipulate the send message*/
static int handlemessage(struct dhcp_msg*rmsg,struct dhcp_msg*smsg)
{
	int i,j,p;
	/*find DNS info*/
	if(getdns){
		p=messagefindoption(rmsg,OPT_DNS_SERVER);
		if(p>=0){
			for(i=0;i<rmsg->msg_opt[p].opt_dns_server.num_dns;i++)
				addaddr(dnsservers,rmsg->msg_opt[p].opt_dns_server.addr[i]);
		}
		p=messagefindoption(rmsg,OPT_DNS_NAME);
		if(p>=0){
			for(i=0;i<rmsg->msg_opt[p].opt_dns_name.num_dns;i++)
				adddomain(rmsg->msg_opt[p].opt_dns_name.namelist[i]);
		}
	}
	/*find PREFIX info*/
	if(getprefix){
		p=messagefindoption(rmsg,OPT_IAPD);
		if(p>=0)
		for(i=0;i<rmsg->msg_opt[p].opt_numopts;i++)
			if(rmsg->msg_opt[p].subopt[i].opt_type==OPT_IAPREFIX){
				j=addaddr(prefixes,rmsg->msg_opt[p].subopt[i].opt_iaprefix.prefix);
				if(j>=0)
					prefixlens[j]=rmsg->msg_opt[p].subopt[i].opt_iaprefix.prefixlen;
			}
	}
	/*find IANA info*/
	if(getaddress){
		p=messagefindoption(rmsg,OPT_IANA);
		if(p>=0)
		for(i=0;i<rmsg->msg_opt[p].opt_numopts;i++)
			if(rmsg->msg_opt[p].subopt[i].opt_type==OPT_IAADDR)
				addaddr(addresses,rmsg->msg_opt[p].subopt[i].opt_iaaddress.addr);
	}
	/*copy server address*/
	Memcpy(&dhcpserver,&rmsg->msg_peer.sin6_addr,16);
	/*check for rapid commit or type=REPLY; if so: tell caller it can stop now*/
	if(rmsg->msg_type==MSG_REPLY)return 0;
	if(messagefindoption(rmsg,OPT_RAPIDCOMMIT)>=0)return 0;
	/*otherwise we need to continue*/
	/*correct message type & id*/
	clearrecvfilter();
	if(getprefix||getaddress){
		addrecvfilter(MSG_REPLY);
		smsg->msg_type=MSG_REQUEST;
	}else{
		addrecvfilter(MSG_REPLY);
		smsg->msg_type=MSG_IREQUEST;
	}
	smsg->msg_id++; /*elapsed time continues to count*/
	/*rapid commit is no longer applicable*/
	messageremoveoption(smsg,OPT_RAPIDCOMMIT);
	/*append server ID*/
	p=messagefindoption(rmsg,OPT_SERVERID);
	if(p>=0)messageappendopt(smsg,&rmsg->msg_opt[p]);
	return 1;
}

/*execute the script*/
static int execscript()
{
	int i;
	char tmp[128],buf[4096];
	/*check there is anything to do*/
	if(Memcmp(addresses,&NULLADDR,16)==0 &&
	   Memcmp(prefixes,&NULLADDR,16)==0 &&
	   Memcmp(dnsservers,&NULLADDR,16)==0 &&
	   *dnsnames==0){
		td_log(LOGWARN,"no information has been received from the server, not executing script");
		return 1;
	}
	/*encode addresses*/
	buf[0]=0;
	for(i=0;i<MAXITEMS;i++){
		if(Memcmp(&addresses[i],&NULLADDR,16)==0)break;
		if(i)strncat(buf," ",sizeof(buf));
		strncat(buf,inet_ntop(AF_INET6,&addresses[i],tmp,sizeof(tmp)),sizeof(buf));
	}
	if(buf[0])setenv("IPADDR",buf,1);
	/*encode prefixes*/
	buf[0]=0;
	for(i=0;i<MAXITEMS;i++){
		if(Memcmp(&prefixes[i],&NULLADDR,16)==0)break;
		if(i)strncat(buf," ",sizeof(buf));
		strncat(buf,inet_ntop(AF_INET6,&prefixes[i],tmp,sizeof(tmp)),sizeof(buf));
		snprintf(tmp,sizeof(tmp),"/%i",(int)prefixlens[i]);
		strncat(buf,tmp,sizeof(buf));
	}
	if(buf[0])setenv("PREFIX",buf,1);
	/*encode DNS servers*/
	buf[0]=0;
	for(i=0;i<MAXITEMS;i++){
		if(Memcmp(&dnsservers[i],&NULLADDR,16)==0)break;
		if(i)strncat(buf," ",sizeof(buf));
		strncat(buf,inet_ntop(AF_INET6,&dnsservers[i],tmp,sizeof(tmp)),sizeof(buf));
	}
	if(buf[0])setenv("DNSSRV",buf,1);
	/*encode DNS search names*/
	buf[0]=0;
	for(i=0;i<MAXITEMS;i++){
		if(!dnsnames[i])break;
		if(i)strncat(buf," ",sizeof(buf));
		strncat(buf,dnsnames[i],sizeof(buf));
	}
	if(buf[0])setenv("DNSDOM",buf,1);
	
	// interface
	if(device && device[0]) setenv("DEVICE", device, 1);
	
	/*dhcp server addr*/
	setenv("DHCPSRV",inet_ntop(AF_INET6,&dhcpserver,tmp,sizeof(tmp)),1);
	/*call*/
	return system(script)!=0;
}

/*main loop, message sender, etc.pp.*/
int main(int argc,char**argv)
{
	int c,optindex=1;
	struct dhcp_msg *msg;
	/*parse options*/
	argv0=*argv;
        while(1){
                c=getopt_long(argc,argv,shortopt,longopt,&optindex);
                if(c==-1)break;
                switch(c){
                        case 'p':getprefix=1;break;
                        case 'P':getprefix=0;break;
                        case 'a':getaddress=1;break;
                        case 'A':getaddress=0;break;
                        case 'd':getdns=1;break;
                        case 'D':getdns=0;break;
                        case 'r':retries=atoi(optarg);break;
                        case 'l':localid=optarg;break;
                        case 'u':setduid(optarg);break;
                        case 'c':userapid=1;break;
                        case 'C':userapid=0;break;
                        case 'L':setloglevel(optarg);break;
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
        if((optind+2)!=argc){
        	fprintf(stderr,"Syntax error.\n");
        	printhelp();
        	return 1;
	}
	device=argv[optind];
	script=argv[optind+1];

	if(DUIDLEN==0){
		if(localid)
			setlocalid(localid);
		else
			initlocalid();
	}
	/*init socket*/
	initsocket(DHCP_CLIENTPORT,device);
	if(sockfd<0){
		td_log(LOGERROR,"unable to allocate socket, exiting.");
		exit(1);
	}
	/*init my own stuff*/
	inititems();
	/*init SOLICIT/IREQ msg*/
	if(!getaddress && !getprefix){
		msg=newmessage(MSG_IREQUEST);
		addrecvfilter(MSG_REPLY);
	}else{
		msg=newmessage(MSG_SOLICIT);
		addrecvfilter(MSG_ADVERTISE);
	}
	COMPAREMSGID=1;
	settargetserver(&msg->msg_peer);
	messageaddopt(msg,OPT_CLIENTID);
	if(getdns){
		messageaddoptrequest(msg,OPT_DNS_SERVER);
		messageaddoptrequest(msg,OPT_DNS_NAME);
	}
	if(getaddress)messageaddopt(msg,OPT_IANA);
	if(getprefix)messageaddopt(msg,OPT_IAPD);
	if(userapid&&(getaddress||getprefix))messageaddopt(msg,OPT_RAPIDCOMMIT);
	/*start main loop*/
	for(c=0;c<retries;c++){
		sendmessage(msg);
		fd_set rfd,xfd;
		struct timeval tv;
		int sret;
		//wait for event
		FD_ZERO(&rfd);
		FD_ZERO(&xfd);
		FD_SET(sockfd,&rfd);
		FD_SET(sockfd,&xfd);
		tv.tv_sec=1;
		tv.tv_usec=0;
		sret=select(sockfd+1,&rfd,0,&xfd,&tv);
		//check for errors
		if(sret<0){
			int e=errno;
			if(e==EAGAIN)continue;
			td_log(LOGERROR,"Error caught: %s\n",strerror(e));
			return 1;
		}
		//check for event
		if(sret>0){
			if(FD_ISSET(sockfd,&rfd)){
				struct dhcp_msg*msg2;
				msg2=readmessage();
				if(msg2)
					if(handlemessage(msg2,msg)==0)break;
			}
			if(FD_ISSET(sockfd,&xfd)){
				td_log(LOGERROR,"Exception on socket caught.\n");
				return 1;
			}
		}else
			td_log(LOGDEBUG,"timeout, iteration %i",c);
	}
	/*execute script*/
	return execscript();
}
