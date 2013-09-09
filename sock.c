/*
*  C Implementation: sock
*
* Description: Socket handling code
*
*
* Author: Konrad Rosenbaum <konrad@silmor.de>, (C) 2009
*
* Copyright: See COPYING file that comes with this distribution
*
*/

#include "sock.h"
#include "common.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>


int sockfd=-1;

static int ifindex=-1;

static void get_if_lladdr(const char*dev,struct sockaddr_in6*sa)
{
	struct ifaddrs *ifa,*ifa2;
	getifaddrs(&ifa);
	ifa2=ifa;
	while(ifa2){
		char a[64]="(none)";
		if(strcmp(dev,ifa2->ifa_name)==0 && ifa2->ifa_addr!=0)
		if(ifa2->ifa_addr->sa_family==AF_INET6){
			struct sockaddr_in6 *in6=(void*)ifa2->ifa_addr;
			unsigned char *llt= (unsigned char*)&in6->sin6_addr;
			if(llt[0]==0xfe && (llt[1]&0xc0)==0x80){
				inet_ntop(AF_INET6,&in6->sin6_addr,a,64);
				td_log(LOGINFO,"binding device %s addr %s iface-id %i",dev,a,in6->sin6_scope_id);
				Memcpy(&sa->sin6_addr,&in6->sin6_addr,sizeof(in6->sin6_addr));
				sa->sin6_scope_id=in6->sin6_scope_id;
				break;
			}
		}
		ifa2=ifa2->ifa_next;
	}
	if(ifa2==0)
		td_log(LOGDEBUG,"no link local address found, binding to ANYv6");
	freeifaddrs(ifa);
}

int checkiface()
{
	struct ifreq ifr;
	//sanity check
	if(ifindex<0 || sockfd<0)return 0;
	//try to find the iface
	Memzero(&ifr,sizeof(ifr));
	ifr.ifr_ifindex=ifindex;
	if(ioctl(sockfd,SIOCGIFNAME,&ifr)<0){
		return 0;
	}
	return 1;
}

/*initializes the socket on port*/
void initsocket(short port,const char*dev)
{
	struct sockaddr_in6 sa;
	struct ifreq ifr;
	int val=0;
	//allocate
	sockfd=socket(PF_INET6,SOCK_DGRAM,0);
	if(sockfd<0){
		td_log(LOGERROR,"Error allocating socket: %s.",strerror(errno));
		close(sockfd);
		sockfd=-1;
		return;
	}
	val=1;
	if(setsockopt(sockfd,IPPROTO_IPV6,IPV6_V6ONLY,&val,sizeof(val))<0){
		fprintf(stderr,"Warning: cannot restrict socket to IPv6.");
	}
	//get interface
	Memzero(&ifr,sizeof(ifr));
	Strncpy(ifr.ifr_name,dev,IFNAMSIZ);
	if(ioctl(sockfd,SIOCGIFINDEX,&ifr)<0){
		td_log(LOGERROR,"Error getting device index for %s: %s.",dev,strerror(errno));
		close(sockfd);
		sockfd=-1;
		return;
	}
	ifindex=ifr.ifr_ifindex;
	td_log(LOGDEBUG,"Interface %s has index %i.",dev,ifindex);
	//set interface for mcast output
	if(setsockopt(sockfd,IPPROTO_IPV6,IPV6_MULTICAST_IF,&ifindex,sizeof(ifindex))<0){
		td_log(LOGERROR,"Error setting multicast interface: %s.",strerror(errno));
		close(sockfd);
		sockfd=-1;
		return;
	}
	//set overall interface
	if(setsockopt(sockfd,SOL_SOCKET,SO_BINDTODEVICE,dev,strlen(dev))<0){
		td_log(LOGWARN,"Cannot bind to device %s: %s",dev,strerror(errno));
	}
	//bind
	Memzero(&sa,sizeof(sa));
	sa.sin6_family=AF_INET6;
	sa.sin6_port=htons(port);
	if(SIDEID!=SIDE_SERVER)
		get_if_lladdr(dev,&sa);
	if(bind(sockfd,(struct sockaddr*)&sa,sizeof(sa))<0){
		td_log(LOGERROR,"Error binding socket: %s.\n",strerror(errno));
		close(sockfd);
		sockfd=-1;
		return;
	}

}

/*joins DHCP multicast group (server only)*/
void joindhcp()
{
	struct ipv6_mreq multi;
	inet_pton(AF_INET6,DHCP_GROUP,&multi.ipv6mr_multiaddr);
	multi.ipv6mr_interface=ifindex;
	if(setsockopt(sockfd,IPPROTO_IPV6,IPV6_ADD_MEMBERSHIP,&multi,sizeof(multi))<0){
		td_log(LOGERROR,"Unable to join multicast group " DHCP_GROUP ": %s.\n",strerror(errno));
		close(sockfd);
		sockfd=-1;
	}
}

void settargetserver(struct sockaddr_in6*sa)
{
	Memzero(sa,sizeof(struct sockaddr_in6));
	sa->sin6_family=AF_INET6;
	sa->sin6_port=htons(DHCP_SERVERPORT);
	sa->sin6_scope_id=ifindex;
	inet_pton(AF_INET6,DHCP_GROUP,&sa->sin6_addr);
}
