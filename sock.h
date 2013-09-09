/*
// C Interface: sock
//
// Description: 
//
//
// Author: Konrad Rosenbaum <konrad@silmor.de>, (C) 2009
//
// Copyright: See COPYING file that comes with this distribution
//
*/

#ifndef TDHCP_SOCK_H
#define TDHCP_SOCK_H

#define DHCP_GROUP "ff02::1:2"
#define DHCP_SERVERPORT 547
#define DHCP_CLIENTPORT 546

/*the file descriptor of the socket*/
extern int sockfd;

/*initializes the socket on port*/
void initsocket(short,const char*);
/*joins DHCP multicast group*/
void joindhcp();

/*checks that the interface still exists; returns true if found*/
int checkiface();

/*set the server multicast as target*/
struct sockaddr_in6;
void settargetserver(struct sockaddr_in6*);

#endif
