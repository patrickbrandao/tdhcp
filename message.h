/*
// C Interface: message
//
// Description: 
//
//
// Author: Konrad Rosenbaum <konrad@silmor.de>, (C) 2009
//
// Copyright: See COPYING file that comes with this distribution
//
*/

#ifndef TDHCP_MESSAGE_H
#define TDHCP_MESSAGE_H

#include "common.h"
#include <netinet/in.h>
#include <sys/time.h>

#define MSG_SOLICIT 1
#define MSG_ADVERTISE 2
#define MSG_REQUEST 3
#define MSG_REPLY 7
#define MSG_IREQUEST 11

/*currently defined maximum size of the message*/
#define MSG_MAXSIZE 65535

/*receive filter for messages - set in client.c and server.c*/
extern unsigned char MSGFILTER[8];
void clearrecvfilter();
void addrecvfilter(unsigned char);

/*flag: if true compare the message ID of received messages with that of the last sent message*/
extern int COMPAREMSGID;

/*primary options*/
#define OPT_CLIENTID 1
#define OPT_SERVERID 2
#define OPT_DNS_SERVER 23
#define OPT_DNS_NAME 24
#define OPT_IANA 3
#define OPT_IAPD 25
#define OPT_RAPIDCOMMIT 14
#define OPT_OPTREQUEST 6

/*sub-options*/
#define OPT_IAADDR 5
#define OPT_IAPREFIX 26
#define OPT_ELA_TIME 8
#define OPT_STATUS_CODE 13


#define STAT_Success	     0
#define STAT_UnspecFail      1
/*Server has no addresses available to assign to the IA(s).*/
#define STAT_NoAddrsAvail    2
/*Client record (binding) unavailable.*/
#define STAT_NoBinding       3
/*The prefix for the address is not appropriate for the link to which the client is attached.*/
#define STAT_NotOnLink       4 
/*force client to use multicasting*/
#define STAT_UseMulticast    5


/*DHCPv6 option structure*/
struct dhcp_opt{
	/*option type, see OPT_* constants*/
	unsigned short opt_type;
	/*option length (ignored on input)*/
	unsigned short opt_len;
	
	union {
		struct dhcp_opt_duid {
			unsigned short len;
			unsigned char *duid;
		} opt_duid;
		struct dhcp_opt_ia {
			long iaid;
			long t1,t2;
			/*subopts: normally of type IAADDRESS, or IAPREFIX*/
		} opt_iana;
		struct dhcp_opt_ia opt_iapd;
		struct dhcp_opt_dns_servers {
			/*number of DNS servers (opt_len/16)*/
			int num_dns;
			struct in6_addr *addr;
		} opt_dns_server;
		struct dhcp_opt_dns_names {
			int num_dns;
			char**namelist;
		} opt_dns_name;
		struct dhcp_opt_iaaddress {
			struct in6_addr addr;
			unsigned long preferred_lifetime,valid_lifetime;
			/*subopts are allowed*/
		} opt_iaaddress;
		struct dhcp_opt_iaprefix {
			struct in6_addr prefix;
			unsigned short prefixlen;
			unsigned long preferred_lifetime,valid_lifetime;
		} opt_iaprefix;
		struct dhcp_opt_ela_time {
			unsigned short csecs;
		} opt_ela_time;
		struct dhcp_opt_status {
			unsigned short status;
			char*message;
		} opt_status;
		struct dhcp_opt_request {
			int numopts;
			unsigned short *opt;
		} opt_oro;
	};
	
	/*amount of sub-options (eg. OPT_IA*)*/
	int opt_numopts;
	struct dhcp_opt*subopt;
	
	/* **** private parts **** */
	int priv_optlen;
};

/*DHCPv6 message structure*/
struct dhcp_msg {
	/*message type (see MSG_* constants)*/
	unsigned char msg_type;
	/*transaction ID, lower 24bits are used*/
	long msg_id;
	/*number of options*/
	int msg_numopts;
	/*array of options*/
	struct dhcp_opt *msg_opt;
	
	/*peer info*/
	struct sockaddr_in6 msg_peer;
	
	/* **** private parts **** */
	/*opt allocation hints*/
	int priv_optlen;
	/*time at which the message was first created: ELA_TIME option*/
	struct timeval starttime;
	
};

/*allocate a new message of given type*/
struct dhcp_msg* newmessage(int);

/*allocate an option (resets it to zero, sets given type)*/
struct dhcp_opt* newoption(unsigned short);

/*free a message structure*/
void freemessage(struct dhcp_msg*);
/*free an option structure recursively*/
void freeoption(struct dhcp_opt*);

/*add an option type to the (request) message, returns index*/
int messageaddopt(struct dhcp_msg*,unsigned short);
/*add an option to the message, returns index*/
int messageappendopt(struct dhcp_msg*,struct dhcp_opt*);
/*add a sub-option to an option, returns index*/
int optappendopt(struct dhcp_opt*,struct dhcp_opt*);
/*add an option request to the message, returns index of the ORO option*/
int messageaddoptrequest(struct dhcp_msg*,unsigned short);
/*add an option request to the ORO option; returns index of the request or -1 on error*/
int oroaddrequest(struct dhcp_opt*,unsigned short);
/*checks that the message has a certain option; returns index on success or -1 on error*/
int messagefindoption(struct dhcp_msg*,unsigned short);
/*checks that the message has an option request option with a certain option requested; returns !=0 on success*/
bool messagehasoptionrequest(struct dhcp_msg*,unsigned short);

/*removes an option (and all sub-options) from the message*/
void messageremoveoption(struct dhcp_msg*,unsigned short);

/*send the message*/
void sendmessage(struct dhcp_msg*);

/*read a message from the line and return it (NULL on error or if the message does not fit the filters)*/
struct dhcp_msg* readmessage();

#endif
