/*
*  C Implementation: message
*
* Description: 
*
*
* Author: Konrad Rosenbaum <konrad@silmor.de>, (C) 2009
*
* Copyright: See COPYING file that comes with this distribution
*
*/

#include "message.h"
#include "common.h"
#include "sock.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

/*increase allocation by ... entities*/
#define ALLOCINCR 8

struct dhcp_msg* newmessage(int t)
{
	struct dhcp_msg *r;
	
	r=Malloc(sizeof(struct dhcp_msg));
	if(r==0)return 0;
	Memzero(r,sizeof(struct dhcp_msg));
	gettimeofday(&r->starttime,0);
	r->msg_id=(r->starttime.tv_sec+r->starttime.tv_usec)&0xffffff;
	r->msg_type=t;
	
	return r;
}

struct dhcp_opt* newoption(unsigned short t)
{
	struct dhcp_opt*o;
	o=Malloc(sizeof(struct dhcp_opt));
	if(o==0)return 0;
	Memzero(o,sizeof(struct dhcp_opt));
	return o;
}

/*free the content and sub-options of an option, does not free tgt itself*/
static void freeopt(struct dhcp_opt*tgt)
{
	int i;
	/*free option dependent stuff*/
	switch(tgt->opt_type){
		case OPT_CLIENTID:case OPT_SERVERID:
			//copy duid
			Free(tgt->opt_duid.duid);
			break;
		case OPT_DNS_SERVER:
			//copy DNS
			Free(tgt->opt_dns_server.addr);
			break;
		case OPT_DNS_NAME:
			if(tgt->opt_dns_name.namelist){
				for(i=0;i<tgt->opt_dns_name.num_dns;i++)
					if(tgt->opt_dns_name.namelist[i])
						Free(tgt->opt_dns_name.namelist[i]);
				Free(tgt->opt_dns_name.namelist);
			}
			break;
		case OPT_STATUS_CODE:
			//copy message
			Free(tgt->opt_status.message);
			break;
		case OPT_OPTREQUEST:
			Free(tgt->opt_oro.opt);
			break;
	}
	/*free sub-options*/
	for(i=0;i<tgt->opt_numopts;i++)
		freeopt(&tgt->subopt[i]);
	Free(tgt->subopt);
	/*wipe*/
	Memzero(tgt,sizeof(struct dhcp_opt));
}
void freeoption(struct dhcp_opt*o)
{
	freeopt(o);
	Free(o);
}

void freemessage(struct dhcp_msg*m)
{
	int i;
	if(m==0)return;
	/*parse options*/
	for(i=0;i<m->msg_numopts;i++)
		freeopt(&m->msg_opt[i]);
	Free(m->msg_opt);
	/*wipe and free*/
	Memzero(m,sizeof(struct dhcp_msg));
	Free(m);
}

/*removes an option (and all sub-options) from the message*/
void messageremoveoption(struct dhcp_msg*msg,unsigned short opt)
{
	int pos;
	pos=messagefindoption(msg,opt);
	if(pos<0)return;
	/*free the option*/
	freeopt(&msg->msg_opt[pos]);
	/*move others*/
	if((pos+1)<msg->msg_numopts)
		memmove(&msg->msg_opt[pos],&msg->msg_opt[pos+1],msg->msg_numopts-pos);
	msg->msg_numopts--;
}

int messageaddopt(struct dhcp_msg*msg,unsigned short optid)
{
	struct dhcp_opt opt;
	Memzero(&opt,sizeof(opt));
	opt.opt_type=optid;
	/*make adjustments*/
	switch(optid)
	{
		case OPT_CLIENTID:case OPT_SERVERID:
			opt.opt_duid.len=DUIDLEN;
			opt.opt_duid.duid=DUID;
			break;
	}
	
	return messageappendopt(msg,&opt);
}

static void cloneopt(struct dhcp_opt*tgt,struct dhcp_opt*src)
{
	/*stage 1: simply copy memory image*/
	Memcpy(tgt,src,sizeof(struct dhcp_opt));
	/*stage 2: copy params, depending on type*/
	switch(tgt->opt_type){
		case OPT_CLIENTID:case OPT_SERVERID:
			//copy duid
			tgt->opt_duid.duid=Malloc(tgt->opt_duid.len);
			Memcpy(tgt->opt_duid.duid,src->opt_duid.duid,tgt->opt_duid.len);
			break;
		case OPT_DNS_SERVER:
			//copy DNS
			tgt->opt_dns_server.addr=Malloc(sizeof(struct in6_addr)*tgt->opt_dns_server.num_dns);
			Memcpy(tgt->opt_dns_server.addr,src->opt_dns_server.addr,sizeof(struct in6_addr)*tgt->opt_dns_server.num_dns);
			break;
		case OPT_DNS_NAME:
			if(tgt->opt_dns_name.num_dns){
				int i;
				tgt->opt_dns_name.namelist=Malloc(sizeof(char*)*tgt->opt_dns_name.num_dns);
				for(i=0;i<tgt->opt_dns_name.num_dns;i++){
					tgt->opt_dns_name.namelist[i]=Malloc(strlen(src->opt_dns_name.namelist[i])+1);
					Strcpy(tgt->opt_dns_name.namelist[i],src->opt_dns_name.namelist[i]);
				}
			}
			break;
		case OPT_STATUS_CODE:
			//copy message
			tgt->opt_status.message=Malloc(strlen(src->opt_status.message)+1);
			Strcpy(tgt->opt_status.message,src->opt_status.message);
			break;
	}
	/*stage 3: copy sub-opts recursively*/
	if(tgt->priv_optlen){
		int i;
		tgt->subopt=Malloc(tgt->priv_optlen*sizeof(struct dhcp_opt));
		if(tgt->subopt == 0){
			tgt->opt_numopts=0;
			tgt->priv_optlen=0;
			return;
		}
		Memzero(tgt->subopt,sizeof(struct dhcp_opt)*tgt->priv_optlen);
		for(i=0;i<tgt->opt_numopts;i++)
			cloneopt(&tgt->subopt[i],&src->subopt[i]);
	}
}

int messageappendopt(struct dhcp_msg*msg,struct dhcp_opt*opt)
{
	if(opt==0)return -1;
	if(msg->msg_numopts>=msg->priv_optlen){
		int nl=msg->priv_optlen+ALLOCINCR;
		void*nop=Realloc(msg->msg_opt,sizeof(struct dhcp_opt)*nl);
		if(nop==0)return -1;
		msg->priv_optlen=nl;
		msg->msg_opt=nop;
		Memzero(&msg->msg_opt[msg->msg_numopts],
			sizeof(struct dhcp_opt)*(msg->priv_optlen-msg->msg_numopts));
	}
	cloneopt(&msg->msg_opt[msg->msg_numopts],opt);
	return msg->msg_numopts++;
}

int optappendopt(struct dhcp_opt*sup,struct dhcp_opt*opt)
{
	if(!sup || !opt)return -1;
	if(sup->opt_numopts>=sup->priv_optlen){
		sup->priv_optlen+=ALLOCINCR;
		sup->subopt=Realloc(sup->subopt,sizeof(struct dhcp_opt)*sup->priv_optlen);
		Memzero(&sup->subopt[sup->opt_numopts],
			sizeof(struct dhcp_opt)*(sup->priv_optlen-sup->opt_numopts));
	}
	cloneopt(&sup->subopt[sup->opt_numopts],opt);
	return sup->opt_numopts++;
}

int messageaddoptrequest(struct dhcp_msg*msg,unsigned short o)
{
	int p;
	if(!msg)return -1;
	p=messagefindoption(msg,OPT_OPTREQUEST);
	if(p<0){
		p=messageaddopt(msg,OPT_OPTREQUEST);
		if(p<0)return -1;
	}
	oroaddrequest(&msg->msg_opt[p],o);
	return p;
}

/*add an option request to the ORO option; returns index of the request or -1 on error*/
int oroaddrequest(struct dhcp_opt*opt,unsigned short oro)
{
	if(!opt)return -1;
	if(opt->opt_type!=OPT_OPTREQUEST)return -1;
	opt->opt_oro.opt=Realloc(opt->opt_oro.opt,(opt->opt_oro.numopts+1)*sizeof(unsigned short));
	opt->opt_oro.opt[opt->opt_oro.numopts]=oro;
	return opt->opt_oro.numopts++;
}

/*checks that the message has a certain option; returns index on success or -1 on error*/
int messagefindoption(struct dhcp_msg*msg,unsigned short opt)
{
	int i;
	if(!msg || !opt)return -1;
	for(i=0;i<msg->msg_numopts;i++)
		if(msg->msg_opt[i].opt_type==opt)
			return i;
	return -1;
}

/*checks that the message has an option request option with a certain option requested; returns !=0 on success*/
bool messagehasoptionrequest(struct dhcp_msg*msg,unsigned short oro)
{
	int i,j;
	if(!msg || !oro)return false;
	i=messagefindoption(msg,OPT_OPTREQUEST);
	if(i<0)return false;
	for(j=0;j<msg->msg_opt[i].opt_oro.numopts;j++)
		if(msg->msg_opt[i].opt_oro.opt[j]==oro)
			return true;
	return false;
}

/*transforms a dotted domain name (eg. dom="hello.org") into DNS notation (eg. buf="\005hello\003org\000"), returns encoded length on success or 0 on failure*/
static int encodedomain(const char*dom,unsigned char*buf,int max)
{
	int i,j,l;
	/*bounds check*/
	l=strlen(dom);
	if((l+2)>max)return 0;
	/*null-domain*/
	if(*dom==0){
		*buf=0;
		return 1;
	}
	/*encode, assuming proper syntax*/
	j=-1;/*assume dot before string*/
	for(i=0;i<l;i++){
		if(dom[i]=='.'){
			/*at dot: encode length, remember position of dot*/
			buf[j+1]=i-j-1;
			j=i;
		}else{
			/*simply copy it*/
			buf[i+1]=dom[i];
		}
	}
	/*encode length of last segment*/
	buf[j+1]=l-j-1;
	/*encode end of domain*/
	buf[l+1]=0;
	/*return total length*/
	return l+2;
}

#define COPYINT4(ptr,i) (ptr)[0]=(i)>>24;(ptr)[1]=((i)>>16)&0xff;(ptr)[2]=((i)>>8)&0xff;(ptr)[3]=(i)&0xff;
#define COPYINT2(ptr,i) (ptr)[0]=((i)>>8)&0xff;(ptr)[1]=(i)&0xff;

/*encodes an option into the buffer of the message packet*/
static void encodeopt(struct dhcp_opt*opt,unsigned char*buf,int*pos,int max)
{
	int p,l;
	/*sanity test*/
	if(opt==0)return;
	/*remember old position and add header*/
	p=*pos;
	*pos += 4;
	if(*pos>max){return;}
	/*encode type*/
	COPYINT2(buf+p,opt->opt_type)
	/*encode content*/
	switch(opt->opt_type){
		case OPT_CLIENTID:case OPT_SERVERID:
			*pos+=opt->opt_duid.len;
			if(*pos>max)return;
			Memcpy(buf+p+4,opt->opt_duid.duid,opt->opt_duid.len);
			break;
		case OPT_IANA:case OPT_IAPD:
			*pos+=12;
			if(*pos>max)return;
			/*base vals*/
			COPYINT4(buf+p+4,opt->opt_iana.iaid)
			COPYINT4(buf+p+8,opt->opt_iana.t1)
			COPYINT4(buf+p+12,opt->opt_iana.t2)
			/*sub-opts*/
			for(l=0;l<opt->opt_numopts;l++)
				encodeopt(&opt->subopt[l],buf,pos,max);
			break;
		case OPT_DNS_SERVER:
			*pos+=16*opt->opt_dns_server.num_dns;
			if(*pos>max)return;
			Memcpy(buf+p+4,opt->opt_dns_server.addr,16*opt->opt_dns_server.num_dns);
			break;
		case OPT_DNS_NAME:
			for(l=0;l<opt->opt_dns_name.num_dns;l++){
				*pos+=encodedomain(opt->opt_dns_name.namelist[l],buf+ *pos,max- *pos);
				if(*pos>max)return;
			}
			break;
		case OPT_IAADDR:
			*pos+=24;
			if(*pos>max)return;
			Memcpy(buf+p+4,&opt->opt_iaaddress.addr,16);
			COPYINT4(buf+p+20,opt->opt_iaaddress.preferred_lifetime)
			COPYINT4(buf+p+24,opt->opt_iaaddress.valid_lifetime)
			/*sub-opts*/
			for(l=0;l<opt->opt_numopts;l++)
				encodeopt(&opt->subopt[l],buf,pos,max);
			break;
		case OPT_IAPREFIX:
			*pos+=25;
			if(*pos>max)return;
			COPYINT4(buf+p+4,opt->opt_iaprefix.preferred_lifetime)
			COPYINT4(buf+p+8,opt->opt_iaprefix.valid_lifetime)
			buf[p+12]=opt->opt_iaprefix.prefixlen;
			Memcpy(buf+p+13,&opt->opt_iaprefix.prefix,16);
			/*sub-opts*/
			for(l=0;l<opt->opt_numopts;l++)
				encodeopt(&opt->subopt[l],buf,pos,max);
			break;
		case OPT_ELA_TIME:
			*pos+=2;
			if(*pos>max)return;
			COPYINT2(buf+p+4,opt->opt_ela_time.csecs)
			break;
		case OPT_STATUS_CODE:
			*pos+=2+strlen(opt->opt_status.message);
			if(*pos>max)return;
			COPYINT2(buf+p+4,opt->opt_status.status);
			Memcpy(buf+p+6,opt->opt_status.message,strlen(opt->opt_status.message));
			break;
		case OPT_RAPIDCOMMIT:
			/*nothing to do*/
			break;
		case OPT_OPTREQUEST:
			*pos+=2*opt->opt_oro.numopts;
			if(*pos>max)return;
			for(l=0;l<opt->opt_oro.numopts;l++){
				COPYINT2(buf+p+4+l*2,opt->opt_oro.opt[l]);
			}
			break;
		default:
			td_log(LOGWARN,"encountered unknown option %i while encoding message, ignoring it",(int)opt->opt_type);
			*pos-=4;
			return;
	}
	/*encode length*/
	l=*pos-p;l-=4;
	COPYINT2(buf+p+2,l);
}

/*encodes the time since the message was allocated into an elapsed time option in the message packet*/
static void encodetime(struct dhcp_msg*msg,unsigned char*buf,int*pos,int max)
{
	struct timeval tv;
	long long t1,t2;
	struct dhcp_opt opt;
	Memzero(&opt,sizeof(opt));
	gettimeofday(&tv,0);
	t1=msg->starttime.tv_sec*100 + msg->starttime.tv_usec/10000;
	t2=tv.tv_sec*100 + tv.tv_usec/10000;
	opt.opt_type=OPT_ELA_TIME;
	opt.opt_ela_time.csecs=t2-t1;
	encodeopt(&opt,buf,pos,max);
}

/*flag: compare message id on receive*/
int COMPAREMSGID=0;
/*remembers last sent message id for comparison*/
static int lastmsgid=0;

/*sends a message to the peer*/
void sendmessage(struct dhcp_msg*msg)
{
	unsigned char buf[65536];
	int i,pos;
	if(msg==0)return;
	/*header*/
	/*type*/
	buf[0]=msg->msg_type;
	/*transaction ID*/
	buf[1]=(msg->msg_id>>16)&0xff;
	buf[2]=(msg->msg_id>>8)&0xff;
	buf[3]=msg->msg_id&0xff;
	pos=4;
	/*options*/
	for(i=0;i<msg->msg_numopts;i++)
		encodeopt(&msg->msg_opt[i],buf,&pos,sizeof(buf));
	/*elapsed time for the client*/
	if(SIDEID==SIDE_CLIENT)
		encodetime(msg,buf,&pos,sizeof(buf));
	/*check*/
	if(pos>sizeof(buf)){
		td_log(LOGERROR,"internal problem: message is too big (>64kB) to send");
		return;
	}
	/*send*/
	i=sendto(sockfd,buf,pos,0,(struct sockaddr*)&msg->msg_peer,sizeof(msg->msg_peer));
	if(i<0)
		td_log(LOGERROR,"unable to send message to %s: %s", inet_ntop(AF_INET6,&msg->msg_peer.sin6_addr,(char*)buf,sizeof(buf)), strerror(errno));
	else{
		td_log(LOGDEBUG,"sent message of type %i, %i bytes, to %s", (int)msg->msg_type, pos, inet_ntop(AF_INET6,&msg->msg_peer.sin6_addr,(char*)buf,sizeof(buf)));
		lastmsgid=msg->msg_id;
	}
}

/*message types that we receive*/
unsigned char MSGFILTER[8]={0,0,0,0, 0,0,0,0};
void clearrecvfilter()
{
	Memzero(MSGFILTER,sizeof(MSGFILTER));
}

void addrecvfilter(unsigned char t)
{
	int i;
	if(t==0)return;
	for(i=0;i<(sizeof(MSGFILTER)/sizeof(unsigned char));i++)
		if(MSGFILTER[i]==0){
			MSGFILTER[i]=t;
			return;
		}
}

/*helpers for decoding*/
#define GETINT2(ptr) (((int)(ptr)[0])<<8 | (ptr)[1])
#define GETINT4(ptr) (((int)(ptr)[0])<<24 | ((int)(ptr)[1])<<16 | ((int)(ptr)[2])<<8 | (ptr)[3])

static void decodeopt(struct dhcp_opt*opt,unsigned char*buf,int max);

/*decode sub-options recursively (used by decodeopt), buf must point to the start of sub-options*/
static void decodesubopts(struct dhcp_opt*opt,unsigned char*buf,int max)
{
	if(!opt)return;
	while(max>=4){
		int t,s;
		t=GETINT2(buf);
		s=GETINT2(buf+2);
		if((s+4)>max)return;
		/*allocate*/
		opt->subopt=Realloc(opt->subopt,sizeof(struct dhcp_opt)*(opt->opt_numopts+1));
		Memzero(&opt->subopt[opt->opt_numopts],sizeof(struct dhcp_opt));
		/*actually decode it*/
		opt->subopt[opt->opt_numopts].opt_type=t;
		opt->subopt[opt->opt_numopts].opt_len=s;
		decodeopt(&opt->subopt[opt->opt_numopts],buf+4,s);
		opt->opt_numopts++;
		/*jump to next option*/
		max-=s+4;
		buf+=s+4;
	}
}

/*decode the content a DNS server name, returns the amount of bytes consumed in len, returns the dotted string notation or NULL on error, maximum name length is 1024 bytes (incl. \0)*/
static const char*decodedomain(unsigned char*buf,int max,int *len)
{
	static char ret[1024];
	int i,j;
	/*start parsing*/
	*len=0;j=0;
	while(*len<max){
		/*get length of next segment*/
		i=buf[(*len)++];
		/*check for end of domain*/
		if(i==0){
			ret[j]=0;
			break;
		}
		/*add dot*/
		if(j)ret[j++]='.';
		/*bounds check*/
		if((j+i)>=sizeof(ret) || ((*len)+i)>=max){
			td_log(LOGWARN,"error while parsing domain name, skipping remainder");
			*len=max;
			return 0;
		}
		/*copy*/
		Memcpy(ret+j,buf+ (*len),i);
		j+=i;(*len)+=i;
	}
	/*return result*/
	return ret;
}

/*parse the content of an option (used by decodemsgopt; recursively used by decodesubopts)*/
static void decodeopt(struct dhcp_opt*opt,unsigned char*buf,int max)
{
	int i,l;
	switch(opt->opt_type){
		case OPT_CLIENTID:
		case OPT_SERVERID:
			opt->opt_duid.len=max;
			opt->opt_duid.duid=Malloc(max);
			Memcpy(opt->opt_duid.duid,buf,max);
			break;
		case OPT_DNS_SERVER:
			opt->opt_dns_server.num_dns=max/16;
			opt->opt_dns_server.addr=Malloc(max);
			Memcpy(opt->opt_dns_server.addr,buf,max);
			break;
		case OPT_DNS_NAME:
			i=0;
			while(i<max){
				const char *d=decodedomain(buf+i,max-i,&l);
				if(!d || !l)break;
				i+=l;
				opt->opt_dns_name.namelist=
				 Realloc(opt->opt_dns_name.namelist,
				  sizeof(char*)*(opt->opt_dns_name.num_dns+1));
				opt->opt_dns_name.namelist[opt->opt_dns_name.num_dns]=Malloc(strlen(d)+1);
				Strcpy(opt->opt_dns_name.namelist[opt->opt_dns_name.num_dns],d);
				opt->opt_dns_name.num_dns++;
			}
			break;
		case OPT_IANA:
		case OPT_IAPD:
			if(max<12)return;
			opt->opt_iana.iaid=GETINT4(buf);
			opt->opt_iana.t1=GETINT4(buf+4);
			opt->opt_iana.t2=GETINT4(buf+8);
			decodesubopts(opt,buf+12,max-12);
			break;
		case OPT_RAPIDCOMMIT:
			/*nothing to do*/
			break;
		case OPT_OPTREQUEST:
			opt->opt_oro.numopts=max/2;
			opt->opt_oro.opt=Malloc(opt->opt_oro.numopts*sizeof(unsigned short));
			for(i=0;i<max/2;i++){
				opt->opt_oro.opt[i]=GETINT2(buf+i*2);
			}
			break;
		/*sub-options*/
		case OPT_IAADDR:
			if(max<24)return;
			Memcpy(&opt->opt_iaaddress.addr,buf,16);
			opt->opt_iaaddress.preferred_lifetime=GETINT4(buf+16);
			opt->opt_iaaddress.valid_lifetime=GETINT4(buf+20);
			decodesubopts(opt,buf+24,max-24);
			break;
		case OPT_IAPREFIX:
			if(max<25)return;
			opt->opt_iaprefix.preferred_lifetime=GETINT4(buf);
			opt->opt_iaprefix.valid_lifetime=GETINT4(buf+4);
			opt->opt_iaprefix.prefixlen=buf[8];
			Memcpy(&opt->opt_iaprefix.prefix,buf+9,16);
			decodesubopts(opt,buf+25,max-25);
			break;
		case OPT_ELA_TIME:
			if(max<2)return;
			opt->opt_ela_time.csecs=GETINT2(buf);
			break;
		case OPT_STATUS_CODE:
			if(max<2)return;
			opt->opt_status.status=GETINT2(buf);
			opt->opt_status.message=Malloc(max-1);
			Memcpy(opt->opt_status.message,buf,max-2);
			opt->opt_status.message[max-2]=0;
			break;
		default:
			td_log(LOGWARN,"unknown option %i encountered, ignoring its content.",(int)opt->opt_type);
			break;
	}
}

/*decodes an option on message level (calls decodeopt to do the actual work, used by decodemessage)*/
static void decodemsgopt(struct dhcp_msg*msg,unsigned char*buf,int*pos,int max)
{
	int p,s;
	p=*pos;
	*pos+=4;
	if(*pos>=max)return;
	/*check option size*/
	s=GETINT2(buf+p+2);
	*pos+=s;
	if(*pos>max){
		td_log(LOGWARN,"encountered option that spans beyond the message, ignoring it");
		return;
	}
	/*allocate option, init to zero*/
	msg->msg_opt=Realloc(msg->msg_opt,sizeof(struct dhcp_opt)*(msg->msg_numopts+1));
	Memzero(&msg->msg_opt[msg->msg_numopts],sizeof(struct dhcp_opt));
	/*set header data*/
	msg->msg_opt[msg->msg_numopts].opt_len=s;
	msg->msg_opt[msg->msg_numopts].opt_type=GETINT2(buf+p);
	/*actually parse it*/
	decodeopt(&msg->msg_opt[msg->msg_numopts],buf+p+4,s);
	msg->msg_numopts++;
}

/*decode a DHCPv6 message*/
static struct dhcp_msg* decodemessage(unsigned char*buf,int max)
{
	int i,p;
	struct dhcp_msg*msg;
	/*check msg type*/
	if(max<4){
		td_log(LOGWARN,"received undersized message, dropping it");
		return 0;
	}
	if(buf[0]==0){
		td_log(LOGWARN,"received invalid message, dropping it");
		return 0;
	}
	for(i=p=0;i<(sizeof(MSGFILTER)/sizeof(unsigned char));i++)
		if(MSGFILTER[i]==buf[0]){
			p=1;
			break;
		}
	if(!p){
		td_log(LOGINFO,"received unexpected message of type %i, dropping it",(int)buf[0]);
		return 0;
	}
	/*decode + check MSG_ID for responses*/
	p=((int)buf[1])<<16 | ((int)buf[2])<<8 | buf[3];
	if(COMPAREMSGID)
		if(p!=lastmsgid){
			td_log(LOGINFO,"received unexpected message with msg id %i, while expecting %i",p,lastmsgid);
			return 0;
		}
	/*allocate*/
	msg=Malloc(sizeof(struct dhcp_msg));
	Memzero(msg,sizeof(struct dhcp_msg));
	msg->msg_id=p;
	msg->msg_type=buf[0];
	/*decode options*/
	p=4;
	while(p<max)
		decodemsgopt(msg,buf,&p,max);
	/*go for it*/
	return msg;
}

/*read a message from the line and return it (NULL on error)*/
struct dhcp_msg* readmessage()
{
	char buf[65536],tmp[128];
	int s;
	socklen_t p;
	struct sockaddr_in6 sa;
	struct dhcp_msg*ret;
	unsigned char *llt;
	/*receive*/
	p=sizeof(sa);
	s=recvfrom(sockfd,buf,sizeof(buf),MSG_TRUNC,(struct sockaddr*)&sa,&p);
	/*check message size*/
	if(s<0){
		td_log(LOGWARN,"error during read: %s",strerror(errno));
		return 0;
	}
	td_log(LOGDEBUG,"received message size %i from %s",s, inet_ntop(AF_INET6,&sa.sin6_addr,tmp,sizeof(tmp)));
	if(s>sizeof(buf)){
		td_log(LOGWARN,"received oversized packet (%i bytes), ignoring it",s);
		return 0;
	}
	/*check sender*/
	llt= (unsigned char*)&sa.sin6_addr;
	if(llt[0]!=0xfe || (llt[1]&0xc0)!=0x80){
		td_log(LOGWARN,"received message from non-link-local sender, dropping it");
		return 0;
	}
	/*decode*/
	td_log(LOGDEBUG,"read %i bytes, decoding now",s);
	ret=decodemessage((unsigned char*)buf,s);
	if(ret)Memcpy(&ret->msg_peer,&sa,sizeof(sa));
	return ret;
}
