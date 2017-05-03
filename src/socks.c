/*
   3APA3A simpliest proxy server
   (c) 2002-2016 by Vladimir Dubrovin <3proxy@3proxy.ru>

   please read License Agreement

*/

#include "proxy.h"

#define RETURN(xxx) { param->res = xxx; goto CLEANRET; }

/* user-chainip-chainport */
int strip_next_chain(char *buf, char chainip[16], char chainport[6])
{
    if (!(buf = strtok(buf, "-")))
        return 0;
    if (!(buf = strtok(NULL, "-")))
        return 0;
    strncpy(chainip, buf, 15);
    chainip[15] = 0;

    if (!(buf = strtok(NULL, "-")))
        return 0;
    strncpy(chainport, buf, 5);
    chainport[5] = 0;

    return 1;
}

int inject_next_chain(struct clientparam *param, char chainip[16], char chainport[6])
{
    if (!(param->myacl = myalloc(sizeof(struct ace))))
        return 0;
    if (!(param->myacl->chains = myalloc(sizeof(struct chain))))
        return 0;
/* manual memory management?, this got SIGSEGV, figure it out later
    bzero(param->myacl, sizeof(struct ace));
    bzero(param->myacl->chains, sizeof(struct chain));
*/
    param->myacl->next = 0;
    param->myacl->operation = 0;
    param->myacl->wdays = 0;
    param->myacl->nolog = 0;
    param->myacl->periods = 0;
    param->myacl->users = 0;
    param->myacl->src = param->myacl->dst = 0;
    param->myacl->dstnames = 0;
    param->myacl->ports = 0;

    param->myacl->chains->next = 0;
    param->myacl->chains->exthost = 0;
    param->myacl->chains->extuser = 0;
    param->myacl->chains->extpass = 0;

    param->myacl->action = REDIRECT;
    param->myacl->chains->type = R_SOCKS5;
    param->myacl->chains->weight = 1000;
    param->myacl->chains->exthost = mystrdup(chainip);

    struct sockaddr_in sin;
    char *err;
    unsigned int status = 1;

    if (inet_pton(AF_INET, chainip, &sin.sin_addr) != 1) {
        fprintf(stderr, "Invalid next chain ip address provided: %s\n", chainip);
        return 0;
    }

    sin.sin_port = strtol(chainport, &err, 10);
    if (*err) {
        fprintf(stderr, "Invalid next chain port provided: %s\n", chainport);
        return 0;
    }

    param->myacl->chains->addr.sin_addr = sin.sin_addr;
    param->myacl->chains->addr.sin_port = htons(sin.sin_port);
    param->myacl->chains->addr.sin_family = AF_INET;

    return 1;
}

unsigned char * commands[] = {(unsigned char *)"UNKNOWN", (unsigned char *)"CONNECT", (unsigned char *)"BIND", (unsigned char *)"UDPMAP"};

#define BUFSIZE 1024
#define LARGEBUFSIZE 67000

void * sockschild(struct clientparam* param) {
 int res;
 unsigned i=0;
 SOCKET s;
 unsigned size;
 SASIZETYPE sasize;
 unsigned short port = 0;
 unsigned char * buf=NULL;
 unsigned char c;
 unsigned char command=0;
 struct pollfd fds[3];
 int ver=0;
 int havepass = 0;
#ifndef NOIPV6
 struct sockaddr_in6 sin = {AF_INET6};
#else
 struct sockaddr_in sin = {AF_INET};
#endif
 int len;

 /* chain hooks */
 char chainip[16];
 char chainport[6];

 param->service = S_SOCKS;

 if(!(buf = myalloc(BUFSIZE))) {RETURN(21);}
 memset(buf, 0, BUFSIZE);
 if ((ver = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_L], 0)) != 5 && ver != 4) {
	RETURN(401);
 } /* version */
 param->service = ver;
 if(ver == 5){
	 if ((i = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0)) == EOF) {RETURN(441);} /* nmethods */
	 for (; i; i--) { /* iterate through all the nmethods */
		if ((res = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0)) == EOF) {RETURN(441);}
		if (res == 2 && param->srv->needuser) {
			havepass = res;
		}
	 }
	 buf[0] = 5;
	 buf[1] = (param->srv->needuser > 1 && !havepass)? 255 : havepass;
	 if(socksend(param->clisock, buf, 2, conf.timeouts[STRING_S])!=2){RETURN(401);}
	 if (param->srv->needuser > 1 && !havepass) RETURN(4);
     /* authentication */
	 if (havepass) {
		if (((res = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_L], 0))) != 1) { /* the version is 1 */
			RETURN(412);
		}
		if ((i = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0)) == EOF) {RETURN(451);} /* the number of chars in the login */
		if (i && (unsigned)(res = sockgetlinebuf(param, CLIENT, buf, i, 0, conf.timeouts[STRING_S])) != i){RETURN(441);}; /* read login in buf */
		buf[i] = 0;

        if (!strip_next_chain(buf,chainip,chainport)) {RETURN(441);};

		if(!param->username)param->username = (unsigned char *)mystrdup((char *)buf);
		if ((i = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0)) == EOF) {RETURN(445);} /* the nr of chars in the password */
		if (i && (unsigned)(res = sockgetlinebuf(param, CLIENT, buf, i, 0, conf.timeouts[STRING_S])) != i){RETURN(441);}; /* read the password in buf */
		buf[i] = 0;
		if(!param->password)param->password = (unsigned char *)mystrdup((char *)buf);
        /* send auth successfully received */
		buf[0] = 1;
		buf[1] = 0;
		if(socksend(param->clisock, buf, 2, conf.timeouts[STRING_S])!=2){RETURN(481);}

        if (!inject_next_chain(param, chainip, chainport)) { RETURN(441); }
	 }
	 if ((c = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_L], 0)) != 5) {
		RETURN(421);
         } /* version */
 }
 if( (command = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0)) < 1 || command > 3){command = 0; RETURN(407);} /* command */
 if(ver == 5){
	 if (sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0) == EOF) {RETURN(447);} /* reserved */
	 c = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0); /* atype */
 }
 else {
	if ((res = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0)) == EOF) {RETURN(441);}
	buf[0] = (unsigned char) res;
	if ((res = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0)) == EOF) {RETURN(441);}
	buf[1] = (unsigned char) res;
	port = *(unsigned short*)buf;
	c = 1;
 }

 size = 4;
 *SAFAMILY(&param->sinsr) = *SAFAMILY(&param->req) = AF_INET;
 switch(c) {
#ifndef NOIPV6
	case 4:
		if(param->srv->family == 4) RETURN(997);
		size = 16;
		*SAFAMILY(&param->sinsr) = *SAFAMILY(&param->req) = AF_INET6;
#endif
	case 1:
        /* get 4 or 16 bytes of destination address to connect to */
		for (i = 0; i<size; i++){
			if ((res = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0)) == EOF) {RETURN(441);}
			buf[i] = (unsigned char)res;
		}
#ifndef NOIPV6
		if (c == 1 && param->srv->family==6){
			char prefix[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255};
			*SAFAMILY(&param->sinsr) = *SAFAMILY(&param->req) = AF_INET6;
			memcpy(SAADDR(&param->sinsr), prefix, 12);
			memcpy(12 + (char *)SAADDR(&param->sinsr), buf, 4);
			memcpy(SAADDR(&param->req), prefix, 12);
			memcpy(12 + (char *)SAADDR(&param->req), buf, 4);
		}
		else {
#endif
			memcpy(SAADDR(&param->sinsr), buf, size);
			memcpy(SAADDR(&param->req), buf, size);
#ifndef NOIPV6
		}
#endif
		if(command == 1 && SAISNULL(&param->req)) {
			RETURN(431);
		}
		myinet_ntop(*SAFAMILY(&param->sinsr), SAADDR(&param->sinsr), (char *)buf, 64);
		break;
	case 3:
		if ((size = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0)) == EOF) {RETURN(451);} /* len of domain name */
		for (i=0; i<size; i++){ /* size < 256, read domain name */
			if ((res = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0)) == EOF) {RETURN(451);}
			buf[i] = (unsigned char)res;
		}
		buf[i] = 0;
		if(!getip46(param->srv->family, buf, (struct sockaddr *) &param->req)) RETURN(100);
		param->sinsr = param->req;
		break;
	default:
		RETURN(997);
 }
 if(param->hostname)myfree(param->hostname);
 /* put presentation of the hostname in buf */
 param->hostname = (unsigned char *)mystrdup((char *)buf);
 if (ver == 5) { // fill port (cmd==1)
	 if ((res = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0)) == EOF) {RETURN(441);} // port 1st byte
	 buf[0] = (unsigned char) res;
	 if ((res = sockgetcharcli(param, conf.timeouts[SINGLEBYTE_S], 0)) == EOF) {RETURN(441);} // port 2nd byte
	 buf[1] = (unsigned char) res;
	 port = *(unsigned short*)buf;

 }
 else {
	sockgetlinebuf(param, CLIENT, buf, BUFSIZE - 1, 0, conf.timeouts[STRING_S]);
	buf[127] = 0;
	if(param->srv->needuser && *buf && !param->username)param->username = (unsigned char *)mystrdup((char *)buf);
	if(!memcmp(SAADDR(&param->req), "\0\0\0", 3)){
		param->service = S_SOCKS45;
		sockgetlinebuf(param, CLIENT, buf, BUFSIZE - 1, 0, conf.timeouts[STRING_S]);
		buf[127] = 0;
		if(param->hostname)myfree(param->hostname);
		param->hostname = (unsigned char *)mystrdup((char *)buf);
		if(!getip46(param->srv->family, buf, (struct sockaddr *) &param->req)) RETURN(100);
		param->sinsr = param->req;
	}
 }

 *SAPORT(&param->sinsr) = *SAPORT(&param->req) = port;
 if(command == 1 && !*SAPORT(&param->sinsr)) {RETURN(461);}
 switch(command) {
	case 1:
	 param->operation = CONNECT;
	 break;
 	case 2:
	case 3:

#ifndef NOIPV6
	 param->sinsl = *SAFAMILY(&param->req)==AF_INET6? param->srv->extsa6 : param->srv->extsa;
#else
	 param->sinsl = param->srv->extsa;
#endif
	 if ((param->remsock=so._socket(SASOCK(&param->req), command == 2? SOCK_STREAM:SOCK_DGRAM, command == 2?IPPROTO_TCP:IPPROTO_UDP)) == INVALID_SOCKET) {RETURN (11);}
	 param->operation = command == 2?BIND:UDPASSOC;
#ifdef REUSE
	if (command == 2){
		int opt;

#ifdef SO_REUSEADDR
		opt = 1;
		so._setsockopt(param->remsock, SOL_SOCKET, SO_REUSEADDR, (unsigned char *)&opt, sizeof(int));
#endif
#ifdef SO_REUSEPORT
		opt = 1;
		so._setsockopt(param->remsock, SOL_SOCKET, SO_REUSEPORT, (unsigned char *)&opt, sizeof(int));
#endif
	}
#endif
	 break;

	default:
	 RETURN(997);
 }
 /* authenticate */
 if((res = (*param->srv->authfunc)(param))) {
	RETURN(res);
 }
 /* in case of BIND or UDP ASSOCIATE */
 if(command > 1) {
	if(so._bind(param->remsock,(struct sockaddr *)&param->sinsl,SASIZE(&param->sinsl))) {
		*SAPORT(&param->sinsl) = 0;
		if(so._bind(param->remsock,(struct sockaddr *)&param->sinsl,SASIZE(&param->sinsl)))RETURN (12);
#if SOCKSTRACE > 0
fprintf(stderr, "%hu binded to communicate with server\n", *SAPORT(&param->sins));
fflush(stderr);
#endif
	}
	sasize = SASIZE(&param->sinsl);
	so._getsockname(param->remsock, (struct sockaddr *)&param->sinsl,  &sasize);
	if(command == 3) {
		param->ctrlsock = param->clisock;
		param->clisock = so._socket(SASOCK(&param->sincr), SOCK_DGRAM, IPPROTO_UDP);
		if(param->clisock == INVALID_SOCKET) {RETURN(11);}
		sin = param->sincl;
		*SAPORT(&sin) = 0;
		if(so._bind(param->clisock,(struct sockaddr *)&sin,SASIZE(&sin))) {RETURN (12);}
#if SOCKSTRACE > 0
fprintf(stderr, "%hu binded to communicate with client\n",
			ntohs(*SAPORT(&sin))
	);
fflush(stderr);
#endif
	}
 }
 param->res = 0;

CLEANRET:

 if(param->clisock != INVALID_SOCKET){
	int repcode;

	sasize = sizeof(sin);
	if(command != 3) so._getsockname(param->remsock, (struct sockaddr *)&sin,  &sasize);
	else so._getsockname(param->clisock, (struct sockaddr *)&sin,  &sasize);
#if SOCKSTRACE > 0
fprintf(stderr, "Sending confirmation to client with code %d for %s with %s:%hu\n",
			param->res,
			commands[command],
			inet_ntoa(sin.sin_addr),
			ntohs(sin.sin_port)
	);
fflush(stderr);
#endif
	if(!param->res) repcode = 0;
	else if(param->res <= 10) repcode = 2;
	else if (param->res < 20) repcode = 5;
	else if (param->res < 30) repcode = 1;
	else if (param->res < 100) repcode = 4;
	else repcode = param->res%10;

	if(ver == 5){
		buf[0] = 5;
		buf[1] = repcode;
		buf[2] = 0;
		buf[3] = (*SAFAMILY(&sin) == AF_INET)?1:4;
		memcpy(buf+4, SAADDR(&sin), SAADDRLEN(&sin));
		memcpy(buf+4+SAADDRLEN(&sin), SAPORT(&sin), 2);
		socksend((command == 3)?param->ctrlsock:param->clisock, buf, 6+SAADDRLEN(&sin), conf.timeouts[STRING_S]);
	}
	else{
		buf[0] = 0;
		buf[1] = 90 + !!(repcode);
		memcpy(buf+2, SAPORT(&sin), 2);
		memcpy(buf+4, SAADDR(&sin), 4);
		socksend(param->clisock, buf, 8, conf.timeouts[STRING_S]);
	}

	if (param->res == 0) {
		switch(command) {
			case 1:
				if(param->redirectfunc){
					if(buf)myfree(buf);
					return (*param->redirectfunc)(param);
				}
				param->res = mapsocket(param, conf.timeouts[CONNECTION_L]);
				break;
			case 2:
				so._listen (param->remsock, 1);

				fds[0].fd = param->remsock;
				fds[1].fd = param->clisock;
				fds[0].events = fds[1].events = POLLIN;
				res = so._poll(fds, 2, conf.timeouts[CONNECTION_L] * 1000);
				if (res < 1 || fds[1].revents) {
					res = 460;
					break;
				}
				sasize = sizeof(param->sinsr);
				s = so._accept(param->remsock, (struct sockaddr *)&param->sinsr, &sasize);
				so._closesocket(param->remsock);
				param->remsock = s;
				if(s == INVALID_SOCKET) {
					param->res = 462;
					break;
				}
				if(SAISNULL(&param->req) &&
				 memcmp(SAADDR(&param->req),SAADDR(&param->sinsr),SAADDRLEN(&param->req))) {
					param->res = 470;
					break;
				}
#if SOCKSTRACE > 0
fprintf(stderr, "Sending incoming connection to client with code %d for %s with %hu\n",
			param->res,
			commands[command],
			*SAPORT(param->sins);
	);
fflush(stderr);
#endif
				if(ver == 5){
					buf[3] = (*SAFAMILY(&param->sinsr) == AF_INET)?1:4;
					memcpy(buf+4, SAADDR(&param->sinsr), SAADDRLEN(&param->sinsr));
					memcpy(buf+4+SAADDRLEN(&param->sinsr), SAPORT(&param->sinsr), 2);
					socksend(param->clisock, buf, 6+SAADDRLEN(&param->sinsr), conf.timeouts[STRING_S]);
				}
				else {
					memcpy (buf+2, SAPORT(&param->sinsr), 2);
					memcpy (buf+4, SAADDR(&param->sinsr), 4);
					socksend(param->clisock, buf, 8, conf.timeouts[STRING_S]);
				}

				param->res = mapsocket(param, conf.timeouts[CONNECTION_S]);
				break;
			case 3:
				param->sinsr = param->req;
				myfree(buf);
				if(!(buf = myalloc(LARGEBUFSIZE))) {RETURN(21);}

				for(;;){
					fds[0].fd = param->remsock;
					fds[1].fd = param->clisock;
					fds[2].fd = param->ctrlsock;
					fds[2].events = fds[1].events = fds[0].events = POLLIN;

					res = so._poll(fds, 3, conf.timeouts[CONNECTION_L]*1000);
					if(res <= 0) {
						param->res = 463;
						break;
					}
					if (fds[2].revents) {
						param->res = 0;
						break;
					}
					if (fds[1].revents) {
						sasize = sizeof(sin);
						if((len = so._recvfrom(param->clisock, (char *)buf, 65535, 0, (struct sockaddr *)&sin, &sasize)) <= 10) {
							param->res = 464;
							break;
						}
						if(SAADDRLEN(&sin) != SAADDRLEN(&param->sincr) || memcmp(SAADDR(&sin), SAADDR(&param->sincr), SAADDRLEN(&sin))){
							param->res = 465;
							break;
						}
						if(buf[0] || buf[1] || buf[2]) {
							param->res = 466;
							break;
						}
						size = 4;
						switch(buf[3]) {
							case 4:
								size = 16;
							case 1:
								i = 4+size;
								memcpy(SAADDR(&param->sinsr), buf+4, size);
								*SAFAMILY(&param->sinsr) = (size == 4)?AF_INET:AF_INET6;
								break;
							case 3:
								size = buf[4];
								for (i=4; size; i++, size--){
									buf[i] = buf[i+1];
								}
								buf[i++] = 0;
								if(!getip46(param->srv->family, buf, (struct sockaddr *) &param->sinsr)) RETURN(100);
								break;
							default:
								RETURN(997);
						 }

						memcpy(SAPORT(&param->sinsr), buf+i, 2);
						i+=2;

						sasize = sizeof(param->sinsr);
						if(len > (int)i){
							if(socksendto(param->remsock, (struct sockaddr *)&param->sinsr, buf+i, len - i, conf.timeouts[SINGLEBYTE_L]*1000) <= 0){
								param->res = 467;
								break;
							}
							param->statscli64+=(len - i);
							param->nwrites++;
#if SOCKSTRACE > 1
fprintf(stderr, "UDP packet relayed from client to %s:%hu size %d, header %d\n",
			inet_ntoa(param->sins.sin_addr),
			ntohs(param->sins.sin_port),
			(len - i),
			i
	);
fprintf(stderr, "client address is assumed to be %s:%hu\n",
			inet_ntoa(sin.sin_addr),
			ntohs(sin.sin_port)
	);
fflush(stderr);
#endif
						}

					}
					if (fds[0].revents) {
						sasize = sizeof(param->sinsr);
						buf[0]=buf[1]=buf[2]=0;
						buf[3]=(*SAFAMILY(&param->sinsl) == AF_INET)?1:4;
						if((len = so._recvfrom(param->remsock, (char *)buf+6+SAADDRLEN(&param->sinsl), 65535 - 10, 0, (struct sockaddr *)&param->sinsr, &sasize)) <= 0) {
							param->res = 468;
							break;
						}
						param->statssrv64+=len;
						param->nreads++;
						memcpy(buf+4, SAADDR(&param->sinsr), SAADDRLEN(&param->sinsr));
						memcpy(buf+4+SAADDRLEN(&param->sinsr), SAPORT(&param->sinsr), 2);
						sasize = sizeof(sin);
						if(socksendto(param->clisock, (struct sockaddr *)&sin, buf, len + 6 + SAADDRLEN(&param->sinsr), conf.timeouts[SINGLEBYTE_L]*1000) <=0){
							param->res = 469;
							break;
						}
#if SOCKSTRACE > 1
fprintf(stderr, "UDP packet relayed to client from %hu size %d\n",
			ntohs(*SAPORT(&param->sinsr)),
			len
	);
fflush(stderr);
#endif

					}
				}
				break;
			default:
				param->res = 417;
				break;
		}
	}
 }

 if(command > 3) command = 0;
 if(buf){
	 sprintf((char *)buf, "%s ", commands[command]);
	 if(param->hostname){
	  sprintf((char *)buf + strlen((char *)buf), "%.265s", param->hostname);
	 }
	 else
		myinet_ntop(*SAFAMILY(&param->req), SAADDR(&param->req), (char *)buf + strlen((char *)buf), 64);
         sprintf((char *)buf+strlen((char *)buf), ":%hu", ntohs(*SAPORT(&param->req)));
	 (*param->srv->logfunc)(param, buf);
	 myfree(buf);
 }
 freeparam(param);
 return (NULL);
}

#ifdef WITHMAIN
struct proxydef childdef = {
	sockschild,
	1080,
	0,
	S_SOCKS,
	""
};
#include "proxymain.c"
#endif
