#include "proxy.h"

int megaindex_chain_hook(struct clientparam *param, int argc, unsigned char **argv) {
    struct ace *acl = NULL;
    struct chain *chains;

    acl = param->srv->acl;

	while(acl && acl->next) acl = acl->next;
	if(!acl || (acl->action && acl->action != 2)) {
		fprintf(stderr, "Chaining error: last ACL entry was not \"allow\" or \"redirect\"\n");
		return(1);
	}
	acl->action = 2;

	chains = myalloc(sizeof(struct chain));
	if(!chains){
		fprintf(stderr, "Chainig error: unable to allocate memory for chain\n");
		return(2);
	}
	memset(chains, 0, sizeof(struct chain));
	chains->weight = (unsigned)atoi((char *)argv[1]);
	if(chains->weight == 0 || chains->weight >1000) {
		fprintf(stderr, "Chaining error: bad chain weight %u\n", chains->weight);
		return(3);
	}
	if(!strcmp((char *)argv[2], "tcp"))chains->type = R_TCP;
	else if(!strcmp((char *)argv[2], "http"))chains->type = R_HTTP;
	else if(!strcmp((char *)argv[2], "connect"))chains->type = R_CONNECT;
	else if(!strcmp((char *)argv[2], "socks4"))chains->type = R_SOCKS4;
	else if(!strcmp((char *)argv[2], "socks5"))chains->type = R_SOCKS5;
	else if(!strcmp((char *)argv[2], "connect+"))chains->type = R_CONNECTP;
	else if(!strcmp((char *)argv[2], "socks4+"))chains->type = R_SOCKS4P;
	else if(!strcmp((char *)argv[2], "socks5+"))chains->type = R_SOCKS5P;
	else if(!strcmp((char *)argv[2], "socks4b"))chains->type = R_SOCKS4B;
	else if(!strcmp((char *)argv[2], "socks5b"))chains->type = R_SOCKS5B;
	else if(!strcmp((char *)argv[2], "pop3"))chains->type = R_POP3;
	else if(!strcmp((char *)argv[2], "ftp"))chains->type = R_FTP;
	else if(!strcmp((char *)argv[2], "admin"))chains->type = R_ADMIN;
	else if(!strcmp((char *)argv[2], "icq"))chains->type = R_ICQ;
	else if(!strcmp((char *)argv[2], "extip"))chains->type = R_EXTIP;
	else if(!strcmp((char *)argv[2], "smtp"))chains->type = R_SMTP;
	else {
		fprintf(stderr, "Chaining error: bad chain type (%s)\n", argv[2]);
		return(4);
	}
	if(!getip46(46, argv[3], (struct sockaddr *)&chains->addr)) return 5;
	chains->exthost = (unsigned char *)mystrdup((char *)argv[3]);
	*SAPORT(&chains->addr) = htons((unsigned short)atoi((char *)argv[4]));
	if(argc > 5) chains->extuser = (unsigned char *)mystrdup((char *)argv[5]);
	if(argc > 6) chains->extpass = (unsigned char *)mystrdup((char *)argv[6]);
    myfree(acl->chains);
    acl->chains = chains;
	return 0;
	
}
