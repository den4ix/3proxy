#include "proxy.h"

// 0        1       2       3       4       5       6
// parent 1000 socks5 89.108.118.24 1080 proxyuser proxypasswd
// app.user-ip-port
int megaindex_login(char *buf, char *argv[7])
{
    char app[32];
    char *p, *q;

    p = buf;
    if (!(q = strchr(p,'.')))
        return 0;
    *q++ = 0;
    strncpy(app, p, 31); app[31] = 0;

    if (!(p = strchr(q, '-')))
        return 0;
    *p++ = 0;
    strncpy(argv[5], q, 255); argv[5][255] = 0;

    if (!(q = strchr(p, '-')))
        return 0;
    *q++ = 0;
    strncpy(argv[3], p, 15); argv[3][15] = 0;
    strncpy(argv[4], q, 5); argv[4][5] = 0;

    if (!strcmp(argv[4], "1080"))
        strcpy(argv[2], "socks5");
    else if (!strcmp(argv[4], "8080") || !strcmp(argv[4], "81"))
        strcpy(argv[2], "http");
    else
        return 0;

    strcpy(buf, argv[5]);
    return 1;
}

int megaindex_passwd(char *buf, char *argv[7])
{
    char app[32];
    char *p;

    if (!(p = strchr(buf, '.')))
        return 0;
    *p++ = 0;
    strncpy(app, buf, 31); app[31] = 0;
    strncpy(argv[6], p, 255); argv[6][255] = 0;
    strcpy(buf, argv[6]);

    return 1;
}


pthread_mutex_t chain_mux = PTHREAD_MUTEX_INITIALIZER;
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
    /* srvparam struct is shared between all the client threads, so it's a bit hackish here */
    //pthread_mutex_lock(&chain_mux);
    //myfree(acl->chains);
    //pthread_mutex_unlock(&chain_mux);
    acl->chains = chains;
	return 0;

}
