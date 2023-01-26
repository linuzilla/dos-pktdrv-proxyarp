/*  proxyarp.c  -- */

#include <stdio.h>
#include <dos.h>
#include <conio.h>
#include <alloc.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "pktdrv.h"
#include "proxyarp.h"

/* Global Variables */

struct IPether far   *IP[256];
int                  IP_a = 0, IP_b = 0, IP_c = 0, IP_d = 0;
int                  idle_predefine = 0, idle_proxy = 0, idle_learning = 0;
char                 *logfile = NULL, *learnfile = NULL;
FILE                 *logfp;
float                timedelay = 1.0;
unsigned char        proxy_ether[6] = { '\0', '\0', '\0', '\0', '\0', '\0' };

InPkt                pktr, pkts, pkts2, pkts_auto;
unsigned int         pktrlen, learned = 0;
int                  buf_full = 0, buf_ready = 0;
unsigned long        pkt_received = 0L, pkt_dropped = 0L;
const char           *ether_arp  = "\x08\x06";
const char           *ether_ip   = "\x08\x00";
const char           *ether_rarp = "\x80\x35";
const char           broadcast[6] = { -1, -1, -1, -1, -1, -1 };

static int           allocate_memory(void);
static void          free_memory(void);
static void          errlog(const char *msg, const char *ip, const char *eth);

void interrupt far   receiver  (unsigned bp, unsigned di, unsigned si,
                                unsigned ds, unsigned es, unsigned dx,
                                unsigned cx, unsigned bx, unsigned ax);
void interrupt far   control_c (unsigned bp, unsigned di, unsigned si,
                                unsigned ds, unsigned es, unsigned dx,
                                unsigned cx, unsigned bx, unsigned ax);

char *print_ether(unsigned char *buf);
char *print_ip(unsigned char *buf);

int processing_ignore        (struct IPether far *ptr);
int processing_predefine     (struct IPether far *ptr);
int processing_proxy         (struct IPether far *ptr);
int processing_learning      (struct IPether far *ptr);
int processing_learned       (struct IPether far *ptr);
int processing_col_predefine (struct IPether far *ptr);
int processing_col_proxy     (struct IPether far *ptr);
int processing_col_learned   (struct IPether far *ptr);
int processing_reply         (struct IPether far *ptr);

int (*ArpRequestFunction[2][9])(struct IPether far *ptr) = {
    {   /*   issue    */
        processing_ignore,          /*  UNSPECIFY      */
        processing_predefine,       /*  PREDEFINED     */
        processing_proxy,           /*  PROXY          */
        processing_learning,        /*  LEARNING       */
        processing_learned,         /*  LEARNED        */
        processing_ignore,          /*  IGNORE         */
        processing_col_predefine,   /*  COL_PREDEFINE  */
        processing_col_proxy,       /*  COL_PROXY      */
        processing_col_learned      /*  COL_LEARNED    */
    },
    {   /*  reply    */
        processing_ignore,          /*  UNSPECIFY      */
        processing_ignore,          /*  PREDEFINED     */
        processing_ignore,          /*  PROXY          */
        processing_ignore,          /*  LEARNING       */
        processing_ignore,          /*  LEARNED        */
        processing_ignore,          /*  IGNORE         */
        processing_reply,           /*  COL_PREDEFINE  */
        processing_reply,           /*  COL_PROXY      */
        processing_ignore           /*  COL_LEARNED    */
    }
};

#pragma warn -parm
int processing_ignore(struct IPether far *ptr)
{
    return 1;   /* just ignore */
}
#pragma warn +parm

int processing_predefine(struct IPether far *ptr)
{
    if (farmemcmp(ptr->addr, pktr.t.arp.sea, 6) != 0) {
        if (logfp != NULL)
            errlog("Duplicate IP Address:",
              print_ip(pktr.t.arp.sip), print_ether(pktr.t.arp.sea));
        printf("Duplicate IP Address: %s\t[ %s ]\n",
              print_ip(pktr.t.arp.sip), print_ether(pktr.t.arp.sea));
        ptr->action = COL_PREDEFINE;
        processing_col_predefine(ptr);
    }
    return 1;
}

int processing_proxy(struct IPether far *ptr)
{

    if (farmemcmp(ptr->addr, pktr.t.arp.sea, 6) != 0) {
        if (logfp != NULL)
            errlog("Illegal IP Address:",
                print_ip(pktr.t.arp.sip), print_ether(pktr.t.arp.sea));
        ptr->action = COL_PROXY;
        processing_col_proxy(ptr);
    }

    return 1;
}

int processing_learning(struct IPether far *ptr)
{
    farmemcpy(ptr->addr, pktr.t.arp.sea, 6);
    ptr->action = LEARNED;
    printf("%d IP Address learned\r", ++learned);
    return 1;
}

int processing_learned(struct IPether far *ptr)
{
    if (farmemcmp(ptr->addr, pktr.t.arp.sea, 6) != 0) {
        if (logfp != NULL)
            errlog("Collision IP Address:",
                print_ip(pktr.t.arp.sip), print_ether(pktr.t.arp.sea));
        ptr->action = COL_LEARNED;
    }
    return 1;
}

int processing_col_predefine(struct IPether far *ptr)
{
    int   i;

    if (farmemcmp(ptr->addr, pktr.t.arp.sea, 6) != 0) {
        memcpy(&pkts, &pktr, pktrlen);
        farmemcpy(pkts.t.arp.sea, ptr->addr, 6);
        memcpy(&pkts2, &pkts, pktrlen);
        pkts.t.arp.op[1] = 2;
        printf("Predefined IP Address: \t%s \t[ %s ] ..... ",
                print_ip(pkts.t.arp.sip), print_ether(pkts.t.arp.sea));

        for (i = 0; i <= 5; i++) {
            delay(200);
            send_pkt(&pkts2, pktrlen);
            delay(200);
            send_pkt(&pkts, pktrlen);
            printf("%d\b", i);
        }
        printf("ok\n");
    }
    return 1;
}

int processing_col_proxy(struct IPether far *ptr)
{
    int   i;

    memcpy(&pkts, &pktr, pktrlen);
    farmemcpy(pkts.t.arp.sea, ptr->addr, 6);
    memcpy(&pkts2, &pkts, pktrlen);
    pkts.t.arp.op[1] = 2;
    printf("Proxy: IP Address: %s  \t[ %s ] ..... ",
           print_ip(pkts.t.arp.sip), print_ether(pkts.t.arp.sea));

    for (i = 0; i <= 5; i++) {
        delay(200);
        send_pkt(&pkts2, pktrlen);
        delay(200);
        send_pkt(&pkts,  pktrlen);
        printf("%d\b", i);
    }
    printf("ok\n");
    return 1;
}

int processing_col_learned(struct IPether far *ptr)
{
    if (farmemcmp(ptr->addr, pktr.t.arp.sea, 6) != 0) {
    }
    return 1;
}

int processing_reply(struct IPether far *ptr)
{
    int   i, j;

    memcpy(&pkts, &pktr, pktrlen);
    memcpy(pkts.da, broadcast, 6);
    memcpy(pkts.t.arp.tea, pktr.t.arp.sea, 10);
    memcpy(pkts.t.arp.sip, pktr.t.arp.tip, 4);
    /* farmemcpy(pkts.sa, ptr->addr, 6); */
    /* farmemcpy(pkts.sa, pkts.da, 6);   */
    farmemcpy(pkts.sa, broadcast, 6);
    farmemcpy(pkts.t.arp.sea, ptr->addr, 6);
    pkts.t.arp.op[1] = 2;
    printf("PROXY: IP Address: %s  \t[ %s ] ..... ",
           print_ip(pkts.t.arp.sip), print_ether(pkts.t.arp.sea));

    for (i = 0; i <= 9; i++) {
        delay(300);
        if ((j = send_pkt(&pkts, pktrlen)) != 0) {
            printf("%d\b", i);
        }
    }
    printf("%s\n", j ? "ok" : "error");
    return j;
}

int main(int argc, char *argv[])
{
    int                  vector, handle, learning_count = 0;
    char                 myEtherAddr[6];
    int                  version, iclass, itype, inum, rmode;
    char                 dname[20];
    struct IPether far   *ip;
    void interrupt       (*ctrl_c)();
    int                  ipc = 0, ipd = 0;
    time_t               current, last;

    if (argc > 2) {
        printf("usage: %s [config file]\n", argv[0]);
        return 1;
    }

    if ((vector = initial_pktdrv()) == 0) {
        printf("Packet Driver not found\n");
        return 2;
    }

    if (! allocate_memory()) {
        printf("%s: out of memory\n", argv[0]);
        return 3;
    }

    if (! parse_config(argv[argc-1])) {
        return 4;
    }

    if ((handle = access_type(1, 0xFFFF, 0, ether_arp, 2, (RECEIVER) receiver)) == 0) {
        printf("Packet Driver error: access_type\n");
        return 5;
    }

    if (get_address(handle, myEtherAddr, 6) == 0) {
        printf("Packet Driver error: can't get Ethernet Address\n");
        return 6;
    }

    if (driver_info(handle, &version, &iclass, &itype, &inum, dname) == 0) {
        printf("Packet Driver error: can't get driver info\n");
        return 7;
    }

    if (set_rcv_mode(handle, RCV_PROMISCUOUS) == 0) {
        printf("Packet Driver error: can't set receive mode\n");
        return 8;
    }

    if (RCV_PROMISCUOUS != get_rcv_mode(handle, &rmode)) {
        printf("Packet Driver error: can't set to promiscuous mode\n");
    }

    if (logfile != NULL) {
        if ((logfp = fopen(logfile, "w+")) == NULL) {
            printf("Warning: Cannot create log file: %s\n", logfile);
        }
    }

    ctrl_c = getvect(0x23);
    setvect(0x23, control_c);

    printf("\n%s Packet Driver (Ver 1.%02d) found at 0x%02x\n"
           "Ethernet Address is: %s", dname, version, vector,
            print_ether((unsigned char *) myEtherAddr));
    printf("\nInterface clase: %d, type: %d, number: %d, (promiscuous mode)\n\n",
           iclass, itype, inum);

    last = time(NULL);

    while (! kbhit() || getch() != 27) {
        if (buf_ready) {
            if (pktr.t.arp.op[0] == 0 && (pktr.t.arp.op[1] == 1 ||
                                          pktr.t.arp.op[1] == 2)) {
                if (pktr.t.arp.sip[0] == IP_a && pktr.t.arp.sip[1] == IP_b) {
                    ip = &IP[pktr.t.arp.sip[2]][pktr.t.arp.sip[3]];
                    ArpRequestFunction[0][ip->action](ip);
                }
                if (pktr.t.arp.tip[0] == IP_a && pktr.t.arp.tip[1] == IP_b) {
                    ip = &IP[pktr.t.arp.tip[2]][pktr.t.arp.tip[3]];
                    ArpRequestFunction[1][ip->action](ip);
                }
            }
            buf_ready = 0;
            buf_full = 0;
        } else {
            if (! idle_learning || learning_count == 0) {
                ip = &IP[ipc][ipd];
                if (((ip->action == COL_PROXY    ) && idle_proxy) ||
                    ((ip->action == COL_PREDEFINE) && idle_predefine)) {
                    memcpy(&pkts_auto, &pktr, pktrlen);
                    memcpy(pkts_auto.da, broadcast, 6);
                    memcpy(pkts_auto.sa, broadcast, 6);
                    pkts_auto.t.arp.sip[0] = (unsigned char) IP_a;
                    pkts_auto.t.arp.sip[1] = (unsigned char) IP_b;
                    pkts_auto.t.arp.sip[2] = (unsigned char) ipc;
                    pkts_auto.t.arp.sip[3] = (unsigned char) ipd;
                    farmemcpy(pkts_auto.t.arp.sea, ip->addr, 6);
                    memcpy(pkts_auto.t.arp.tea, pkts_auto.t.arp.sea, 10);
                    pkts_auto.t.arp.op[1] = 2;
                    send_pkt(&pkts_auto, pktrlen);
                    /*
                    printf("Time interval automatic proxy: %u.%u.%u.%u\n", IP_a, IP_b, ipc, ipd);
                    */
                } else {
                    if ((ip->action == LEARNING) && idle_learning && ipc && ipd) {
                        printf("Try to learning: %03u.%03u.%03u.%03u\r",
                                 IP_a, IP_b, ipc, ipd);
                        memcpy(&pkts_auto, &pktr, pktrlen);
                        memcpy(pkts_auto.da, broadcast, 6);
                        memcpy(pkts_auto.sa, myEtherAddr, 6);
                        pkts_auto.t.arp.tip[0] = (unsigned char) IP_a;
                        pkts_auto.t.arp.tip[1] = (unsigned char) IP_b;
                        pkts_auto.t.arp.tip[2] = (unsigned char) ipc;
                        pkts_auto.t.arp.tip[3] = (unsigned char) ipd;
                        pkts_auto.t.arp.sip[0] = (unsigned char) IP_a;
                        pkts_auto.t.arp.sip[1] = (unsigned char) IP_b;
                        pkts_auto.t.arp.sip[2] = (unsigned char) IP_c;
                        pkts_auto.t.arp.sip[3] = (unsigned char) IP_d;
                        memcpy(pkts_auto.t.arp.sea, myEtherAddr, 6);
                        memcpy(pkts_auto.t.arp.tea, broadcast,   6);
                        pkts_auto.t.arp.op[1] = 1;
                        send_pkt(&pkts_auto, pktrlen);
                        learning_count = 30000;
                        last = time(NULL);
                    }
                }
                if (++ipd == 256) {
                    ipd = 0;
                    ipc = (ipc+1) % 256;
                }
            } else {
                if (idle_learning) {
                    current = time(NULL);
                    if (difftime(current, last) > timedelay)
                        learning_count = 0;
                }
            }
        }
    }

    if (release_type(handle)) {
        printf("\nPacket Driver: release handle (%d)\n", handle);
    } else {
        printf("\nPacket Driver: can not release handle\n");
    }

    setvect(0x23, ctrl_c);

    if (learnfile != NULL) {
        FILE  *fp;
        int   i, j, k;

        if ((fp = fopen(learnfile, "w+")) == NULL) {
            perror("fopen");
        } else {
            for (i = 0; i < 256; i++) {
                unsigned char z;
                for (j = 0; j < 255; j++) {
                    if (IP[i][j].action == LEARNED) {
                         fprintf(fp, "140.115.%d.%d\t\t", i, j);
                         for (k = 0; k < 6; k++) {
                             z = IP[i][j].addr[k];
                             fprintf(fp, "%02X", z);
                             if (k != 5)
                                 fprintf(fp, ":");
                         }
                         fprintf(fp, "\n");
                    }
                }
            }
            fclose(fp);
            printf("\n%u IP address learned (save to %s)\n", learned, learnfile);
        }
    } else {
        printf("\n%u IP address learned\n", learned);
    }

    printf("\n%lu packets received by filter\n", pkt_received);
    printf("%lu packets dropped by kernel\n", pkt_dropped);

    if (logfp != NULL) {
        fprintf(logfp, "\n%lu packets received by filter\n", pkt_received);
        fprintf(logfp, "%lu packets dropped by kernel\n", pkt_dropped);
        fclose(logfp);
    }

    free_memory();
    return 0;
}

static int allocate_memory(void)
{
    int   i, j;

/*  printf("Memory %lu left\n", farcoreleft()); */

    for (i = 0; i < 256; i++) {
        if ((IP[i] = farcalloc(256, sizeof(struct IPether))) == NULL)
            return 0;
        for (j = 0; j < 255; j++)
            IP[i][j].action = UNSPECIFY;
    }

/*  printf("Memory %lu left\n", farcoreleft()); */
    return 1;
}

static void free_memory(void)
{
    int   i;

    for (i = 0; i < 256; i++)
        farfree(IP[i]);
}


#pragma warn -parm
void interrupt far control_c(unsigned bp, unsigned di, unsigned si,
                             unsigned ds, unsigned es, unsigned dx,
                             unsigned cx, unsigned bx, unsigned ax)
{
}

void interrupt far receiver (unsigned bp, unsigned di, unsigned si,
                             unsigned ds, unsigned es, unsigned dx,
                             unsigned cx, unsigned bx, unsigned ax)
{
    if (! ax) {                    /*   AX == 0  (request a buffer)   */
        if (! buf_full) {
            es = FP_SEG(&pktr);
            di = FP_OFF(&pktr);
            pktrlen = cx;
            buf_full = 1;
            pkt_received++;
        } else {
            es = di = 0;
            pkt_dropped++;
        }
    } else {                        /*   AX == 1  (copy completed)     */
        buf_ready = 1;
    }
}
#pragma warn +parm

char *print_ether(unsigned char *buf)
{
    static char  ether[20];
    sprintf(ether, "%02X:%02X:%02X:%02X:%02X:%02X",
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
    return ether;
}

char *print_ip(unsigned char *buf)
{
     static char  ip[16];
     sprintf(ip, "%u.%u.%u.%u", buf[0], buf[1], buf[2], buf[3]);
     return ip;
}

static void  errlog(const char *msg, const char *ip, const char *eth)
{
    fprintf(logfp, "%s\t%s\tEthernet: %s\n", msg, ip, eth);
}
