#ifndef __PROXY_ARP_H_
#define __PROXY_ARP_H_

#include "pktdrv.h"

#define  UNSPECIFY      (0)     /* Unspecify (ignore) */
#define  PREDEFINED     (1)     /* Predefine Ethernet Address */
#define  PROXY          (2)     /* Predefine PROXY */
#define  LEARNING       (3)     /* Ready to Learning Ethernet Address */
#define  LEARNED        (4)     /* Learned Ethernet Address : will be saved */
#define  IGNORE         (5)     /* Ignore: Don't Care */
#define  COL_PREDEFINE  (6)     /* Predefine Ethernet Address with Collision */
#define  COL_PROXY      (7)     /* Predefine PROXY with Collision */
#define  COL_LEARNED    (8)     /* Learned with Collision */

struct IPether {
    char  action;
    char  addr[6];
};


int  parse_config(const char *confile);

extern struct IPether far     *IP[];
extern int                    IP_a, IP_b, IP_c, IP_d;
extern char                   *logfile, *learnfile;
extern unsigned char          proxy_ether[6];
extern int                    idle_predefine, idle_proxy, idle_learning;
extern float                  timedelay;

#endif
