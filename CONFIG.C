#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "proxyarp.h"

static int  analyzing(const char *buffer);
static int  analyz_ip(const char *buffer);
static int  analyz_net(const char *buffer);
static int  read_predefine(const char *fname);
static int  count_range(const char *buffer, int *from, int *to);

int parse_config(const char *confile)
{
    FILE   *fp;
    char   *cfile = strdup(confile);
    char   buffer[256], *ptr;
    strlwr(cfile);

    if (strcmp(&cfile[strlen(cfile)-4], ".exe") == 0)
        memcpy(&cfile[strlen(cfile)-4], ".cfg", 4);

    if ((fp = fopen(cfile, "r")) == NULL) {
        printf("Can not reading configure file %s\n", cfile);
        free(cfile);
        return 0;
    }
    printf("Reading configure file: %s\n", cfile);

    while (fgets(buffer, 255, fp) != NULL) {
        if ((ptr = strchr(buffer, '\n')) != NULL)
            *ptr = '\0';
        if ((ptr = strchr(buffer, '\r')) != NULL)
            *ptr = '\0';
        if (! analyzing(buffer)) {
            printf("Syntax error: %s\n", buffer);
            return 0;
        }
    }
    fclose(fp);
    free(cfile);
    return 1;
}

#define NUM_OF_KEYWORD  (9)

static char *keyword[] = {
    "net=",
    "log=",
    "predefine=",
    "learn=",
    "proxy=",
    "net.",
    "idle=",
    "myip=net.",
    "timedelay="
};

static int analyzing(const char *buffer)
{
    int   i, j, found;
    char  *ptr;
    char  buf[256];
    int   e[6];

    for (i = j = 0; i < strlen(buffer); i++) {
        if (buffer[i] != ' ' && buffer[i] != '\t') {
            buf[j++] = buffer[i];
        }
    }
    buf[j] = '\0';
    if ((ptr = strchr(buf, ';')) != NULL)
        *ptr = '\0';

    strlwr(buf);

    if (strlen(buf) == 0)
        return 1;

    for (i = found = 0; i < NUM_OF_KEYWORD; i++) {
        if (strncmp(keyword[i], buf, strlen(keyword[i])) == 0) {
            found = 1;
            break;
        }
    }
    if (! found)
        return 0;

    ptr = &buf[strlen(keyword[i])];

    switch (i) {
    case  0:    /* net       */
        sscanf(ptr, "%d.%d", &IP_a, &IP_b);
        printf("Net = %d.%d.x.x\n", IP_a, IP_b);
        break;
    case  1:    /* log       */
        logfile = strdup(ptr);
        printf("Logfile = %s\n", logfile);
        break;
    case  2:    /* predefine */
        printf("Reading IP Address predefinition from %s\n", ptr);
        read_predefine(ptr);
        break;
    case  3:    /* learn     */
        learnfile = strdup(ptr);
        printf("Learning to file = %s\n", learnfile);
        break;
    case  4:    /* proxy     */
        sscanf(ptr, "%x:%x:%x:%x:%x:%x",
               &e[0], &e[1], &e[2], &e[3], &e[4], &e[5]);
        for (i = 0; i < 6; i++)
            proxy_ether[i] = (unsigned char) e[i];
        printf("PROXY Ethernet Address = %02X:%02X:%02X:%02X:%02X:%02X\n",
            e[0], e[1], e[2], e[3], e[4], e[5]);
        break;
    case  5:    /* net.      */
        if (! analyz_net(ptr))
            return 0;
        break;
    case  6:    /*  idle     */
        if (strcmp(ptr, "predefine") == 0) {
            idle_predefine = 1;
        } else {
            if (strcmp(ptr, "proxy") == 0) {
                idle_proxy = 1;
            } else {
                if (strcmp(ptr, "learning") == 0) {
                    idle_learning = 1;
                } else {
                    return 0;
                }
            }
        }
        break;
    case  7:    /*  myip   */
        sscanf(ptr, "%d.%d", &IP_c, &IP_d);
        printf("IP Address = %d.%d.%d.%d\n", IP_a, IP_b, IP_c, IP_d);
        break;
    case  8:    /*  timedelay  */
        sscanf(ptr, "%f", &timedelay);
        printf("Set time-delay to %04.2f second(s)\n", timedelay);
        break;
    }

    return 1;
}

static int  read_predefine(const char *fname)
{
    FILE   *fp;
    char   *ptr;
    char   buffer[256];

    if ((fp = fopen(fname, "r")) == NULL) {
        printf("\nWarning! %c file \"%s\" not found!\n", '\007', fname);
        return 0;
    }

    while (fgets(buffer, 255, fp) != NULL) {
        if ((ptr = strchr(buffer, '\n')) != NULL)
            *ptr = '\0';
        if ((ptr = strchr(buffer, '\r')) != NULL)
            *ptr = '\0';
        if (! analyz_ip(buffer)) {
            printf("Syntax error: %s\n", buffer);
            return 0;
        }
    }

    fclose(fp);
    return 1;
}

static int analyz_ip(const char *buffer)
{
    struct IPether far    *ptr;
    unsigned char         eth[6];
    unsigned int          ip_a, ip_b, ip_c, ip_d, e[6];
    int                   i;

    if (buffer[0] != '\0' && buffer[0] != ';' && buffer[0] != '#') {
        sscanf(buffer, "%d.%d.%d.%d %x:%x:%x:%x:%x:%x",
               &ip_a, &ip_b, &ip_c, &ip_d,
               &e[0], &e[1], &e[2], &e[3], &e[4], &e[5]);

        for (i = 0; i < 6; i++)
            eth[i] = (unsigned char) e[i];

        if ((ip_a == IP_a) && (ip_b == IP_b) && (ip_c < 255) && (ip_d < 255)) {
            ptr = &IP[ip_c][ip_d];
            if (ptr->action == PREDEFINED) {
                if (farmemcmp(ptr->addr, eth, 6) != 0) {
                    printf("Redefine IP address: %d.%d.%d.%d (ignore)\n",
                           ip_a, ip_b, ip_c, ip_d);
                    return 1;
                }
                printf("Multiple defined IP address: %d.%d.%d.%d\n",
                       ip_a, ip_b, ip_c, ip_d);
            } else {
                farmemcpy(ptr->addr, eth, 6);
                ptr->action = PREDEFINED;
            }
        } else {
            printf("Warning: %s\n", buffer);
        }
/*
        printf("%d.%d.%d.%d -> %02X:%02X:%02X:%02X:%02X:%02X\n",
               ip_a, ip_b, ip_c, ip_d, e0, e1, e2, e3, e4, e5);
*/
    }
    return 1;
}

const char *tag[] = { "learn", "ignore", "proxy" };

static int analyz_net(const char *buffer)
{
    int                   i, j, k, found;
    char                  ptr1[256];
    char                  *ptr2, *ptr3;
    int                   from1, from2, to1, to2;
    struct IPether far    *ptr;

    strcpy(ptr1, buffer);

    if ((ptr2 = strchr(ptr1, '.')) == NULL)
        return 0;
    if ((ptr3 = strchr(ptr2, '=')) == NULL)
        return 0;

    *ptr2 = *ptr3 = '\0'; ptr2++; ptr3++;

    if (! count_range(ptr1, &from1, &to1))
        return 0;

    if (! count_range(ptr2, &from2, &to2))
        return 0;

    for (k = found = 0; k < 3; k++) {
        if (strcmp(ptr3, tag[k]) == 0) {
            found = 1;
            break;
        }
    }
    if (! found)
        return 0;

    for (i = from1; i <= to1; i++) {
        for (j = from2; j <= to2; j++) {
            ptr = &IP[i][j];
            if (ptr->action == UNSPECIFY) {
                switch (k) {
                case 0: /* learn  */
                    ptr->action = LEARNING;
                    break;
                case 1: /* ignore */
                    ptr->action = IGNORE;
                    break;
                case 2: /* proxy  */
                    ptr->action = PROXY;
                    farmemcpy(ptr->addr, proxy_ether, 6);
                    break;
                }
            }
        }
    }
    printf("IP Address: %d.%d.[%d-%d].[%d-%d] (%s)\n", IP_a, IP_b,
            from1, to1, from2, to2, tag[k]);
    return 1;
}

static int count_range(const char *buffer, int *from, int *to)
{
    int   f, t;
    char  buf[20];

    buf[0] = '\0';

    if (buffer[0] >= '0' && buffer[0] <= '9') {
        sscanf(buffer, "%d", &f);
        if ((t = f) >= 0 && (t <= 255)) {
            sprintf(buf, "%d", f);
        }
    } else {
        if (buffer[0] == '[') {
            sscanf(buffer, "[%d-%d]", &f, &t);
            if ((t >= 0) && (t <= 255) &&
                (f >= 0) && (f <= 255) &&
                (t >= f)) {
                sprintf(buf, "[%d-%d]", f, t);
            }
        } else {
            if (buffer[0] == '*') {
                strcpy(buf, "*");
                f = 0;
                t = 255;
            }
        }
    }

    if (strcmp(buf, buffer) != 0)
        return 0;

    *from = f;
    *to   = t;
    return 1;
}
