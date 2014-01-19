#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdbool.h>
#include <time.h>
#include "memdump.h"

void usage() {
    fprintf(stderr, 
            "Usage: ./memdump [opts] -p <pid>\n\n"
            "Options:\n"
            "   -a              dump all segments\n"
            "   -b              dump the stack\n"
            "   -c              dump the heap\n"
            "   -d <dir>        save dumps to custom directory <dir>\n"
            "   -p <pid>        pid of the process to dump\n"
            "   -h              this menu\n");
    exit(1);
}

bool opt_allsegments = false;
bool opt_heap = false;
bool opt_stack = false;
bool opt_customdir = false;
char opt_dirname[FILENAME_MAX];

int main(int argc, const char *argv[])
{
    char map_fn[64];
    FILE *map_fh;
    int c;
    char buf[BUFLEN];
    procmap map;
    pid_t pid = 0;

    opterr = 0;

    while ((c = getopt (argc, (char * const *)argv, "abcd:p:h")) != -1) {
        switch (c) {
            case 'a':
                opt_allsegments = true;
                break;
            case 'b':
                opt_stack = true;
                break;
            case 'c':
                opt_heap = true;
                break;
            case 'd':
                opt_customdir = true;
                if (strlen(optarg) >= sizeof(opt_dirname)) {
                    usage();
                }
                strncpy(opt_dirname, optarg, strlen(optarg));

                break;
            case 'p':
                pid = (pid_t)atoi(optarg);
                break;
            case 'h':
                usage();
                break;
            default:
                if (optopt == 'd' || optopt == 'p')
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                else if (isprint (optopt))
                    fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                else
                    fprintf (stderr,
                            "Unknown option character `\\x%x'.\n",
                            optopt);
                return 1;
        }
    }

    if (pid <= 0) {
        fprintf(stderr, "Must specify pid\n!");
        usage();
    }
    if (!(opt_allsegments | opt_stack | opt_heap)) {
        fprintf(stderr, "Must choose section(s) of memory to dump\n");
        usage();
    }
    if (!opt_customdir) {
        snprintf(opt_dirname, sizeof(opt_dirname), "%d-%d", (int)pid, (int)time(NULL));
    }

    if (mkdir(opt_dirname, 0755)) {
        perror("mkdir");
        exit(errno);
    }

    map.count = 0;
    map.pid = pid;

    if (ptrace(PTRACE_ATTACH, map.pid, NULL, NULL)) {
        perror("PTRACE_ATTACH");
        exit(errno);
    }

    snprintf(map_fn, sizeof(map_fn), "/proc/%d/maps", pid);
    map_fh = fopen(map_fn, "r");
    if (!map_fh) {
        printf("Failed to open %s\n", map_fn);
        exit(errno);
    }

    char *cmd = malloc(3+strlen(map_fn)+strlen(opt_dirname)+1);
    sprintf(cmd, "cp %s %s", map_fn, opt_dirname);
    if (system(cmd)) {
        perror("system");
        exit(1);
    }
    free(cmd);

    procmap_record tmp;
    while (fgets(buf, sizeof(buf), map_fh) && map.count < MAX_RECORDS)
    {
        buf[strlen(buf)-1] = 0;
        sscanf((const char *)buf, MAP_FMT, &tmp.begin, &tmp.end, &tmp.read,
                &tmp.write, &tmp.exec, &tmp.q, &tmp.offset, &tmp.dev_major,
                &tmp.dev_minor, &tmp.inode, tmp.info);
#ifdef DEBUG
        printf(MAP_FMT "\n", tmp.begin, tmp.end, tmp.read, tmp.write, tmp.exec,
                tmp.q, tmp.offset, tmp.dev_major, tmp.dev_minor, tmp.inode,
                tmp.info); 
#endif
        bool doit = false;
        if (tmp.read == 'r') {
            doit |= opt_allsegments;
            doit |= (opt_stack && !strcmp(tmp.info, "[stack]"));
            doit |= (opt_heap && !strcmp(tmp.info, "[heap]"));
            if (doit)
                memcpy(&map.records[map.count++], &tmp, sizeof(procmap_record));
        }
    }

    if (map.count == MAX_RECORDS) {
        fprintf(stderr, "[warn] max segments exceeded, not dumping any more");
    }

    procmap_record *it;
    it = &map.records[0];
    int i;

    for (i=0; i<map.count; i++) {
        it = &map.records[i];

        if (it->read == 'r') {
            long tmp, addr;
            size_t segment_sz = it->end - it->begin;
            unsigned char *data = (unsigned char *)calloc(segment_sz, 1);
            if (!data) {
                perror("calloc");
                exit(errno);
            }

            for (addr = it->begin; addr < it->end; addr += WORD) {
                errno = 0;
                tmp = ptrace(PTRACE_PEEKTEXT, map.pid, (void *)addr, NULL);
                if (errno) {
                    perror("PTRACE_PEEKTEXT");
                }
                memcpy(data, &tmp, WORD);
                data += WORD;
            }

            data -= segment_sz;

            char dump_fn[FILENAME_MAX];
            snprintf(dump_fn, sizeof(dump_fn), DUMP_FMT, opt_dirname, it->begin, it->end);
#ifdef DEBUG
            printf("Created file: %s\n", dump_fn);
#endif
            FILE *dump_fh = fopen(dump_fn, "wb");
            if (!dump_fh) {
                perror("fopen");
                exit(errno);
            }
            fwrite((const void *)data, segment_sz, 1, dump_fh);
            free(data);
            fclose(dump_fh);
        }
    }
    if (ptrace(PTRACE_DETACH, map.pid, NULL, NULL)) {
        perror("PTRACE_DETACH");
        exit(errno);
    }

    return 0;
}
