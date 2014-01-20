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
#include <stdarg.h>
#include "memdump.h"

void usage() {
    fprintf(stderr, 
            "Usage: ./memdump <segment(s)> [opts] -p <pid>\n\n"
            "Options:\n"
            "   -A              dump all segments\n"
            "   -D              dump data segments\n"
            "   -S              dump the stack\n"
            "   -H              dump the heap\n"
            "   -d <dir>        save dumps to custom directory <dir>\n"
            "   -p <pid>        pid of the process to dump\n"
            "   -v              verbose\n"
            "   -h              this menu\n");
    exit(1);
}

bool opt_allsegments = false;
bool opt_data = false;
bool opt_heap = false;
bool opt_stack = false;
bool opt_customdir = false;
bool opt_verbose = false;
char opt_dirname[FILENAME_MAX];

void printv(const char *format, ...)
{
    if (opt_verbose) {
        va_list args;
        va_start(args, format);
        vfprintf(stderr, format, args);
        va_end(args);
    }
}

int main(int argc, const char *argv[], char *envp[])
{
    procmap map;
    char map_fn[64];
    char buf[BUFLEN];
    FILE *map_fh;
    int c;
    size_t i = 0;
    pid_t pid = 0;

    opterr = 0;

    while ((c = getopt (argc, (char * const *)argv, "ADSHvhd:p:")) != -1) {
        switch (c) {
            case 'A':
                opt_allsegments = true;
                break;
            case 'D':
                opt_data = true;
                break;
            case 'S':
                opt_stack = true;
                break;
            case 'H':
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
            case 'v':
                opt_verbose = true;
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
        fprintf(stderr, "Must specify pid!\n");
        usage();
    }
    if (!(opt_allsegments | opt_stack | opt_heap | opt_data)) {
        fprintf(stderr, "Must choose section(s) of memory to dump!\n");
        usage();
    }
    if (!opt_customdir) {
        snprintf(opt_dirname, sizeof(opt_dirname), "%d-%d", (int)pid, (int)time(NULL));
    }

    if (mkdir(opt_dirname, 0755)) {
        perror("mkdir");
        exit(errno);
    }
    printv("Dumping output to directory '%s'\n", opt_dirname);

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

    char *mapout_fn = malloc(strlen(opt_dirname)+1+sizeof("maps")+1);
    sprintf(mapout_fn, "%s/maps", opt_dirname);
    FILE *mapout_fh = fopen(mapout_fn, "w");
    if (!mapout_fh) {
        perror("fopen");
        exit(errno);
    }
    printv("Wrote maps to %s\n", mapout_fn);
    free(mapout_fn);

    procmap_record tmp;
    char *proc_name = NULL;
    while (fgets(buf, sizeof(buf), map_fh) && map.count < MAX_RECORDS)
    {
        fwrite(buf, strlen(buf), 1, mapout_fh);
        buf[strlen(buf)-1] = 0;
        sscanf((const char *)buf, MAP_FMT, &tmp.begin, &tmp.end, &tmp.read,
                &tmp.write, &tmp.exec, &tmp.q, &tmp.offset, &tmp.dev_major,
                &tmp.dev_minor, &tmp.inode, tmp.info);
        if (!proc_name) {
            proc_name = malloc(strlen(tmp.info)+1);
            strcpy(proc_name, tmp.info);
        }

        bool doit = false;
        if (tmp.read == 'r') {
            doit |= opt_allsegments;
            doit |= (opt_data && !strcmp(tmp.info, proc_name));
            doit |= (opt_stack && strstr(tmp.info, "[stack"));
            doit |= (opt_heap && strstr(tmp.info, "[heap"));
            if (doit) {
                memcpy(&map.records[map.count++], &tmp, sizeof(procmap_record));
                printv("To-dump: %s\n", buf);
            }
        }
    }

    fclose(mapout_fh);
    fclose(map_fh);
    free(proc_name);

    if (map.count == MAX_RECORDS) {
        fprintf(stderr, "[warn] max segments exceeded, not dumping any more");
    }

    procmap_record *it;
    it = &map.records[0];

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
            printv("Created file: %s\n", dump_fn);
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
