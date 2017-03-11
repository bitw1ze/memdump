#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include "memdump.h"

typedef int (*memcallback_t)
    (
     const procmap_record *record, 
     const void *data,
     size_t sz
    );

static void parse_args(int argc, const char **argv);
static void usage();
static void sigint_handler(int dummy);
static void cleanup();
static void printv(const char *format, ...);
static int fetch_map_memory(const procmap *map, memcallback_t callback);
static int write_dumpfile(const procmap_record *record, const void *data, size_t sz);
static int write_mapsfile(const procmap *map);
static int filter_maps(const procmap *imap, procmap *omap);

static const char *blacklist[] = {"(deleted)", NULL};

bool opt_allsegments = false;
bool opt_data = false;
bool opt_heap = false;
bool opt_stack = false;
bool opt_customdir = false;
bool opt_verbose = false;
char opt_dirname[FILENAME_MAX];

pid_t target_pid;

static void usage() {
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

static void printv(const char *format, ...)
{
    if (opt_verbose) {
        va_list args;
        va_start(args, format);
        vfprintf(stderr, format, args);
        va_end(args);
    }
}

static void sigint_handler(int dummy) {
    printf("\n[-] Caught CTRL-C. Exiting!\n");
    cleanup();
}

static void cleanup() {
    if (ptrace(PTRACE_DETACH, target_pid, NULL, NULL)) {
        perror("PTRACE_DETACH");
        exit(errno);
    }
}

static void parse_args(int argc, const char **argv) {
    int c;
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
                target_pid = (pid_t)atoi(optarg);
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
                exit(1);
        }
    }

    if (target_pid <= 0) {
        fprintf(stderr, "Must specify pid!\n");
        usage();
    }

    if (!(opt_allsegments | opt_stack | opt_heap | opt_data)) {
        fprintf(stderr, "Must choose section(s) of memory to dump!\n");
        usage();
    }
    if (!opt_customdir) {
        snprintf(opt_dirname, sizeof(opt_dirname), "%d-%d",
                (int)target_pid, (int)time(NULL));
    }
}

static int filter_maps(const procmap *imap, procmap *omap) {
    bool doit;
    size_t i, j;
    
    for (i=0; i<imap->count; ++i) {
        doit = false;
        doit |= opt_allsegments;
        doit |= (opt_data && !strcmp(imap->records[i].info, imap->records[i].info));
        doit |= (opt_stack && strstr(imap->records[i].info, "[stack"));
        if (opt_heap) {
            doit |= strstr(imap->records[i].info, "[heap") || 
                    strstr(imap->records[i].info, "[anon:libc_malloc");
        }

        j = 0;
        while (doit && blacklist[j] != NULL) {
            doit &= (strstr(imap->records[i].info, blacklist[j]) == NULL);
            j++;
        }

        if (doit) {
            memcpy(&omap->records[omap->count], &imap->records[i], 
                    sizeof(procmap_record));
            omap->count++;
        }
    }
    return 0;
}

static int write_dumpfile(const procmap_record *record, const void *data, size_t sz) {
    char dump_fn[FILENAME_MAX];
    FILE *dump_fh;

    char *info = strdup(record->info);
    if (info) {
        char *c = info;
        while (*c != '\0') {
            switch (*c) {
                case ':':
                    *c = '@';
                    break;
                case '/':
                    *c = '_';
                    break;
            }
            c++;
        }
    }
    snprintf(dump_fn, sizeof(dump_fn), DUMP_FMT, 
            opt_dirname, record->begin, record->end, record->read,
            record->write, record->exec, record->shared, record->offset,
            info ? info : "");
    free(info);
    dump_fh = fopen(dump_fn, "wb");
    if (!dump_fh) {
        return -1;
    }
    if (data) {
        fwrite(data, sz, 1, dump_fh);
        fflush(dump_fh);
    }
    else {
        fprintf(stderr, "[warning] failed to read %p-%p\n",
            (void *)record->begin, (void *)record->end);
    }
    fclose(dump_fh);
    printv("[+] wrote section \"%s\" to %s\n", record->info, dump_fn);

    return 0;
}

static int write_mapsfile(const procmap *map) {
    FILE *mapout_fh;
    char *mapout_fn;

    mapout_fn = malloc(strlen(opt_dirname)+1+sizeof("maps")+1);
    sprintf(mapout_fn, "%s/maps", opt_dirname);

    mapout_fh = fopen(mapout_fn, "w");
    if (!mapout_fh) {
        perror("fopen");
        return -1;
    }

    write_maps(map, mapout_fh);
    printv("[+] wrote maps to %s\n", mapout_fn);

    free(mapout_fn);
    fclose(mapout_fh);

    return 0;
}

int fetch_map_memory(const procmap *map, memcallback_t callback) {
    size_t i;
    const procmap_record *it;
    size_t segment_size;
    void *data;

    for (i=0; i<map->count; i++) {
        it = &map->records[i];

        if (it->read == 'r' && it->end > it->begin) {
            segment_size = it->end - it->begin;
            data = fetch_memory(map->pid, (void *)it->begin, segment_size);
            callback(it, data, segment_size);
        }
    }

    return 0;
}

static int run() {
    procmap map, filtered_map;

    procmap_init(&map, target_pid);
    procmap_init(&filtered_map, target_pid);

    if (mkdir(opt_dirname, 0755)) {
        perror("mkdir");
        exit(errno);
    }

    printv("[+] writing output to directory '%s'\n", opt_dirname);

    if (read_maps(&map, NULL))
        return -1;

    if (write_mapsfile(&map))
        return -1;

    if (filter_maps(&map, &filtered_map))
        return -1;

    if (fetch_map_memory(&filtered_map, write_dumpfile)) {
        return -1;
    }

    return 0;
}

int main(int argc, const char *argv[], char *envp[])
{
    signal(SIGINT, sigint_handler);
    parse_args(argc, argv);
    
    if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL)) {
        perror("PTRACE_ATTACH");
        exit(errno);
    }

    run();
    cleanup();

    return 0;
}
