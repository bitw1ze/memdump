#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdbool.h>
#include "memdump.h"

void usage() {
    fprintf(stderr, "Usage: ./memdump [opts] <pid>\n");
    exit(1);
}

bool opt_stack = true;
bool opt_heap = true;
bool opt_all = false;

int main(int argc, const char *argv[])
{
    char *fn;
    FILE *fh;
    char buf[BUFLEN];
    procmap map;
    pid_t pid;

    if (argc != 2 || (pid = (pid_t)atoi(argv[1])) <= 0) {
        usage();
    }

    map.count = 0;
    map.pid = pid;

    if (ptrace(PTRACE_ATTACH, map.pid, NULL, NULL)) {
        perror("PTRACE_ATTACH");
        exit(errno);
    }

    size_t len = strlen(argv[1]) + strlen("/proc/") + strlen("/maps");
    fn = calloc(len+1, 1);
    if (!fn) {
        perror("calloc");
        exit(errno);
    }
    snprintf(fn, len+1, "/proc/%s/maps", argv[1]);

    fh = fopen(fn, "r");
    if (!fh) {
        printf("Failed to open %s\n", fn);
        exit(errno);
    }

    procmap_record *it, tmp;
    it = &map.records[0];

    while (fgets(buf, sizeof(buf), fh) && map.count < MAX_RECORDS)
    {
        buf[strlen(buf)-1] = 0;
        sscanf((const char *)buf, MAP_FMT, &tmp.begin, &tmp.end, &tmp.read,
                &tmp.write, &tmp.exec, &tmp.q, &tmp.offset, &tmp.dev_major,
                &tmp.dev_minor, &tmp.inode, tmp.path);
#ifdef DEBUG
        printf(MAP_FMT "\n", tmp.begin, tmp.end, tmp.read, tmp.write, tmp.exec,
                tmp.q, tmp.offset, tmp.dev_major, tmp.dev_minor, tmp.inode,
                tmp.path); 
#endif
        if (tmp.read == 'r') {
            memcpy(&map.records[map.count++], &tmp, sizeof(procmap_record));
        }
    }

    if (map.count == MAX_RECORDS) {
        fprintf(stderr, "[warn] max segments exceeded, not dumping any more");
    }

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

            size_t fnsize = atoi(ADDRLEN)*2+sizeof(ADDRSEP)+sizeof(SUFFIX)+1;
            char *fn = calloc(fnsize, 1);
            if (!fn) {
                perror("calloc");
                exit(errno);
            }
            snprintf(fn, fnsize, "%0"ADDRLEN"lx-%0"ADDRLEN"lx"SUFFIX, it->begin, it->end);
            FILE *fout = fopen(fn, "wb");
            if (!fout) {
                perror("fopen");
                exit(errno);
            }
            fwrite((const void *)data, segment_sz, 1, fout);
            free(data);
            fclose(fout);
        }
    }
    if (ptrace(PTRACE_DETACH, map.pid, NULL, NULL)) {
        perror("PTRACE_DETACH");
        exit(errno);
    }

    return 0;
}
