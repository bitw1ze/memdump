#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/ptrace.h>
#include "memdump.h"

int procmap_init(procmap *map, pid_t pid) {
    size_t i;
    map->pid = pid;
    map->count = 0;

    for (i=0; i<MAX_RECORDS; ++i) {
        map->records[i].info[0] = '\0';
    }

    return 0;
}

int read_maps(procmap *map, FILE *ifile) {
    char map_fn[64];
    char buf[BUFLEN];
    procmap_record *it;

    // try to open /prod/<pid>/maps if file is not supplied
    if (!ifile) {
        snprintf(map_fn, sizeof(map_fn), "/proc/%d/maps", map->pid);
        ifile = fopen(map_fn, "r");
        if (!ifile) {
            return -1;
        }
    }

    // read all the records from maps and parse them
    map->count = 0;
    while (fgets(buf, sizeof(buf), ifile) && map->count < MAX_RECORDS)
    {
        it = &map->records[map->count];
        memset(it, 0, sizeof(procmap_record));
        buf[strlen(buf)-1] = 0;
        sscanf((const char *)buf, MAPI_FMT, &it->begin, &it->end, &it->read,
                &it->write, &it->exec, &it->q, &it->offset, &it->dev_major,
                &it->dev_minor, &it->inode, it->info);
        char* newline = strchr(it->info, '\n');
        if (newline)
            *newline = 0;
        memset(buf, 0, sizeof(buf));
        map->count++;
    }

    fclose(ifile);

    if (map->count == MAX_RECORDS) {
        fprintf(stderr, "[warn] max segments exceeded, not dumping any more");
    }

    return 0;
}

int write_maps(FILE *ofile, const procmap *map) {
    size_t i;
    const procmap_record *it;

    if (!ofile) {
        return -1;
    }

    for (i=0; i<map->count; ++i) {
        it = &map->records[i];
        fprintf(ofile, MAPO_FMT, it->begin, it->end, it->read, it->write,
                it->exec, it->q, it->offset, it->dev_major, it->dev_minor,
                it->inode, it->info);
    }

    return 0;
}

void * fetch_memory(pid_t pid, const void *start, size_t len) {
    // caller must make sure this does not overflow

    void *data = calloc(len, 1);
    long word = 0;
    if (!data) {
        return NULL;
    }

    size_t offset;
    errno = 0;
    for (offset=0; offset<len; offset += WORD) {
        word = ptrace(PTRACE_PEEKTEXT, pid, (void *)(start+offset), NULL);
        if (errno) {
            return NULL;
        }
        memcpy(data+offset, &word, WORD);
    }

    return data;
}

