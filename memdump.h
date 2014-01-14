#if __GNUC__
#if __x86_64__ || __ppc64__
#define ENVIRONMENT64
#else
#define ENVIRONMENT32
#endif
#endif

#ifdef ENVIRONMENT64
#define ADDRLEN "16"
#else
#define ADDRLEN "8"
#endif

#define WORD sizeof(long)
#define BUFLEN 4096
#define SUFFIX ".dump"
#define ADDRSEP "-"
#define MAP_FMT "%0"ADDRLEN"lx"ADDRSEP"%0"ADDRLEN"lx %c%c%c%c %0"ADDRLEN"llx %02x:%02x %lu %255s"
#define MAX_RECORDS 4096 

typedef struct __procmap_record {
    long begin;
    long end;
    unsigned char read;
    unsigned char write;
    unsigned char exec;
    unsigned char q;
    long long offset;
    unsigned int dev_major;
    unsigned int dev_minor;
    unsigned long inode;
    char path[256];
} procmap_record;

typedef struct __procmap {
    procmap_record records[MAX_RECORDS];
    size_t count;
    pid_t pid;
} procmap;


