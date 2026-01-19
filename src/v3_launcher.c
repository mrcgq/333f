
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>

// =========================================================
// Version Definitions (Sorted by priority)
// =========================================================
typedef struct {
    const char *name;
    const char *binary;
    const char *description;
    int         priority;
} v3_version_t;

static const v3_version_t VERSIONS[] = {
    {"v5", "v3_server_v5",     "Enterprise (Full)",       1},
    {"v8", "v3_server_v8",     "Turbo (Brutal)",          2},
    {"v6", "v3_server_v6",     "Portable (Static)",       3},
    {"v9", "v3_server_v9",     "Turbo-Portable (Hybrid)", 4},
    {"v7", "v3_server_v7",     "Rescue (WSS)",            5},
    {NULL, NULL, NULL, 0}
};

static const char *SEARCH_PATHS[] = {
    "/usr/local/bin",
    "/opt/v3/bin",
    "/usr/bin",
    ".",
    NULL
};

// =========================================================
// Find Binary
// =========================================================
static char* find_binary(const char *name) {
    static char path[512];
    struct stat st;
    
    for (int i = 0; SEARCH_PATHS[i]; i++) {
        snprintf(path, sizeof(path), "%s/%s", SEARCH_PATHS[i], name);
        if (stat(path, &st) == 0 && (st.st_mode & S_IXUSR)) {
            return path;
        }
    }
    return NULL;
}

// =========================================================
// Try Start Version (With timeout)
// =========================================================
static int try_start_version(const v3_version_t *ver, char **argv) {
    char *binary_path = find_binary(ver->binary);
    if (!binary_path) {
        fprintf(stderr, "[Launcher] %s: Binary not found\n", ver->name);
        return -1;
    }
    
    printf("[Launcher] Trying %s (%s)...\n", ver->name, ver->description);
    
    pid_t pid = fork();
    
    if (pid == 0) {
        // Child process
        argv[0] = binary_path;
        execv(binary_path, argv);
        
        fprintf(stderr, "[Launcher] Failed to exec %s: %s\n", 
                ver->binary, strerror(errno));
        _exit(127);
    }
    
    if (pid < 0) {
        fprintf(stderr, "[Launcher] Fork failed: %s\n", strerror(errno));
        return -1;
    }
    
    // Wait 2s to check for immediate crash
    sleep(2);
    
    int status;
    pid_t result = waitpid(pid, &status, WNOHANG);
    
    if (result == 0) {
        // Still running
        printf("[Launcher] %s started successfully (PID: %d)\n", ver->name, pid);
        
        // Wait for child exit
        waitpid(pid, &status, 0);
        
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            return 0;
        }
        
        printf("[Launcher] %s exited with status %d\n", 
               ver->name, WEXITSTATUS(status));
        return WEXITSTATUS(status);
    }
    
    if (result == pid) {
        if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            fprintf(stderr, "[Launcher] %s crashed with signal %d", 
                    ver->name, sig);
            
            if (sig == SIGILL) {
                fprintf(stderr, " (Illegal instruction - CPU feature not available)\n");
            } else if (sig == SIGSEGV) {
                fprintf(stderr, " (Segmentation fault)\n");
            } else {
                fprintf(stderr, "\n");
            }
        } else {
            fprintf(stderr, "[Launcher] %s exited immediately with code %d\n",
                    ver->name, WEXITSTATUS(status));
        }
        return -1;
    }
    
    return -1;
}

// =========================================================
// Main
// =========================================================
int main(int argc, char **argv) {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║              v3 Auto-Fallback Launcher                        ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n\n");
    
    printf("[Launcher] Scanning available versions...\n");
    
    int available_count = 0;
    for (int i = 0; VERSIONS[i].name; i++) {
        char *path = find_binary(VERSIONS[i].binary);
        if (path) {
            printf("  ✓ %s: %s\n", VERSIONS[i].name, path);
            available_count++;
        } else {
            printf("  ✗ %s: Not found\n", VERSIONS[i].name);
        }
    }
    
    if (available_count == 0) {
        fprintf(stderr, "\n[Launcher] ERROR: No v3 versions found!\n");
        fprintf(stderr, "Please install v3 first.\n");
        return 1;
    }
    
    printf("\n[Launcher] Starting with auto-fallback...\n\n");
    
    for (int i = 0; VERSIONS[i].name; i++) {
        char *path = find_binary(VERSIONS[i].binary);
        if (!path) continue;
        
        int result = try_start_version(&VERSIONS[i], argv);
        
        if (result == 0) {
            return 0;
        }
        
        if (result > 0) {
            printf("[Launcher] %s failed, trying fallback...\n\n", 
                   VERSIONS[i].name);
        }
    }
    
    fprintf(stderr, "\n[Launcher] All versions failed!\n");
    return 1;
}



