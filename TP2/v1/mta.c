#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <systemd/sd-journal.h>

#define REQUEST_PIPE "/tmp/chat_request"

int verifyUsers(unsigned int uid) {
    FILE* usersFile = fopen("users.bin", "rb");
    if (usersFile == NULL) return 1;
    else {
        char* line = NULL;
        size_t len;
        while (getline(&line, &len, usersFile) != -1) {
            if (uid == atoi(line)) {
                fclose(usersFile);
                return 0;
            }
        }
    }

    return 1;
}

void addUser(unsigned int uid) {
    FILE* usersFile = fopen("users.bin", "ab");
    fprintf(usersFile, "%u\n", uid);
    fclose(usersFile);
}

void handleRequest(char* buffer) {
    printf("Recebido: %s\n", buffer);
    uid_t uid;
    if (strstr(buffer, "User ") != NULL) {
        sscanf(buffer, "User %u", &uid);
        syslog(LOG_NOTICE, "User %u connected via <%s>", uid, buffer);
    }
    if (strcmp(buffer, "concordia-ativar") == 0) {
        if (verifyUsers(uid)) {
            syslog(LOG_NOTICE, "User %u added to service", uid);
            addUser(uid);
        }
        else printf("User %u already in system.\n", uid);
    }
}

static void createDaemon() {
    pid_t pid;

    /* Fork off the parent process */
    pid = fork();

    /* An error occurred */
    if (pid < 0) exit(EXIT_FAILURE);

    /* Success: Let the parent terminate */
    if (pid > 0) exit(EXIT_SUCCESS);

    /* On success: The child process becomes session leader */
    if (setsid() < 0) exit(EXIT_FAILURE);

    /* Catch, ignore and handle signals */
    //TODO: Implement a working signal handler */
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    /* Fork off for the second time*/
    pid = fork();

    /* An error occurred */
    if (pid < 0) exit(EXIT_FAILURE);

    /* Success: Let the parent terminate */
    if (pid > 0) exit(EXIT_SUCCESS);

    /* Set new file permissions */
    umask(0);

    /* Change the working directory to the root directory */
    /* or another appropriated directory */
    chdir("/");
 
    openlog("ssidaemon", LOG_PID, LOG_DAEMON);
    syslog(LOG_ALERT, "Daemon started");
}

int main() {
    createDaemon();
    mkfifo(REQUEST_PIPE, 0666);
    char buffer[512];

    while(1) {
        int request_fd = open(REQUEST_PIPE, O_RDONLY);
        ssize_t bytesread = read(request_fd, buffer, sizeof(buffer));
        if (bytesread > 0) {
            handleRequest(buffer);
        }
    }
    
}