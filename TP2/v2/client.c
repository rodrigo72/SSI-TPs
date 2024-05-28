#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <limits.h>

#include <pwd.h>
#include <grp.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <time.h>
#include "utils.h"

#define MAX_RETRIES 10
#define MAX_BACKOFF_TIME 100000 // in milliseconds

#define DEBUG 1


void send(int fd, void *data, REQUEST_TYPE type, size_t size) {
    HEADER_PRIVATE header_private;
    header_private.size = size;
    header_private.type = type;

    write(fd, &header_private, sizeof(HEADER_PRIVATE));
    write(fd, data, header_private.size);
}

void ativar(int fd) {
    if (DEBUG) printf(">> Ativar\n");

    ACTIVATE_USER activate_user;
    activate_user.user_id = getuid();
    activate_user.group_id = getgid();

    if (DEBUG) printf("\tUser ID: %d\n", activate_user.user_id);
    if (DEBUG) printf("\tGroup ID: %d\n", activate_user.group_id);

    send(fd, &activate_user, ACTIVATE, sizeof(ACTIVATE_USER));
}

void desativar(int fd) {
    if (DEBUG) printf(">> Desativar\n");

    DEACTIVATE_USER deactivate_user;
    deactivate_user.user_id = getuid();

    if (DEBUG) printf("\tUser ID: %d\n", deactivate_user.user_id);

    send(fd, &deactivate_user, DEACTIVATE, sizeof(DEACTIVATE_USER));
}

void criar_grupo(int fd, char *group_name) {
    if (DEBUG) printf(">> Criar grupo\n");

    CREATE_GROUP create_group;
    strncpy(create_group.group_name, group_name, sizeof(create_group.group_name) - 1);
    create_group.group_name[sizeof(create_group.group_name) - 1] = '\0'; 
    create_group.user_id = getuid();

    if (DEBUG) printf("\tGroup name: %s\n", create_group.group_name);

    send(fd, &create_group, G_CREATE, sizeof(CREATE_GROUP));
}


int main (int argc, char *argv[]) {

    if (argc < 2) {
        printf("Usage: %s <command> [arguments]\n", argv[0]);
        return 1;
    }

    uid_t uid = getuid();
    struct passwd *pw = getpwuid(uid);
    if (pw == NULL) {
        perror("getpwuid");
        return 1;
    }

    gid_t gid = getgid();
    struct group *grp = getgrgid(gid);
    if (grp == NULL) {
        perror("getgrgid");
        return 1;
    }

    if (DEBUG) {
        printf("User ID: %d\n", uid);
        printf("Username: %s\n", pw->pw_name);
        printf("User's home directory: %s\n", pw->pw_dir);
        printf("Group ID: %d\n", gid);
        printf("Group name: %s\n\n", grp->gr_name);
    }

    srand(time(NULL));

    int fd, retries = 0, backoffTime = 0;
    int bytes_read = 0;
    char buf[50];

    do {
        fd = open(FIFO_PATH, O_WRONLY, 0200);
        if (fd == -1) {
            perror("open");
            
            retries++;
            if (retries >= MAX_RETRIES) {
                if (DEBUG) printf("Failed to open file descriptor after maximum retries.\n");
                break;
            }

            backoffTime = (1 << retries) * 1000; // exponential backoff time

            int jitter = rand() % (backoffTime / 2);
            backoffTime += jitter;

            if (backoffTime > MAX_BACKOFF_TIME) {
                backoffTime = MAX_BACKOFF_TIME;
            }

            if (DEBUG) printf("Retrying after %d milliseconds.\n", backoffTime);
            usleep(backoffTime * 1000);

        }
    } while (fd == -1);

    if (fd != -1) {

        int pid = getpid();
        char *fifo_name = malloc(sizeof(char) * 64);
        sprintf(fifo_name, "/tmp/%d.fifo", pid);

        if (mkfifo(fifo_name, 0666) == -1) {
            perror("mkfifo");
            exit(EXIT_FAILURE);
        }

        HEADER header;
        header.type = NEW;
        header.pid = pid;

        write(fd, &header, sizeof(HEADER));
        if (DEBUG) printf("Sent header to main FIFO.\n");

        int private_fifo_fd = open(fifo_name, O_WRONLY);
        if (private_fifo_fd == -1) {
            perror("open");
            exit(EXIT_FAILURE);
        }

        if (DEBUG) printf("Connected to private fifo.\n");

        if (strcmp(argv[1], "ativar") == 0) {
            ativar(private_fifo_fd);
        } else if (strcmp(argv[1], "desativar") == 0) {
            desativar(private_fifo_fd);
        } else if (strcmp(argv[1], "criar-grupo") == 0) {
            if (argc < 3) {
                printf("Usage: %s criar-grupo <group_name>\n", argv[0]);
                return 1;
            }
            char *group_name = argv[2];
            criar_grupo(private_fifo_fd, group_name);
        } else {
            printf("Command not recognized.\n");
        }

        close(private_fifo_fd);
    }

    close(fd);
    exit(EXIT_SUCCESS);
}