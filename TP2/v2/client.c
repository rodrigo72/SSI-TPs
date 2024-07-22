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
#include <stdbool.h>

#include <time.h>
#include "utils.h"

#define MAX_RETRIES 10
#define MAX_BACKOFF_TIME 100000 // in milliseconds

#define DEBUG true


void send(int fd, void *data, REQUEST_TYPE type, size_t size) {
    HEADER_PRIVATE header_private;
    header_private.size = size;
    header_private.type = type;

    write(fd, &header_private, sizeof(HEADER_PRIVATE));
    write(fd, data, header_private.size);
}

void activate(int fd) {
    if (DEBUG) printf(">> Ativar\n");

    ACTIVATE_USER activate_user;
    activate_user.user_id = getuid();
    activate_user.group_id = getgid();

    if (DEBUG) printf("\tUser ID: %d\n", activate_user.user_id);
    if (DEBUG) printf("\tGroup ID: %d\n", activate_user.group_id);

    send(fd, &activate_user, ACTIVATE, sizeof(ACTIVATE_USER));
}

void deactivate(int fd) {
    if (DEBUG) printf(">> Desativar\n");

    DEACTIVATE_USER deactivate_user;
    deactivate_user.user_id = getuid();

    if (DEBUG) printf("\tUser ID: %d\n", deactivate_user.user_id);

    send(fd, &deactivate_user, DEACTIVATE, sizeof(DEACTIVATE_USER));
}

void g_create(int fd, char *group_name) {
    if (DEBUG) printf(">> Criar grupo\n");

    CREATE_GROUP create_group;
    strncpy(create_group.group_name, group_name, sizeof(create_group.group_name) - 1);
    create_group.group_name[sizeof(create_group.group_name) - 1] = '\0'; 
    create_group.user_id = getuid();

    if (DEBUG) printf("\tGroup name: %s\n", create_group.group_name);

    send(fd, &create_group, G_CREATE, sizeof(CREATE_GROUP));
}

void g_remove(int fd, int group_id) {
    if (DEBUG) printf(">> Remover grupo\n");

    REMOVE_GROUP remove_group;
    remove_group.group_id = group_id;
    remove_group.user_id = getuid();

    if (DEBUG) printf("\tGroup ID: %d\n", remove_group.group_id);

    send(fd, &remove_group, G_REMOVE, sizeof(REMOVE_GROUP));
}

void g_add_user(int fd, int group_id) {
    if (DEBUG) printf(">> Adicionar usuÃ¡rio ao grupo\n");

    ADD_USER_TO_GROUP add_user_to_group;
    add_user_to_group.group_id = group_id;
    add_user_to_group.user_id = getuid();

    if (DEBUG) printf("\tGroup ID: %d\n", add_user_to_group.group_id);

    send(fd, &add_user_to_group, G_ADD_USER, sizeof(ADD_USER_TO_GROUP));
}

void g_send(int fd, int type, int dest, char* subject, char* body) {
    
    MSG_TYPE msg_type;
    switch(type) {
        case 0: msg_type = USER; break;
        case 1: msg_type = GROUP; break;
    }

    SEND_MSG send_msg;
    send_msg.type = msg_type;
    send_msg.dest = dest;
    send_msg.from = getuid();
    strncpy(send_msg.subject, subject, sizeof(send_msg.subject) - 1);
    strncpy(send_msg.body, body, sizeof(send_msg.body) - 1);

    send(fd, &send_msg, SEND_MESSAGE, sizeof(send_msg));
}

void list_messages(int fd) {
    LIST_MSGS list_msgs;
    list_msgs.id = getuid();
    list_msgs.all = true;
    send(fd, &list_msgs, LIST_MESSAGES, sizeof(list_msgs));
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
            if (backoffTime > MAX_BACKOFF_TIME) backoffTime = MAX_BACKOFF_TIME;

            if (DEBUG) printf("Retrying after %d milliseconds.\n", backoffTime);
            usleep(backoffTime * 1000);
        }
    } while (fd == -1);

    if (fd != -1) {

        int pid = getpid();
        char *fifo_name = malloc(sizeof(char) * 64);
        sprintf(fifo_name, "/tmp/client_to_server%d.fifo", pid);

        if (mkfifo(fifo_name, FIFO_PERMISSIONS) == -1) {
            perror("mkfifo");
            free(fifo_name);
            exit(EXIT_FAILURE);
        }

        char *fifo_name2 = malloc(sizeof(char) * 64);
        sprintf(fifo_name2, "/tmp/server_to_client%d.fifo", pid);

        HEADER header;
        header.type = NEW;
        header.pid = pid;

        write(fd, &header, sizeof(HEADER));
        if (DEBUG) printf("Sent header to main FIFO.\n");

        int private_fifo_fd_w = open(fifo_name, O_WRONLY);
        if (private_fifo_fd_w == -1) {
            perror("open (1)");
            exit(EXIT_FAILURE);
        }

        if (DEBUG) printf("Connected to private fifo.\n");

        if (strcmp(argv[1], "activate") == 0) {
            activate(private_fifo_fd_w);
        } else if (strcmp(argv[1], "deactivate") == 0) {
            deactivate(private_fifo_fd_w);
        } else if (strcmp(argv[1], "g-create") == 0) {

            if (argc < 3) {
                printf("Usage: %s g-create <group_name>\n", argv[0]);
                return 1;
            }
            char *group_name = argv[2];
            g_create(private_fifo_fd_w, group_name);

        }  else if (strcmp(argv[1], "g-remove") == 0) {

            if (argc < 3) {
                printf("Usage: %s g-remove <group_id>\n", argv[0]);
                return 1;
            }
            int group_id = atoi(argv[2]);
            g_remove(private_fifo_fd_w, group_id);

        } else if (strcmp(argv[1], "g-add-user") == 0) {

            if (argc < 3) {
                printf("Usage: %s g-create <group_id>\n", argv[0]);
                return 1;
            }
            int group_id = atoi(argv[2]);
            g_add_user(private_fifo_fd_w, group_id);

        } else if (strcmp(argv[1], "send") == 0) {

            if (argc < 6) {
                printf("Usage: %s send <type> <dest> <subject> <body>\n", argv[0]);
                return 1;
            }
            int type = atoi(argv[2]);
            int dest = atoi(argv[3]);
            char *subject = argv[4];
            char *body = argv[5];
            g_send(private_fifo_fd_w, type, dest, subject, body);

        } else if (strcmp(argv[1], "list") == 0) {

            list_messages(private_fifo_fd_w);

        } else {
            printf("Command not recognized.\n");
        }

        pid = fork();
        if (pid) {
            int private_fifo_fd_r = open(fifo_name2, O_RDONLY);
            if (private_fifo_fd_r == -1) {
                perror("open (2)");
                exit(EXIT_FAILURE);
            }

            int max = 1, count = 0;
            
            int bytes_read = 0;
            HEADER_PRIVATE header_private;
            while ((bytes_read = read(private_fifo_fd_r, &header_private, sizeof(HEADER_PRIVATE))) > 0) {
                
                if (max == count) break;

                if (header_private.type == STATUS) {

                    STATUS_RESPONCE status_response;
                    bytes_read = read(private_fifo_fd_r, &status_response, header_private.size);
                    if (bytes_read == -1) break;
                    printf("\t«%s»\n", status_type_to_string(status_response.status));

                    count += 1;

                    break;
                } else if (header_private.type == LISTING_INFO) {

                    LISTING listing;
                    bytes_read = read(private_fifo_fd_r, &listing, header_private.size);
                    if (bytes_read == -1) break;

                    REQUEST_TYPE type = listing.type;
                    int quantity = listing.quantity;

                    switch(type) {
                        case SEND_MESSAGE: {
                            SEND_MSG send_msg;
                            for (int i = 0; i < quantity; i++) {
                                bytes_read = read(private_fifo_fd_r, &send_msg, sizeof(SEND_MSG));
                                if (bytes_read == -1) break;
                                printf("Subject: %s\n", send_msg.subject);
                                printf("Body: %s\n", send_msg.body);
                                printf("Type: %d\n", send_msg.type);
                                printf("Destination: %d\n", send_msg.dest);
                                printf("From: %d\n", send_msg.from);
                                printf("\n");
                            }
                            break;
                        }
                        default: {
                            break;
                        }
                    }

                    break;

                } else {
                    printf("Unkown header type\n");
                }
            }

            close(private_fifo_fd_r);
            free(fifo_name2);
        }

        close(private_fifo_fd_w);
        free(fifo_name);
    }

    close(fd);
    exit(EXIT_SUCCESS);
}