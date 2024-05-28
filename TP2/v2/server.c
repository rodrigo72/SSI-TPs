#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <limits.h>

#include <grp.h>
#include <pwd.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "utils.h"

#define DEBUG 1


void aux_create_directory(
    char* path, 
    int user_id, 
    int group_id, 
    int original_euid, 
    int original_egid
) {

    // change the effective group ID (before UID !!)
    if (setegid(group_id) == -1) {
        perror("[ativar] setegid (1)");
        return;
    }

    // change the effective user ID
    if (seteuid(user_id) == -1) {
        perror("[ativar] seteuid (1)");
        return;
    }

    // printf("current gid: %d\ngroup gid: %d\n", getegid(), group_id);

    // create the directory
    if (mkdir(path, 0777) == -1) {
        perror("[ativar] mkdir");
        return;
    }

    // // restore the original effective group ID
    if (setegid(original_egid) == -1) {
        perror("[ativar] setegid (2)");
        exit(EXIT_FAILURE);
    }

    // restore the original effective user ID
    if (seteuid(original_euid) == -1) {
        perror("[ativar] seteuid (2)");
        exit(EXIT_FAILURE);
    }
}

int aux_count_digits(int number) {
    int count = 0;
    if (number < 0) number *= -1;
    do {
        number /= 10;
        count++;
    } while (number != 0);
    return count;
}

void ativar(int user_id, int group_id) {
    if (DEBUG) printf("Activating user with id %d.\n", user_id);

    uid_t original_euid = geteuid();
    gid_t original_egid = getegid();

    char *mail_box_path = malloc(sizeof(char) * 64);
    sprintf(mail_box_path, "%s/u_%d", MAIL_BOX_PATH, user_id);

    struct stat st;
    if (stat(mail_box_path, &st) == 0 && S_ISDIR(st.st_mode)) { // directory exists
        if (DEBUG) printf("Directory '%s' already exists.\n", mail_box_path);
    } else { // command: sudo setcap cap_setuid,cap_setgid+ep my_program
        aux_create_directory(mail_box_path, user_id, group_id, original_euid, original_egid);
    }

    return;
}

void desativar(int user_id) {
    if (DEBUG) printf("Deactivating user with id %d.\n", user_id);

    char *mail_box_path = malloc(sizeof(char) * 64);
    sprintf(mail_box_path, "%s/u_%d", MAIL_BOX_PATH, user_id);

    struct stat st;
    if (stat(mail_box_path, &st) == 0 && S_ISDIR(st.st_mode)) { // directory exists
        if (DEBUG) printf("Directory '%s' exists.\n", mail_box_path);

        if (rmdir(mail_box_path) == -1) {
            perror("[desativar] rmdir");
            return;
        }
    } else {
        if (DEBUG) printf("Directory '%s' does not exist.\n", mail_box_path);
    }

    return;
}

void criar_grupo(char *group_name, gid_t *group_id, int user_id) {
    if (DEBUG) printf("Creating group with name '%s'.\n", group_name);

    char *mail_box_path = malloc(sizeof(char) * 64);
    sprintf(mail_box_path, "%s/g_%s", MAIL_BOX_PATH, group_name);

    struct stat st;
    if (stat(mail_box_path, &st) == 0 && S_ISDIR(st.st_mode)) { // directory exists
        if (DEBUG) printf("Directory '%s' already exists.\n", mail_box_path);
    } else {

        char* group_entry = malloc(sizeof(char) * (strlen(group_name) + 3 + aux_count_digits(*group_id) + 2));
        sprintf(group_entry, "%s:x:%d\n", group_name, *group_id); // x is a placeholder for the password

        int fd = open("/etc/group", O_WRONLY | O_APPEND);
        if (fd == -1) {
            perror("open");
            return;
        }

        if (write(fd, group_entry, strlen(group_entry)) == -1) {
            perror("write");
            close(fd);
            return;
        }

        close(fd);

        uid_t original_euid = geteuid();
        gid_t original_egid = getegid();
        aux_create_directory(mail_box_path, user_id, *group_id, original_euid, original_egid);
    }
}


int main (void) {

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

    unlink(FIFO_PATH);

    if (mkfifo(FIFO_PATH, FIFO_PERMISSIONS) == -1) {
        perror("mkfifo");
        exit(EXIT_FAILURE);
    }

    if (chmod(FIFO_PATH, FIFO_PERMISSIONS | S_IWOTH) == -1) {
        perror("chmod");
        exit(EXIT_FAILURE);
    }

    // FIFO (READ)
    int fd_fifo_r = open(FIFO_PATH, O_RDONLY);
    if (fd_fifo_r == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    // FIFO (WRITE)
    // assim o server não entra em loop quando não existem clientes
    int fd_fifo_w = open(FIFO_PATH, O_WRONLY);
    if (fd_fifo_w == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    gid_t group_id = 1021;
    int bytes_read = 0;

    while (1) {
        HEADER header;
        bytes_read = read(fd_fifo_r, &header, sizeof(HEADER));
        if (bytes_read == -1) {
            perror("read");
            exit(EXIT_FAILURE);
        }
        
        if (header.type == NEW) {

            if (DEBUG) printf("\nRecieved header with request type NEW.\n");

            int pid = fork();
            if (pid == 0) {
                char *fifo_name = malloc(sizeof(char) * 64);
                sprintf(fifo_name, "/tmp/%d.fifo", header.pid);

                int private_fifo_fd = open(fifo_name, O_RDONLY);
                if (private_fifo_fd == -1) {
                    perror("[private_fifo_fd] open");
                    _exit(EXIT_FAILURE);
                }

                if (DEBUG) printf("Connected to private fifo.\n");

                HEADER_PRIVATE header_private;
                while ((bytes_read = read(private_fifo_fd, &header_private, sizeof(HEADER_PRIVATE))) > 0) {
                    if (header_private.type == ACTIVATE) {

                        ACTIVATE_USER activate_user;
                        bytes_read = read(private_fifo_fd, &activate_user, header_private.size);
                        if (bytes_read == -1) break;
                        ativar(activate_user.user_id, activate_user.group_id);

                    } else if (header_private.type == DEACTIVATE) {

                        DEACTIVATE_USER deactivate_user;
                        bytes_read = read(private_fifo_fd, &deactivate_user, header_private.size);
                        if (bytes_read == -1) break;
                        desativar(deactivate_user.user_id);

                    } else if (header_private.type = G_CREATE) {

                        CREATE_GROUP create_group;
                        bytes_read = read(private_fifo_fd, &create_group, header_private.size);
                        if (bytes_read == -1) break;
                        criar_grupo(create_group.group_name, &group_id, create_group.user_id);

                    }
                } 

                close(private_fifo_fd);

                _exit(0);
            }
        }

    }

    close(fd_fifo_r);
    close(fd_fifo_w);

    if (unlink(FIFO_PATH) == -1) {
        perror("unlink");
        exit(EXIT_FAILURE);
    }

    exit(EXIT_SUCCESS);
}