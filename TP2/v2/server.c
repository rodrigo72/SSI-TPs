#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <limits.h>
#include <sys/mman.h>
#include <dirent.h>

#include <grp.h>
#include <pwd.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "utils.h"

#define DEBUG true
#define MAX_LINE_LENGTH 256
#define APP_GROUP_ID 1002
#define MAX_MESSAGES 100

static int *next_group_id;


int get_next_group_id() {
    int next_id;
    next_id = (*next_group_id)++;
    return next_id;
}

int count_files_in_directory(const char *directory_path) {
    DIR *dir;
    struct dirent *entry;
    int file_count = 0;

    dir = opendir(directory_path);
    if (dir == NULL) {
        perror("opendir");
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            file_count++;
        }
    }

    closedir(dir);
    return file_count;
}

void send_status(int fd, STATUS_TYPE type) {
    STATUS_RESPONCE status_responce;
    status_responce.status = type;

    HEADER_PRIVATE header_private;
    header_private.type = STATUS;
    header_private.size = sizeof(status_responce);

    write(fd, &header_private, sizeof(HEADER_PRIVATE));
    write(fd, &status_responce, header_private.size);
}

void aux_create_directory(
    int fd,
    char* path, 
    int user_id, 
    int group_id, 
    int permissions
) {

    uid_t original_euid = geteuid();
    gid_t original_egid = getegid();

    // change the effective group ID (before UID !)
    if (setegid(APP_GROUP_ID) == -1) {
        perror("[aux_create_directory] setegid (1)");
        send_status(fd, ERROR);
        return;
    }

    // change the effective user ID
    if (seteuid(user_id) == -1) {
        perror("[aux_create_directory] seteuid (1)");
        send_status(fd, ERROR);
        return;
    }

    // create the directory
    if (mkdir(path, permissions) == -1) {
        perror("[aux_create_directory] mkdir");
        send_status(fd, ERROR);
        return;
    }

    // restore the original effective group ID
    if (setegid(original_egid) == -1) {
        perror("[aux_create_directory] setegid (2)");
        send_status(fd, ERROR);
        exit(EXIT_FAILURE);
    }

    // restore the original effective user ID
    if (seteuid(original_euid) == -1) {
        perror("[aux_create_directory] seteuid (2)");
        send_status(fd, ERROR);
        exit(EXIT_FAILURE);
    }

    // change the permissions of the directory
    if (chown(path, -1, group_id) == 0) {
        if (DEBUG) printf("Group of directory '%s' changed successfully to '%d'.\n", path, group_id);
    } else {
        perror("chown");
        send_status(fd, ERROR);
        exit(EXIT_FAILURE);
    }

    send_status(fd, SUCCESS);
}

void aux_remove_directory(int fd, char* path, int user_id) {

    uid_t original_euid = geteuid();
    gid_t original_egid = getegid();

    // change the effective group ID (before UID !)
    if (setegid(APP_GROUP_ID) == -1) {
        perror("[aux_remove_directory] setegid (1)");
        send_status(fd, ERROR);
        return;
    }

    // change the effective user ID
    if (seteuid(user_id) == -1) {
        perror("[aux_remove_directory] seteuid (1)");
        send_status(fd, ERROR);
        return;
    }

    DIR *dir;
    struct dirent *entry;

    dir = opendir(path);
    if (dir == NULL) {
        perror("opendir");
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        char filepath[PATH_MAX];
        snprintf(filepath, PATH_MAX, "%s/%s", path, entry->d_name);
        if (unlink(filepath) != 0) {
            perror("unlink");
        }
    }

    closedir(dir);

    if (rmdir(path) == 0) {
        if (DEBUG) printf("Directory '%s' removed successfully.\n", path);
    } else {
        perror("rmdir");
    }

    // restore the original effective group ID
    if (setegid(original_egid) == -1) {
        perror("[ativar] setegid (2)");
        send_status(fd, ERROR);
        exit(EXIT_FAILURE);
    }

    // restore the original effective user ID
    if (seteuid(original_euid) == -1) {
        perror("[ativar] seteuid (2)");
        send_status(fd, ERROR);
        exit(EXIT_FAILURE);
    }

    send_status(fd, SUCCESS);
    return;
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

void ativar(int fd, int user_id, int group_id) {
    if (DEBUG) printf("Activating user with id %d.\n", user_id);

    char *mail_box_path = malloc(sizeof(char) * 64);
    sprintf(mail_box_path, "%s/u_%d", MAIL_BOX_PATH, user_id);

    struct stat st;
    if (stat(mail_box_path, &st) == 0 && S_ISDIR(st.st_mode)) { // directory exists
        if (DEBUG) printf("Directory '%s' already exists.\n", mail_box_path);
        send_status(fd, NO_CHANGES);
    } else { // command: sudo setcap cap_setuid,cap_setgid+ep my_program
        aux_create_directory(fd, mail_box_path, user_id, APP_GROUP_ID, 0700);
    }
    free(mail_box_path);
    return;
}

void desativar(int fd, int user_id) {
    if (DEBUG) printf("Deactivating user with id %d.\n", user_id);

    char *mail_box_path = malloc(sizeof(char) * 64);
    sprintf(mail_box_path, "%s/u_%d", MAIL_BOX_PATH, user_id);

    struct stat st;
    if (stat(mail_box_path, &st) == 0 && S_ISDIR(st.st_mode)) { // directory exists
        if (DEBUG) printf("Directory '%s' exists.\n", mail_box_path);
        if (rmdir(mail_box_path) == -1) {
            perror("[desativar] rmdir");
            send_status(fd, ERROR);
            return;
        }
        send_status(fd, SUCCESS);
    } else {
        if (DEBUG) printf("Directory '%s' does not exist.\n", mail_box_path);
        send_status(fd, NO_CHANGES);
    }
    return;
}

void criar_grupo(int fd_client, char *group_name, int user_id) {
    if (DEBUG) printf("Creating group with name '%s'.\n", group_name);

    int group_id = get_next_group_id();

    char *mail_box_path = malloc(sizeof(char) * 64);
    sprintf(mail_box_path, "%s/g_%d", MAIL_BOX_PATH, group_id);

    struct stat st;
    if (stat(mail_box_path, &st) == 0 && S_ISDIR(st.st_mode)) { // directory exists
        if (DEBUG) printf("Directory '%s' already exists.\n", mail_box_path);
        send_status(fd_client, NO_CHANGES);
    } else {
        char* group_entry = malloc(sizeof(char) * (strlen(group_name) + 3 + aux_count_digits(group_id) + 2));
        sprintf(group_entry, "%s:x:%d:\n", group_name, group_id); // x is a placeholder for the password

        int fd = open("/etc/group", O_WRONLY | O_APPEND);
        if (fd == -1) {
            perror("open");
            send_status(fd_client, ERROR);
            free(mail_box_path);
            free(group_entry);
            return;
        }

        if (write(fd, group_entry, strlen(group_entry)) == -1) {
            perror("write");
            close(fd);
            send_status(fd_client, ERROR);
            free(mail_box_path);
            free(group_entry);
            return;
        }

        close(fd);
        aux_create_directory(fd_client, mail_box_path, user_id, group_id, 0770);
        free(group_entry);
    }
    free(mail_box_path);
}


void remover_grupo(int fd, int group_id, int owner_id) {
    if (DEBUG) printf("Removing group with id %d.\n", group_id);

    char *mail_box_path = malloc(sizeof(char) * 64);
    sprintf(mail_box_path, "%s/g_%d", MAIL_BOX_PATH, group_id);

    struct stat file_stat;
    if (stat(mail_box_path, &file_stat) == -1) {
        perror("stat");
        send_status(fd, NO_CHANGES);
        free(mail_box_path);
        exit(EXIT_FAILURE);
    }

    if (DEBUG) printf("UID: %d\n", file_stat.st_uid);

    if ((int) file_stat.st_uid != owner_id) {
        if (DEBUG) fprintf(stderr, "User with id %d is not the owner of the group %d.\n", owner_id, group_id);
        send_status(fd, NO_PERMISSION);
        free(mail_box_path);
        return;
    }

    // remove line from the group file

    FILE *file, *tempFile;
    char line[MAX_LINE_LENGTH];
    char searchString[10];
    sprintf(searchString, ":%d:", group_id);
    
    file = fopen("/etc/group", "r");
    if (file == NULL) {
        perror("Error opening file");
        send_status(fd, ERROR);
        free(mail_box_path);
        return;
    }
    
    tempFile = fopen("temp.txt", "w");
    if (tempFile == NULL) {
        perror("Error creating temporary file");
        fclose(file);
        send_status(fd, ERROR);
        free(mail_box_path);
        return;
    }
    
    while (fgets(line, sizeof(line), file)) {
        if (strstr(line, searchString) == NULL) {
            fputs(line, tempFile);
        }
    }
    
    fclose(file);
    fclose(tempFile);
    
    if (rename("temp.txt", "/etc/group") != 0) {
        perror("Error renaming file");
        send_status(fd, ERROR);
        free(mail_box_path);
        return;
    }
    
    if (DEBUG) printf("Lines containing \"%s\" removed successfully.\n", searchString);
   
    aux_remove_directory(fd, mail_box_path, owner_id);
    free(mail_box_path);
    return;
}


void enviar_msg(int fd, SEND_MSG msg) {

    uid_t original_euid = geteuid();
    gid_t original_egid = getegid();

    int user_id, group_id;

    char *mail_box_path = malloc(sizeof(char) * 64);
    if (msg.type == USER) {
        sprintf(mail_box_path, "%s/u_%d", MAIL_BOX_PATH, msg.dest);
        user_id = msg.dest;
        group_id = APP_GROUP_ID;
    } else if (msg.type == GROUP) {
        sprintf(mail_box_path, "%s/g_%d", MAIL_BOX_PATH, msg.dest);
        user_id = original_euid; // dubious
        group_id = msg.dest;
        // TODO: adicionar uma maneira de confirmar que o user (msg.from) pertence ao grupo (msg.dest)
    } else {
        send_status(fd, ERROR);
        free(mail_box_path);
        return;
    }

    if (DEBUG) printf("group id: %d\t user id: %d\n", group_id, user_id);

    struct stat st;
    if (stat(mail_box_path, &st) == 0 && S_ISDIR(st.st_mode)) { // directory exists
        // change the effective group ID (before UID !)
        if (setegid(group_id) == -1) {
            perror("[enviar_msg] setegid (1)");
            send_status(fd, ERROR);
            free(mail_box_path);
            return;
        }

        // change the effective user ID
        if (seteuid(user_id) == -1) {
            perror("[enviar_msg] seteuid (1)");
            send_status(fd, ERROR);
            free(mail_box_path);
            return;
        }

        // create a file
        int n = count_files_in_directory(mail_box_path);
        if (n == -1) {
            send_status(fd, ERROR);
            free(mail_box_path);
            return;
        }

        char *filepath = malloc(sizeof(char) * 64);
        sprintf(filepath, "%s/%d.bin", mail_box_path, n);
        free(mail_box_path);

        FILE *file = fopen(filepath, "wb");
        if (file == NULL) {
            perror("Error opening file");
            send_status(fd, ERROR);
            free(filepath);
            return;
        }

        size_t bytes_written = fwrite(&msg, sizeof(SEND_MSG), 1, file);
        if (bytes_written != 1) {
            perror("Error writing to file");
            fclose(file);
            send_status(fd, ERROR);
            free(filepath);
            return;
        }

        if (chmod(filepath, S_IRUSR | S_IWUSR) == -1) {
            perror("Error setting file permissions");
            fclose(file);
            send_status(fd, ERROR);
            free(filepath);
            return;
        }

        fclose(file);

        if (DEBUG) printf("Struct written to file successfully.\n");

        // restore the original effective group ID
        if (setegid(original_egid) == -1) {
            perror("[enviar_msg] setegid (2)");
            send_status(fd, ERROR);
            free(filepath);
            exit(EXIT_FAILURE);
        }

        // restore the original effective user ID
        if (seteuid(original_euid) == -1) {
            perror("[enviar_msg] seteuid (2)");
            send_status(fd, ERROR);
            free(filepath);
            exit(EXIT_FAILURE);
        }

        free(filepath);
        send_status(fd, SUCCESS);

    } else {
        free(mail_box_path);
        send_status(fd, ERROR);
    }

}

int read_message(const char *filename, SEND_MSG *msg) {
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Error opening file");
        return -1; // Return -1 to indicate an error
    }

    if (fread(msg, sizeof(SEND_MSG), 1, file) != 1) {
        perror("Error reading file");
        fclose(file);
        return -1; // Return -1 to indicate an error
    }

    fclose(file);
    return 0; // Return 0 to indicate success
}

void listar_msgs(int fd, bool all, int id) {

    if (!all) {
        // TODO
    }

    char *mail_box_path = malloc(sizeof(char) * 64);
    sprintf(mail_box_path, "%s/u_%d", MAIL_BOX_PATH, id);

    uid_t original_euid = geteuid();
    gid_t original_egid = getegid();


    // change the effective group ID (before UID !)
    if (setegid(APP_GROUP_ID) == -1) {
        perror("[listar_msgs] setegid (1)");
        send_status(fd, ERROR);
        return;
    }

    // change the effective user ID
    if (seteuid(id) == -1) {
        perror("[listar_msgs] seteuid (1)");
        send_status(fd, ERROR);
        free(mail_box_path);
        return;
    }

    // get messages

    DIR *dir = opendir(mail_box_path);
    if (dir == NULL) {
        perror("Error opening directory");
        send_status(fd, ERROR);
        free(mail_box_path);
        return;
    }
    
    int i = 0;
    SEND_MSG messages_arr[MAX_MESSAGES];
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG && strstr(entry->d_name, ".bin") != NULL) {
            char filepath[256];
            snprintf(filepath, sizeof(filepath), "%s/%s", mail_box_path, entry->d_name);
            SEND_MSG msg;
            int result = read_message(filepath, &msg);
            if (result == -1) {
                send_status(fd, ERROR);
                return;
            }
            messages_arr[i] = msg;
            i += 1;
        }
    }

    closedir(dir);

    // restore the original effective group ID
    if (setegid(original_egid) == -1) {
        perror("[listar_msgs] setegid (2)");
        send_status(fd, ERROR);
        free(mail_box_path);
        exit(EXIT_FAILURE);
    }

    // restore the original effective user ID
    if (seteuid(original_euid) == -1) {
        perror("[listar_msgs] seteuid (2)");
        send_status(fd, ERROR);
        free(mail_box_path);
        exit(EXIT_FAILURE);
    }

    // send listing message

    LISTING listing;
    listing.type = SEND_MESSAGE;
    listing.quantity = i;

    HEADER_PRIVATE header_private;
    header_private.type = LISTING_INFO;
    header_private.size = sizeof(listing);

    write(fd, &header_private, sizeof(HEADER_PRIVATE));
    write(fd, &listing, header_private.size);

    for (int j = 0; j < i; j++) {
        SEND_MSG msg = messages_arr[j];
        write(fd, &msg, sizeof(msg));
    }

    free(mail_box_path);
}


int main (void) {

    next_group_id = mmap(NULL, sizeof *next_group_id, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (next_group_id == MAP_FAILED) {
        perror("Failed to create shared memory");
        exit(EXIT_FAILURE);
    }
    *next_group_id = 1021;

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
        perror("open (1)");
        exit(EXIT_FAILURE);
    }

    // FIFO (WRITE)
    // assim o server não entra em loop quando não existem clientes
    int fd_fifo_w = open(FIFO_PATH, O_WRONLY);
    if (fd_fifo_w == -1) {
        perror("open (2)");
        exit(EXIT_FAILURE);
    }

    int bytes_read = 0;

    // Listen to new clients
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
                // Private client to server FIFO
                char *fifo_name_1 = malloc(sizeof(char) * 64);
                sprintf(fifo_name_1, "/tmp/client_to_server%d.fifo", header.pid);

                // Private server to client FIFO
                char *fifo_name_2 = malloc(sizeof(char) * 64);
                sprintf(fifo_name_2, "/tmp/server_to_client%d.fifo", header.pid);

                if (mkfifo(fifo_name_2, FIFO_PERMISSIONS) == -1) {
                    perror("mkfifo");
                    free(fifo_name_2);
                    exit(EXIT_FAILURE);
                }

                int private_fifo_fd_r = open(fifo_name_1, O_RDONLY);
                if (private_fifo_fd_r == -1) {
                    perror("[private_fifo_fd] open (1)");
                    free(fifo_name_1);
                    _exit(EXIT_FAILURE);
                }
                free(fifo_name_1);

                if (DEBUG) printf("Connected to private fifo (1).\n");

                int private_fifo_fd_w = open(fifo_name_2, O_WRONLY);
                if (private_fifo_fd_w == -1) {
                    perror("[private_fifo_fd] open (2)");
                    free(fifo_name_2);
                    _exit(EXIT_FAILURE);
                }
                free(fifo_name_2);

                if (DEBUG) printf("Connected to private fifo (2).\n");

                // Listen to client
                HEADER_PRIVATE header_private;
                while ((bytes_read = read(private_fifo_fd_r, &header_private, sizeof(HEADER_PRIVATE))) > 0) {
                    if (header_private.type == ACTIVATE) {

                        ACTIVATE_USER activate_user;
                        bytes_read = read(private_fifo_fd_r, &activate_user, header_private.size);
                        if (bytes_read == -1) break;
                        ativar(private_fifo_fd_w, activate_user.user_id, activate_user.group_id);

                    } else if (header_private.type == DEACTIVATE) {

                        DEACTIVATE_USER deactivate_user;
                        bytes_read = read(private_fifo_fd_r, &deactivate_user, header_private.size);
                        if (bytes_read == -1) break;
                        desativar(private_fifo_fd_w, deactivate_user.user_id);

                    } else if (header_private.type == G_CREATE) {

                        CREATE_GROUP create_group;
                        bytes_read = read(private_fifo_fd_r, &create_group, header_private.size);
                        if (bytes_read == -1) break;
                        criar_grupo(private_fifo_fd_w, create_group.group_name, create_group.user_id);

                    } else if (header_private.type == G_REMOVE) {

                        REMOVE_GROUP remove_group;
                        bytes_read = read(private_fifo_fd_r, &remove_group, header_private.size);
                        if (bytes_read == -1) break;
                        remover_grupo(private_fifo_fd_w, remove_group.group_id, remove_group.user_id);
    
                    } else if (header_private.type == SEND_MESSAGE) {

                        SEND_MSG send_msg;
                        bytes_read = read(private_fifo_fd_r, &send_msg, header_private.size);
                        if (bytes_read == -1) break;
                        enviar_msg(private_fifo_fd_w, send_msg);

                    } else if (header_private.type == LIST_MESSAGES) {

                        LIST_MSGS list_msgs;
                        bytes_read = read(private_fifo_fd_r, &list_msgs, header_private.size);
                        if (bytes_read == -1) break;
                        listar_msgs(private_fifo_fd_w, list_msgs.all, list_msgs.id);

                    }
                } 

                close(private_fifo_fd_r);
                close(private_fifo_fd_w);
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