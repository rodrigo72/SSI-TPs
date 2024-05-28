#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <fcntl.h>
#include <pwd.h>

#define REQUEST_PIPE "/tmp/chat_request"

char* printListOptions() {
    printf("--------- Comandos disponíveis ---------\n\n");
    printf("concordia-enviar <dest> <msg>\n");
    printf("concordia-listar [-a]\n");
    printf("concordia-ler <mid>\n");
    printf("concordia-responder <mid> <msg>\n");
    printf("concordia-remover <mid>\n");
    printf("concordia-grupo-criar <nome>\n");
    printf("concordia-grupo-remover <nome>\n");
    printf("concordia-grupo-listar\n");
    printf("concordia-grupo-destinario-adicionar <uid>\n");
    printf("concordia-grupo-destinario-remover <uid>\n");
    printf("concordia-ativar\n");
    printf("concordia-desativar\n");
    printf("Opção: ");
    char* command = NULL;
    size_t len;
    getline(&command, &len, stdin);

    return command;
}

int main(int argc, char *argv[]) {
    int request_fd;

    request_fd = open(REQUEST_PIPE, O_WRONLY);
    if (request_fd < 0) {
        perror("open");
        exit(1);
    }

    unsigned int uid = getuid();
    char buffer[512];
    sprintf(buffer, "User %u", uid);
    buffer[strlen(buffer)] = '\0'; 
    write(request_fd, buffer, strlen(buffer) + 1);
    
    while(1) {
        char* command = printListOptions(); 
        command[strlen(command) - 1] = '\0';
        printf("Comando: %s\n", command);
        write(request_fd, command, strlen(command) + 1);
    }   
}