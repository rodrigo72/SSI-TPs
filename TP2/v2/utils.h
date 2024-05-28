#include <stddef.h>

#define FIFO_PATH "/tmp/main.fifo"
#define FIFO_PERMISSIONS 0777
#define MAIL_BOX_PATH "/tmp/mail_box"


typedef enum status_type {
    SUCCESS,
    NO_CHANGES,
    ERROR
} STATUS_TYPE;


typedef enum request_type {
    NEW,
    STATUS,
    ACTIVATE,
    DEACTIVATE,
    G_CREATE,
    G_DELETE,
    G_ADD_USER,
    G_REMOVE_USER,
} REQUEST_TYPE;


typedef struct header {
    REQUEST_TYPE type;
    int pid;
} HEADER;


typedef struct header_private {
    size_t size;
    REQUEST_TYPE type;
} HEADER_PRIVATE;


typedef struct status_responce {
    STATUS_TYPE status;
} STATUS_RESPONCE;


typedef struct activate_user {
    int user_id;
    int group_id;
} ACTIVATE_USER;


typedef struct deactivate_user {
    int user_id;
} DEACTIVATE_USER;


typedef struct create_group {
    int user_id;
    char group_name[64];
} CREATE_GROUP;