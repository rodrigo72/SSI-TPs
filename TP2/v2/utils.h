#include <stddef.h>

#define FIFO_PATH "/tmp/main.fifo"
#define FIFO_PERMISSIONS 0777
#define MAIL_BOX_PATH "/tmp/mail_box"


typedef enum status_type {
    SUCCESS,
    NO_CHANGES,
    ERROR,
    NO_PERMISSION
} STATUS_TYPE;


const char* status_type_to_string(STATUS_TYPE status) {
    switch (status) {
        case SUCCESS: return "SUCCESS";
        case NO_CHANGES: return "NO_CHANGES";
        case ERROR: return "ERROR";
        case NO_PERMISSION: return "NO_PERMISSION";
        default: return "UNKNOWN";
    }
}


typedef enum request_type {
    NEW,
    STATUS,
    ACTIVATE,
    DEACTIVATE,
    G_CREATE,
    G_REMOVE,
    G_ADD_USER,
    G_REMOVE_USER,
    SEND_MESSAGE,
    LIST_MESSAGES,
    LISTING_INFO,
} REQUEST_TYPE;


typedef enum msg_type {
    USER,
    GROUP
} MSG_TYPE;


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


typedef struct remove_group {
    int group_id;
    int user_id;
} REMOVE_GROUP;


typedef struct add_user_to_group {
    int group_id;
    int user_id;
} ADD_USER_TO_GROUP;


typedef struct send_msg {
    char subject[50];
    char body[462];
    MSG_TYPE type;
    int dest;
    int from;
} SEND_MSG;


typedef struct list_msgs {
    int id;
    bool all;
} LIST_MSGS;


typedef struct listing {
    REQUEST_TYPE type;
    int quantity;
} LISTING;