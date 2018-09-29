#include <stdio.h>
#include <string.h>
#include <my_global.h>
#include <mysql/plugin.h>
#include <mysql/plugin_audit.h>
#include <sql_plugin.h>
#include "htp_audit.h"
#include <list>
#include <ctype.h>
#include <string>
#include "config.h"
#include "log.h"


/* filter to string */
#define RULE_ITEM_BUFFER_LEN (32 * 1024)
#define RULES2STR_BUFFER_LEN (32 * 1024)

struct rules2str_buffer_struct
{
    char *buffer;         //buffer指针
    char buffer_inner[RULES2STR_BUFFER_LEN];   //初始缓冲区
    int buffer_size;      //buffer的长度
    int occupied_bytes;   //使用的字节数
};
typedef struct rules2str_buffer_struct rules2str_buffer_t;

static int rules2str_buffer_init(rules2str_buffer_t *buffer)
{
    buffer->buffer = buffer->buffer_inner;
    buffer->buffer_size = RULES2STR_BUFFER_LEN;
    buffer->buffer[0] = 0;
    buffer->occupied_bytes = 0;
    return 0;
}

static void rules2str_buffer_deinit(rules2str_buffer_t *buffer)
{
    if (buffer->buffer != buffer->buffer_inner)
        free(buffer->buffer);
}

static int rules2str_buffer_reset(rules2str_buffer_t *buffer)
{
    if (buffer->buffer != buffer->buffer_inner)
        free(buffer->buffer);
    rules2str_buffer_init(buffer);
    return 0;
}

const char *general_events[] = {
        CTRIP_AUDIT_EVENT_GENERAL_SUB_LOG
        , CTRIP_AUDIT_EVENT_GENERAL_SUB_ERROR
        , CTRIP_AUDIT_EVENT_GENERAL_SUB_RESULT
        , CTRIP_AUDIT_EVENT_GENERAL_SUB_STATUS
};

const char *connection_events[] = {
        CTRIP_AUDIT_EVENT_CONNECTION_SUB_CONNECT
        , CTRIP_AUDIT_EVENT_CONNECTION_SUB_DISCONNECT
        , CTRIP_AUDIT_EVENT_CONNECTION_SUB_CHANGE_USER
};

static void
ctrip_audit_rule_2_str(
        filter_item_t *item, char *buffer, int size)
{
    char *buffer_index = buffer;

    //name
    strcpy(buffer_index, CTRIP_AUDIT_RULE_KEY_NAME);
    buffer_index += strlen(CTRIP_AUDIT_RULE_KEY_NAME);
    strcpy(buffer_index, "=");
    buffer_index += 1;
    strcpy(buffer_index, item->name);
    buffer_index += strlen(item->name);
    //host
    if (item->host_length != 0)
    {
        strcpy(buffer_index, "\n");
        buffer_index += 1;
        strcpy(buffer_index, CTRIP_AUDIT_RULE_KEY_HOST);
        buffer_index += strlen(CTRIP_AUDIT_RULE_KEY_HOST);
        strcpy(buffer_index, "=");
        buffer_index += 1;
        strcpy(buffer_index, item->host);
        buffer_index += item->host_length;
    }
    //user
    if (item->user_length != 0)
    {
        strcpy(buffer_index, "\n");
        buffer_index += 1;
        strcpy(buffer_index, CTRIP_AUDIT_RULE_KEY_USER);
        buffer_index += strlen(CTRIP_AUDIT_RULE_KEY_USER);
        strcpy(buffer_index, "=");
        buffer_index += 1;
        strcpy(buffer_index, item->user);
        buffer_index += item->user_length;
    }
    //event
    strcpy(buffer_index, "\n");
    buffer_index += 1;
    if (item->audit_all_event == true)
    {
        //all event setted
        const char *audit_all = "event=all";
        strcpy(buffer_index, audit_all);
        buffer_index += strlen(audit_all);
    }
    else
    {
        const char *event_head = "event=";
        strcpy(buffer_index, event_head);
        buffer_index += strlen(event_head);
        bool need_semicolon = false;

        //general event
        if (item->audit_all_general)
        {
            const char *all_general = CTRIP_AUDIT_EVENT_GENERAL_CLASS;
            strcpy(buffer_index, all_general);
            buffer_index += strlen(all_general);
            need_semicolon = true;
        }
        else
        {
            for (int i = 0; i < MAX_FILTER_GENERAL_EVENTS; i++)
            {
                if (item->general_events[i] == EVENT_SETTED)
                {
                    if (need_semicolon)
                    {
                        strcpy(buffer_index, ";");
                        buffer_index++;
                    }
                    strcpy(buffer_index, CTRIP_AUDIT_EVENT_GENERAL_CLASS);
                    buffer_index += strlen(CTRIP_AUDIT_EVENT_GENERAL_CLASS);
                    strcpy(buffer_index, ":");
                    buffer_index++;
                    strcpy(buffer_index, general_events[i]);
                    buffer_index += strlen(general_events[i]);
                    need_semicolon = true;
                }
            }
        }

        //connection event
        if (item->audit_all_connection)
        {
            if (need_semicolon)
            {
                strcpy(buffer_index, ";");
                buffer_index++;
            }

            const char *all_connection = CTRIP_AUDIT_EVENT_CONNECTION_CLASS;
            strcpy(buffer_index, all_connection);
            buffer_index += strlen(all_connection);
            need_semicolon = true;
        }
        else
        {
            for (int i = 0; i < MAX_FILTER_CONNECTION_EVENTS; i++)
            {
                if (item->connection_events[i] == EVENT_SETTED)
                {
                    if (need_semicolon)
                    {
                        strcpy(buffer_index, ";");
                        buffer_index++;
                    }
                    strcpy(buffer_index, CTRIP_AUDIT_EVENT_CONNECTION_CLASS);
                    buffer_index += strlen(CTRIP_AUDIT_EVENT_CONNECTION_CLASS);
                    strcpy(buffer_index, ":");
                    buffer_index++;
                    strcpy(buffer_index, connection_events[i]);
                    buffer_index += strlen(connection_events[i]);
                    need_semicolon = true;
                }
            }
        }
    }
    //command
    if (item->command_length != 0)
    {
        strcpy(buffer_index, "\n");
        buffer_index += 1;
        strcpy(buffer_index, CTRIP_AUDIT_RULE_KEY_CMD);
        buffer_index += strlen(CTRIP_AUDIT_RULE_KEY_CMD);
        strcpy(buffer_index, "=");
        buffer_index += 1;
        strcpy(buffer_index, item->command);
        buffer_index += item->command_length;
    }
    //sql_command
    if (item->sql_command_length != 0)
    {
        strcpy(buffer_index, "\n");
        buffer_index += 1;
        strcpy(buffer_index, CTRIP_AUDIT_RULE_KEY_SQL_CMD);
        buffer_index += strlen(CTRIP_AUDIT_RULE_KEY_SQL_CMD);
        strcpy(buffer_index, "=");
        buffer_index += 1;
        strcpy(buffer_index, item->sql_command);
        buffer_index += item->sql_command_length;
    }
    //sql_keyword
    if (item->sql_keyword_length != 0)
    {
        strcpy(buffer_index, "\n");
        buffer_index += 1;
        strcpy(buffer_index, CTRIP_AUDIT_RULE_KEY_SQL_KEYWORD);
        buffer_index += strlen(CTRIP_AUDIT_RULE_KEY_SQL_KEYWORD);
        strcpy(buffer_index, "=");
        buffer_index += 1;
        strcpy(buffer_index, item->sql_keyword);
        buffer_index += item->sql_keyword_length;
    }
    strcpy(buffer_index, "\n");
    buffer_index += 1;
}

static void rules2str_buffer_write(
        const char *rule, rules2str_buffer_t *buffer)
{
    int len = strlen(rule);
    if ((buffer->occupied_bytes + len) >= buffer->buffer_size)
    {
        //TODO:重新分配空间
    }
    char *start = buffer->buffer + buffer->occupied_bytes;
    strcpy(start, rule);
    buffer->occupied_bytes += len;
}

static void ctrip_audit_rules_2_str(rules2str_buffer_t *buffer)
{
    char temp_rule_buffer[RULE_ITEM_BUFFER_LEN];

    rules2str_buffer_reset(buffer);
    list<int>::iterator it;
    filter_item_t *item;
    for (it = filters.begin(); it != filters.end(); it++)
    {
        int pos = *it;
        item = filter_items + pos;
        ctrip_audit_rule_2_str(item, temp_rule_buffer, sizeof(temp_rule_buffer));
        rules2str_buffer_write(temp_rule_buffer, buffer);
    }
}

/* 状态 */
/*传入插件的事件统计*/
/* status variables */
static volatile int64_t number_of_calls; /* for SHOW STATUS, see below */
/* Count MYSQL_AUDIT_GENERAL_CLASS event instances */
/*static volatile int64_t number_of_calls_general_log;
static volatile int64_t number_of_calls_general_error;
static volatile int64_t number_of_calls_general_result;
static volatile int64_t number_of_calls_general_status;*/
/* Count MYSQL_AUDIT_CONNECTION_CLASS event instances */
/*static volatile int64_t number_of_calls_connection_connect;
static volatile int64_t number_of_calls_connection_disconnect;
static volatile int64_t number_of_calls_connection_change_user;*/

/*被审计的事件统计*/
static volatile int64_t number_of_records; /* for SHOW STATUS, see below */
/* Count MYSQL_AUDIT_GENERAL_CLASS event instances */
static volatile int64_t number_of_records_general_log;
static volatile int64_t number_of_records_general_error;
static volatile int64_t number_of_records_general_result;
static volatile int64_t number_of_records_general_status;
/* Count MYSQL_AUDIT_CONNECTION_CLASS event instances */
static volatile int64_t number_of_records_connection_connect;
static volatile int64_t number_of_records_connection_disconnect;
static volatile int64_t number_of_records_connection_change_user;

#define CTRIP_AUDIT_VAR(x) static volatile int number_of_calls_ ## x;
/* Count MYSQL_AUDIT_GENERAL_CLASS event instances */
CTRIP_AUDIT_VAR(general_log)
CTRIP_AUDIT_VAR(general_error)
CTRIP_AUDIT_VAR(general_result)
CTRIP_AUDIT_VAR(general_status)

/* Count MYSQL_AUDIT_CONNECTION_CLASS event instances */
CTRIP_AUDIT_VAR(connection_connect)
CTRIP_AUDIT_VAR(connection_disconnect)
CTRIP_AUDIT_VAR(connection_change_user)
CTRIP_AUDIT_VAR(connection_pre_authenticate)

/* Count MYSQL_AUDIT_PARSE_CLASS event instances */
CTRIP_AUDIT_VAR(parse_preparse)
CTRIP_AUDIT_VAR(parse_postparse)

/* Count MYSQL_AUDIT_COMMAND_CLASS event instances */
CTRIP_AUDIT_VAR(command_start)
CTRIP_AUDIT_VAR(command_end)

/* Count MYSQL_AUDIT_AUTHORIZATION_CLASS event instances */
CTRIP_AUDIT_VAR(authorization_user)
CTRIP_AUDIT_VAR(authorization_db)
CTRIP_AUDIT_VAR(authorization_table)
CTRIP_AUDIT_VAR(authorization_column)
CTRIP_AUDIT_VAR(authorization_procedure)
CTRIP_AUDIT_VAR(authorization_proxy)

/* Count MYSQL_AUDIT_QUERY_CLASS event instances */
CTRIP_AUDIT_VAR(query_start)
CTRIP_AUDIT_VAR(query_nested_start)
CTRIP_AUDIT_VAR(query_status_end)
CTRIP_AUDIT_VAR(query_nested_status_end)

/* Count MYSQL_AUDIT_SERVER_STARTUP_CLASS event instances */
CTRIP_AUDIT_VAR(server_startup)

/* Count MYSQL_AUDIT_SERVER_SHUTDOWN_CLASS event instances */
CTRIP_AUDIT_VAR(server_shutdown)

/* Count MYSQL_AUDIT_TABLE_ACCESS_CLASS event instances */
CTRIP_AUDIT_VAR(table_access_insert)
CTRIP_AUDIT_VAR(table_access_delete)
CTRIP_AUDIT_VAR(table_access_update)
CTRIP_AUDIT_VAR(table_access_read)

/* Count MYSQL_AUDIT_GLOBAL_VARIABLE_CLASS event instances */
CTRIP_AUDIT_VAR(global_variable_get)
CTRIP_AUDIT_VAR(global_variable_set)

/*
  Plugin status variables for SHOW STATUS
*/
static struct st_mysql_show_var ctrip_audit_status[]=
        {
                { "Ctrip_audit_called",
                        (char *) &number_of_calls,
                        SHOW_LONGLONG , SHOW_SCOPE_GLOBAL},
                { "Ctrip_audit_general_log_called",
                        (char *) &number_of_calls_general_log,
                        SHOW_LONGLONG , SHOW_SCOPE_GLOBAL},
                { "Ctrip_audit_general_error_called",
                        (char *) &number_of_calls_general_error,
                        SHOW_LONGLONG , SHOW_SCOPE_GLOBAL},
                { "Ctrip_audit_general_result_called",
                        (char *) &number_of_calls_general_result,
                        SHOW_LONGLONG , SHOW_SCOPE_GLOBAL},
                { "Ctrip_audit_general_status_called",
                        (char *) &number_of_calls_general_status,
                        SHOW_LONGLONG , SHOW_SCOPE_GLOBAL},
                { "Ctrip_audit_connection_connect_called",
                        (char *) &number_of_calls_connection_connect,
                        SHOW_LONGLONG , SHOW_SCOPE_GLOBAL},
                { "Ctrip_audit_connection_disconnect_called",
                        (char *) &number_of_calls_connection_disconnect,
                        SHOW_LONGLONG , SHOW_SCOPE_GLOBAL},
                { "Ctrip_audit_connection_change_user_called",
                        (char *) &number_of_calls_connection_change_user,
                        SHOW_LONGLONG , SHOW_SCOPE_GLOBAL},

                { "Ctrip_audit_recorded",
                        (char *) &number_of_records,
                        SHOW_LONGLONG , SHOW_SCOPE_GLOBAL},
                { "Ctrip_audit_general_log_recorded",
                        (char *) &number_of_records_general_log,
                        SHOW_LONGLONG , SHOW_SCOPE_GLOBAL},
                { "Ctrip_audit_general_error_recorded",
                        (char *) &number_of_records_general_error,
                        SHOW_LONGLONG , SHOW_SCOPE_GLOBAL},
                { "Ctrip_audit_general_result_recorded",
                        (char *) &number_of_records_general_result,
                        SHOW_LONGLONG , SHOW_SCOPE_GLOBAL},
                { "Ctrip_audit_general_status_recorded",
                        (char *) &number_of_records_general_status,
                        SHOW_LONGLONG , SHOW_SCOPE_GLOBAL},
                { "Ctrip_audit_connection_connect_recorded",
                        (char *) &number_of_records_connection_connect,
                        SHOW_LONGLONG , SHOW_SCOPE_GLOBAL},
                { "Ctrip_audit_connection_disconnect_recorded",
                        (char *) &number_of_records_connection_disconnect,
                        SHOW_LONGLONG , SHOW_SCOPE_GLOBAL},
                { "Ctrip_audit_connection_change_user_recorded",
                        (char *) &number_of_records_connection_change_user,
                        SHOW_LONGLONG , SHOW_SCOPE_GLOBAL},

                { 0, 0, SHOW_UNDEF, SHOW_SCOPE_GLOBAL}
        };


static void ctrip_audit_init_status()
{
    number_of_calls= 0;
    number_of_calls_general_log= 0;
    number_of_calls_general_error= 0;
    number_of_calls_general_result= 0;
    number_of_calls_general_status= 0;
    number_of_calls_connection_connect= 0;
    number_of_calls_connection_disconnect= 0;
    number_of_calls_connection_change_user= 0;

    number_of_records= 0;
    number_of_records_general_log= 0;
    number_of_records_general_error= 0;
    number_of_records_general_result= 0;
    number_of_records_general_status= 0;
    number_of_records_connection_connect= 0;
    number_of_records_connection_disconnect= 0;
    number_of_records_connection_change_user= 0;
}

static void ctrip_audit_deinit_status()
{
    //do nothing now
}

/* 变量 */
/*command line/option file/system variables*/
#define MAX_ADD_RULE_LENGTH 1024
#define DEFAULT_LOG_FILE "ctrip_audit.log"
#define DEFAULT_ERROR_LOG_FILE "ctrip_audit_error.log"

#define CTRIP_AUDIT_CONFIG_MAX_FILE_NAME 1024
static char ctrip_audit_log_file[CTRIP_AUDIT_CONFIG_MAX_FILE_NAME + 1];
static char ctrip_audit_error_log_file[CTRIP_AUDIT_CONFIG_MAX_FILE_NAME + 1];

static char *log_file = NULL;
static char *error_log_file = NULL;
static char *rules = NULL;
static char *add_rule = NULL;
static char *remove_rule = NULL;
static my_bool enable_buffer = FALSE;
static my_bool flush_log = FALSE;
static int buffer_size = 32;  //measure in KB.32 means 32KB
static char version_inner[] = CTRIP_AUDIT_VERSION;
static char *version = version_inner;

static rules2str_buffer_t rules_buffer;

static
void
ctrip_audit_add_rule_update(
        THD*				thd,		/*!< in: thread handle */
        struct st_mysql_sys_var*	var,		/*!< in: pointer to
							system variable */
        void*				var_ptr,	/*!< out: where the
							formal string goes */
        const void*			save);		/*!< in: immediate result
							from check function */

static
int
ctrip_audit_add_rule_validate(
        /*=============================*/
        THD*                            thd,    /*!< in: thread handle */
        struct st_mysql_sys_var*        var,    /*!< in: pointer to system
                                            variable */
        void*                           save,   /*!< out: immediate result
                                            for update function */
        struct st_mysql_value*          value);  /*!< in: incoming string */


static
void
ctrip_audit_remove_rule_update(
        THD*				thd,		/*!< in: thread handle */
        struct st_mysql_sys_var*	var,		/*!< in: pointer to
							system variable */
        void*				var_ptr,	/*!< out: where the
							formal string goes */
        const void*			save);		/*!< in: immediate result
							from check function */

static
int
ctrip_audit_remove_rule_validate(
        /*=============================*/
        THD*                            thd,    /*!< in: thread handle */
        struct st_mysql_sys_var*        var,    /*!< in: pointer to system
                                            variable */
        void*                           save,   /*!< out: immediate result
                                            for update function */
        struct st_mysql_value*          value);  /*!< in: incoming string */

static
void
ctrip_audit_set_enable_buffer_update(
        THD*				thd,		/*!< in: thread handle */
        struct st_mysql_sys_var*	var,		/*!< in: pointer to
							system variable */
        void*				var_ptr,	/*!< out: where the
							formal string goes */
        const void*			save);		/*!< in: immediate result
							from check function */

static
int
ctrip_audit_flush_log_validate(
        /*=============================*/
        THD*                            thd,    /*!< in: thread handle */
        struct st_mysql_sys_var*        var,    /*!< in: pointer to system
                                            variable */
        void*                           save,   /*!< out: immediate result
                                            for update function */
        struct st_mysql_value*          value);  /*!< in: incoming string */

static
void
ctrip_audit_flush_log_update(
        THD*				thd,		/*!< in: thread handle */
        struct st_mysql_sys_var*	var,		/*!< in: pointer to
							system variable */
        void*				var_ptr,	/*!< out: where the
							formal string goes */
        const void*			save);		/*!< in: immediate result
							from check function */
static
int
ctrip_audit_set_buffer_size_validate(
        /*=============================*/
        THD*                            thd,    /*!< in: thread handle */
        struct st_mysql_sys_var*        var,    /*!< in: pointer to system
                                            variable */
        void*                           save,   /*!< out: immediate result
                                            for update function */
        struct st_mysql_value*          value);  /*!< in: incoming string */

static
void
ctrip_audit_set_buffer_size_update(
        THD*				thd,		/*!< in: thread handle */
        struct st_mysql_sys_var*	var,		/*!< in: pointer to
							system variable */
        void*				var_ptr,	/*!< out: where the
							formal string goes */
        const void*			save);		/*!< in: immediate result
							from check function */

static MYSQL_SYSVAR_STR(log_file, log_file
, PLUGIN_VAR_READONLY | PLUGIN_VAR_NOCMDOPT
| PLUGIN_VAR_NOCMDARG
, "Ctrip audit log file"
, NULL , NULL
, DEFAULT_LOG_FILE);

static MYSQL_SYSVAR_STR(error_log_file, error_log_file
, PLUGIN_VAR_READONLY | PLUGIN_VAR_NOCMDOPT
| PLUGIN_VAR_NOCMDARG
, "Ctrip audit error log file"
, NULL , NULL
, DEFAULT_ERROR_LOG_FILE);


static MYSQL_SYSVAR_STR(rules, rules
, PLUGIN_VAR_READONLY | PLUGIN_VAR_NOCMDOPT
| PLUGIN_VAR_NOCMDARG
, "Ctrip audit rules"
, NULL , NULL
, NULL);

static MYSQL_SYSVAR_STR(add_rule, add_rule
, PLUGIN_VAR_NOCMDOPT | PLUGIN_VAR_NOCMDARG
, "Ctrip audit add new rule"
, ctrip_audit_add_rule_validate
, ctrip_audit_add_rule_update
, "");

static MYSQL_SYSVAR_STR(remove_rule, remove_rule
, PLUGIN_VAR_NOCMDOPT | PLUGIN_VAR_NOCMDARG
, "Ctrip audit remove rule"
, ctrip_audit_remove_rule_validate
, ctrip_audit_remove_rule_update
, NULL);

static MYSQL_SYSVAR_BOOL(enable_buffer, enable_buffer
, PLUGIN_VAR_NOCMDOPT | PLUGIN_VAR_NOCMDARG
, "set whether use buffer to store audit record"
, NULL
, ctrip_audit_set_enable_buffer_update
, FALSE);

static MYSQL_SYSVAR_BOOL(flush_log, flush_log
, PLUGIN_VAR_NOCMDOPT | PLUGIN_VAR_NOCMDARG
, "set whether use buffer to store audit record"
, ctrip_audit_flush_log_validate
, ctrip_audit_flush_log_update
, FALSE);

static MYSQL_SYSVAR_INT(buffer_size, buffer_size
, PLUGIN_VAR_NOCMDOPT | PLUGIN_VAR_NOCMDARG
, "set audit log buffer size"
, ctrip_audit_set_buffer_size_validate
, ctrip_audit_set_buffer_size_update
, MIN_BUFFER_SIZE, MIN_BUFFER_SIZE
, MAX_BUFFER_SIZE, 0);

static MYSQL_SYSVAR_STR(version, version
, PLUGIN_VAR_READONLY | PLUGIN_VAR_NOCMDOPT
| PLUGIN_VAR_NOCMDARG
, "Ctrip audit plugin version"
, NULL , NULL
, NULL);

static struct st_mysql_sys_var *ctrip_audit_sys_var[] = {
        MYSQL_SYSVAR(log_file)
        , MYSQL_SYSVAR(error_log_file)
        , MYSQL_SYSVAR(rules)
        , MYSQL_SYSVAR(add_rule)
        , MYSQL_SYSVAR(remove_rule)
        , MYSQL_SYSVAR(enable_buffer)
        , MYSQL_SYSVAR(flush_log)
        , MYSQL_SYSVAR(buffer_size)
        , MYSQL_SYSVAR(version)
        , 0
};

bool variable_initialized = false;
static void ctrip_audit_init_variable()
{
    rules2str_buffer_init(&rules_buffer);

    ctrip_audit_rules_2_str(&rules_buffer);
    rules = rules_buffer.buffer;

    log_file = NULL;
    if (strlen(ctrip_audit_log_file) > 0)
        log_file = ctrip_audit_log_file;
    error_log_file = NULL;
    if (strlen(ctrip_audit_error_log_file) > 0)
        error_log_file = ctrip_audit_error_log_file;

    variable_initialized = true;
}

static void ctrip_audit_deinit_variable()
{
    if (!variable_initialized)
        return;

    rules2str_buffer_deinit(&rules_buffer);
    variable_initialized = false;
}

/*************************************************************//**
Check if it is a valid add rule input. This function is registered as
a callback with MySQL.
@return	0 for valid input , 1 for invalid*/
static
int
ctrip_audit_add_rule_validate(
        /*=============================*/
        THD*                            thd,    /*!< in: thread handle */
        struct st_mysql_sys_var*        var,    /*!< in: pointer to system
                                            variable */
        void*                           save,   /*!< out: immediate result
                                            for update function */
        struct st_mysql_value*          value)  /*!< in: incoming string */
{
    const char*     input;
    char            buff[MAX_ADD_RULE_LENGTH + 1];
    int             len = sizeof(buff);
    bool            success = true;

    input = value->val_str(value, buff, &len);
    if (input == NULL)
        return (1);

    char *dup_str = strdup(input);
    if (dup_str == NULL)
        return (1);

    ctrip_audit_lock_filter_and_var();

    switch (0)
    {
        case 0:
            if (filters.size() >= MAX_FILTER_ITEMS)
            {
                success = false;
                break;
            }

            filter_item_t item;
            ctrip_audit_init_filter_item(&item);

            ctrip_audit_parse_filter(dup_str, &item);
            if (ctrip_audit_find_filter_by_name(item.name) != -1)
                success = false;

            *static_cast<const char**>(save) = input;
            free(dup_str);
    }

    ctrip_audit_unlock_filter_and_var();
    if (success)
        return (0);

    return(1);
}

static
void
ctrip_audit_add_rule_update(
        THD*				thd,		/*!< in: thread handle */
        struct st_mysql_sys_var*	var,		/*!< in: pointer to
							system variable */
        void*				var_ptr,	/*!< out: where the
							formal string goes */
        const void*			save)		/*!< in: immediate result
							from check function */
{
    DBUG_ENTER("ctrip_audit_add_rule_update");
    const char *str= *(const char**)save;
    DBUG_PRINT("add rule update value", ("str: %s", str));
    char *dup_str = NULL;


    if (str == NULL)
        DBUG_VOID_RETURN;

    dup_str = strdup(str);
    if (dup_str == NULL)
        DBUG_VOID_RETURN;

    ctrip_audit_lock_filter_and_var();

    {
        if (add_rule != NULL)
        {
            free(add_rule);
        }

        filter_item_t item;
        ctrip_audit_init_filter_item(&item);

        ctrip_audit_parse_filter(dup_str, &item);
        ctrip_audit_add_filter(&item);

        add_rule = dup_str;
    }

    //返回设置后的值
    ctrip_audit_rules_2_str(&rules_buffer);
    rules = rules_buffer.buffer;
    *(const char**)var_ptr= add_rule;

    ctrip_audit_unlock_filter_and_var();

    DBUG_VOID_RETURN;
}

/*************************************************************//**
Check if it is a valid remove rule input. This function is registered as
a callback with MySQL.
@return	0 for valid input , 1 for invalid*/
static
int
ctrip_audit_remove_rule_validate(
        /*=============================*/
        THD*                            thd,    /*!< in: thread handle */
        struct st_mysql_sys_var*        var,    /*!< in: pointer to system
                                            variable */
        void*                           save,   /*!< out: immediate result
                                            for update function */
        struct st_mysql_value*          value)  /*!< in: incoming string */
{
    const char*     input;
    char            buff[MAX_ADD_RULE_LENGTH + 1];
    int             len = sizeof(buff);
    bool            success = true;

    input = value->val_str(value, buff, &len);
    if (input == NULL)
        return(1);

    ctrip_audit_lock_filter_and_var();
    {
        remove_parse_t parse;
        remove_parse_init(&parse);
        ctrip_audit_parse_remove_input(input, &parse);

        if (ctrip_audit_remove_rule_check_exist(&parse) == -1)
            success = false;

        *static_cast<const char**>(save) = input;
    }
    ctrip_audit_unlock_filter_and_var();

    if (success)
        return (0);

    return(1);
}

static
void
ctrip_audit_remove_rule_update(
        THD*				thd,		/*!< in: thread handle */
        struct st_mysql_sys_var*	var,		/*!< in: pointer to
							system variable */
        void*				var_ptr,	/*!< out: where the
							formal string goes */
        const void*			save)		/*!< in: immediate result
							from check function */
{
    DBUG_ENTER("ctrip_audit_remove_rule_update");
    const char *str= *(const char**)save;
    DBUG_PRINT("add rule update value", ("str: %s", str));

    if (str == NULL)
        DBUG_VOID_RETURN;

    char *dup_str = strdup(str);
    if (dup_str == NULL)
        DBUG_VOID_RETURN;

    ctrip_audit_lock_filter_and_var();

    {
        if (remove_rule != NULL)
        {
            free(remove_rule);
        }
        remove_rule = dup_str;
        remove_parse_t parse;

        remove_parse_init(&parse);
        ctrip_audit_parse_remove_input(str, &parse);
        ctrip_audit_remove_filter(&parse);
    }

    //返回设置后的值
    ctrip_audit_rules_2_str(&rules_buffer);
    rules = rules_buffer.buffer;
    *(const char**)var_ptr= remove_rule;
    ctrip_audit_unlock_filter_and_var();
    //*(const char**)var_ptr= “hello update add rule”;
    DBUG_VOID_RETURN;
}

static
void
ctrip_audit_set_enable_buffer_update(
        THD*				thd,		/*!< in: thread handle */
        struct st_mysql_sys_var*	var,		/*!< in: pointer to
							system variable */
        void*				var_ptr,	/*!< out: where the
							formal string goes */
        const void*			save)		/*!< in: immediate result
							from check function */
{
    DBUG_ENTER("ctrip_audit_set_enable_buffer_update");
    my_bool nvalue = (*(static_cast<const my_bool*>(save)) != 0);

    if (nvalue == enable_buffer)
        DBUG_VOID_RETURN ;

    if (nvalue == FALSE)
    {
        Logger::GetLogger()->EnableBuffer(false);
        Logger::GetELogger()->EnableBuffer(false);
    }
    else
    {
        Logger::GetLogger()->EnableBuffer(true);
        Logger::GetELogger()->EnableBuffer(true);
    }

    enable_buffer = nvalue;

    DBUG_VOID_RETURN;
}

static
int
ctrip_audit_flush_log_validate(
        /*=============================*/
        THD*                            thd,    /*!< in: thread handle */
        struct st_mysql_sys_var*        var,    /*!< in: pointer to system
                                            variable */
        void*                           save,   /*!< out: immediate result
                                            for update function */
        struct st_mysql_value*          value)  /*!< in: incoming string */
{
    DBUG_ENTER("ctrip_audit_flush_log_validate");
    long long tmp;

    value->val_int(value, &tmp);
    if (tmp)
    {
        int ret = Logger::FlushNew();
        if (ret)
        {
            //      *static_cast<long long*>(save) = TRUE;
            //      *(my_bool*) save = TRUE;
            DBUG_RETURN(ret);
        }
        else
        {
            //*static_cast<long long*>(save) = FALSE;
            //      *(my_bool*) save = FALSE;
            DBUG_RETURN(0);
        }
    }

    DBUG_RETURN(1);
}

static
void
ctrip_audit_flush_log_update(
        THD*				thd,		/*!< in: thread handle */
        struct st_mysql_sys_var*	var,		/*!< in: pointer to
							system variable */
        void*				var_ptr,	/*!< out: where the
							formal string goes */
        const void*			save)		/*!< in: immediate result
							from check function */
{
    DBUG_ENTER("ctrip_audit_flush_log_update");

    //  my_bool flush = *(my_bool*) save;

    DBUG_VOID_RETURN;
}

static
int
ctrip_audit_set_buffer_size_validate(
        /*=============================*/
        THD*                            thd,    /*!< in: thread handle */
        struct st_mysql_sys_var*        var,    /*!< in: pointer to system
                                            variable */
        void*                           save,   /*!< out: immediate result
                                            for update function */
        struct st_mysql_value*          value)  /*!< in: incoming string */
{
    DBUG_ENTER("ctrip_audit_flush_log_validate");

    long long tmp;
    value->val_int(value, &tmp);

    int setted_value = (int)tmp;
    if (setted_value < MIN_BUFFER_SIZE)
        DBUG_RETURN(1);
    if (setted_value > MAX_BUFFER_SIZE)
        DBUG_RETURN(1);

    *static_cast<ulonglong*>(save) = setted_value;

    DBUG_RETURN(0);
}

static
void
ctrip_audit_set_buffer_size_update(
        THD*				thd,		/*!< in: thread handle */
        struct st_mysql_sys_var*	var,		/*!< in: pointer to
							system variable */
        void*				var_ptr,	/*!< out: where the
							formal string goes */
        const void*			save)		/*!< in: immediate result
							from check function */
{
    DBUG_ENTER("ctrip_audit_set_buffer_size_update");

    int setted_value = *((int *)save);
    if (setted_value == buffer_size)
        DBUG_VOID_RETURN;

    Logger::SetBufferSize(setted_value);
    buffer_size = setted_value;

    DBUG_VOID_RETURN;
}
