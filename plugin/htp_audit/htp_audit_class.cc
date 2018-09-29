#include <stdio.h>
#include <string.h>
#include <my_global.h>
#include <mysql/plugin.h>
#include <mysql/plugin_audit.h>
#include <sql_plugin.h>
#include "ctrip_audit.h"
#include <list>
#include <ctype.h>
#include <string>
#include "config.h"
#include "log.h"




/* 审计事件处理 */

/*解析general传入的user串*/
static void ctrip_audit_general_event_get_user(
        const char *general_user, char *user)
{
    int len = strlen(general_user);
    int user_len = 0;
    for (int i = 0; i < len; i++)
    {
        if (general_user[i] == '[')
            break;

        user[user_len] = general_user[i];
        user_len++;
    }
    user[user_len] = 0;
}

static int
ctrip_audit_process_general_event(
        MYSQL_THD thd __attribute__((unused))
        , unsigned int event_class
        ,const void *event)
{
    const struct mysql_event_general *event_general=
            (const struct mysql_event_general *) event;

    event_info_t info;
    char user[256];
    ctrip_audit_general_event_get_user(event_general->general_user.str, user);
    info.ip = event_general->general_ip.str;
    info.user = user;
    info.host = event_general->general_host.str;
    info.main_class = MYSQL_AUDIT_GENERAL_CLASS;
    info.sub_class = event_general->event_subclass;
    info.command = event_general->general_command.str;
    info.query = event_general->general_query.str;
    info.sql_command = event_general->general_sql_command.str;

    //统计调用次数
    switch (event_general->event_subclass)
    {
        case MYSQL_AUDIT_GENERAL_LOG:
            number_of_calls_general_log++;
            break;
        case MYSQL_AUDIT_GENERAL_ERROR:
            number_of_calls_general_error++;
            break;
        case MYSQL_AUDIT_GENERAL_RESULT:
            number_of_calls_general_result++;
            break;
        case MYSQL_AUDIT_GENERAL_STATUS:
            number_of_calls_general_status++;
            break;
        default:
            break;
    }

    if (ctrip_audit_filter_event(&info, event_class) == NOT_AUDIT_EVENT)
    {
        return 0;
    }

    number_of_records++;
    //进行审计
    switch (event_general->event_subclass)
    {
        case MYSQL_AUDIT_GENERAL_LOG:
            break;
        case MYSQL_AUDIT_GENERAL_ERROR:
            audit_general_error(event_general);
            number_of_records_general_error++;
            break;
        case MYSQL_AUDIT_GENERAL_RESULT:
            break;
        case MYSQL_AUDIT_GENERAL_STATUS:
            number_of_records_general_status++;
            audit_general_status(event_general);
            break;
        default:
            break;
    }
    return 0;
}

static int
ctrip_audit_process_connection_event(
        MYSQL_THD thd __attribute__((unused))
        , unsigned int event_class
        ,const void *event)
{
    const struct mysql_event_connection *event_connection=
            (const struct mysql_event_connection *) event;

    event_info_t info;
    info.ip = event_connection->ip.str;
    info.user = event_connection->user.str;
    info.host = event_connection->host.str;
    info.main_class = MYSQL_AUDIT_CONNECTION_CLASS;
    info.sub_class = event_connection->event_subclass;

    switch (event_connection->event_subclass)
    {
        case MYSQL_AUDIT_CONNECTION_CONNECT:
            number_of_calls_connection_connect++;
            break;
        case MYSQL_AUDIT_CONNECTION_DISCONNECT:
            number_of_calls_connection_disconnect++;
            break;
        case MYSQL_AUDIT_CONNECTION_CHANGE_USER:
            number_of_calls_connection_change_user++;
            break;
        default:
            break;
    }

    if (ctrip_audit_filter_event(&info, event_class) == NOT_AUDIT_EVENT)
    {
        return 0;
    }

    number_of_records++;
    switch (event_connection->event_subclass)
    {
        case MYSQL_AUDIT_CONNECTION_CONNECT:
            number_of_records_connection_connect++;
            audit_connection_connect(event_connection);
            break;
        case MYSQL_AUDIT_CONNECTION_DISCONNECT:
            number_of_records_connection_disconnect++;
            audit_connection_disconnect(event_connection);
            break;
        case MYSQL_AUDIT_CONNECTION_CHANGE_USER:
            number_of_records_connection_change_user++;
            audit_connection_change_user(event_connection);
            break;
        default:
            break;
    }
    return 0;
}

static int
ctrip_audit_process_parse_event(
        MYSQL_THD thd __attribute__((unused))
        , unsigned int event_class
        ,const void *event)
{
    const struct mysql_event_parse
            *event_parse = (const struct mysql_event_parse *)event;

    switch (event_parse->event_subclass)
    {
        case MYSQL_AUDIT_PARSE_PREPARSE:
            number_of_calls_parse_preparse++;
            break;
        case MYSQL_AUDIT_PARSE_POSTPARSE:
            number_of_calls_parse_postparse++;
            break;
        default:
            break;
    }
    return 0;
}


/*static int
ctrip_audit_process_auth_event(
  MYSQL_THD thd __attribute__((unused))
  , unsigned int event_class
  ,const void *event)
{
  const struct mysql_event_authorization *event_grant =
  (const struct mysql_event_authorization *)event;

  buffer_data= sprintf(buffer, "db=\"%s\" table=\"%s\" object=\"%s\" "
                       "requested=\"0x%08x\" granted=\"0x%08x\"",
                       event_grant->database.str ? event_grant->database.str : "<NULL>",
                       event_grant->table.str ? event_grant->table.str : "<NULL>",
                       event_grant->object.str ? event_grant->object.str : "<NULL>",
                       event_grant->requested_privilege,
                       event_grant->granted_privilege);

  switch (event_grant->event_subclass)
  {
  case MYSQL_AUDIT_AUTHORIZATION_USER:
    number_of_calls_authorization_user++;
    break;
  case MYSQL_AUDIT_AUTHORIZATION_DB:
    number_of_calls_authorization_db++;
    break;
  case MYSQL_AUDIT_AUTHORIZATION_TABLE:
    number_of_calls_authorization_table++;
    break;
  case MYSQL_AUDIT_AUTHORIZATION_COLUMN:
    number_of_calls_authorization_column++;
    break;
  case MYSQL_AUDIT_AUTHORIZATION_PROCEDURE:
    number_of_calls_authorization_procedure++;
    break;
  case MYSQL_AUDIT_AUTHORIZATION_PROXY:
    number_of_calls_authorization_proxy++;
    break;
  default:
    break;
  }
  return 0;
  }*/

hstatic int
ctrip_audit_process_startup_event(
        MYSQL_THD thd __attribute__((unused))
        , unsigned int event_class
        ,const void *event)
{
    /* const struct mysql_event_server_startup *event_startup=
       (const struct mysql_event_server_startup *) event; */
    number_of_calls_server_startup++;
    return 0;
}

static int
ctrip_audit_process_shutdown_event(
        MYSQL_THD thd __attribute__((unused))
        , unsigned int event_class
        ,const void *event)
{
    /* const struct mysql_event_server_shutdown *event_startup=
       (const struct mysql_event_server_shutdown *) event; */
    number_of_calls_server_shutdown++;
    return 0;
}

static int
ctrip_audit_process_command_event(
        MYSQL_THD thd __attribute__((unused))
        , unsigned int event_class
        ,const void *event)
{
    /* const struct mysql_event_server_shutdown *event_startup=
       (const struct mysql_event_server_shutdown *) event; */
    const struct mysql_event_command *event_command=
            (const struct mysql_event_command *)event;

    //debug test for deinit
    //  sleep(10);

    switch (event_command->event_subclass)
    {
        case MYSQL_AUDIT_COMMAND_START:
            number_of_calls_command_start++;
            break;
        case MYSQL_AUDIT_COMMAND_END:
            number_of_calls_command_end++;
            break;
        default:
            break;
    }
    return 0;
}

static int
ctrip_audit_process_query_event(
        MYSQL_THD thd __attribute__((unused))
        , unsigned int event_class
        ,const void *event)
{
    const struct mysql_event_query *event_query=
            (const struct mysql_event_query *)event;

    switch (event_query->event_subclass)
    {
        case MYSQL_AUDIT_QUERY_START:
            number_of_calls_query_start++;
            break;
        case MYSQL_AUDIT_QUERY_NESTED_START:
            number_of_calls_query_nested_start++;
            break;
        case MYSQL_AUDIT_QUERY_STATUS_END:
            number_of_calls_query_status_end++;
            break;
        case MYSQL_AUDIT_QUERY_NESTED_STATUS_END:
            number_of_calls_query_nested_status_end++;
            break;
        default:
            break;
    }
    return 0;
}

static int
ctrip_audit_process_table_access_event(
        MYSQL_THD thd __attribute__((unused))
        , unsigned int event_class
        ,const void *event)
{
    const struct mysql_event_table_access *event_table=
            (const struct mysql_event_table_access *)event;

    switch (event_table->event_subclass)
    {
        case MYSQL_AUDIT_TABLE_ACCESS_INSERT:
            number_of_calls_table_access_insert++;
            break;
        case MYSQL_AUDIT_TABLE_ACCESS_DELETE:
            number_of_calls_table_access_delete++;
            break;
        case MYSQL_AUDIT_TABLE_ACCESS_UPDATE:
            number_of_calls_table_access_update++;
            break;
        case MYSQL_AUDIT_TABLE_ACCESS_READ:
            number_of_calls_table_access_read++;
            break;
        default:
            break;
    }
    return 0;
}

static int
ctrip_audit_process_variable_event(
        MYSQL_THD thd __attribute__((unused))
        , unsigned int event_class
        ,const void *event)
{
    const struct mysql_event_global_variable *event_gvar =
            (const struct mysql_event_global_variable *)event;

    /* Copy the variable content into the buffer. We do not guarantee that the
       variable value will fit into buffer. The buffer should be large enough
       to be used for the test purposes. */
    /*    buffer_data= sprintf(buffer, "name=\"%.*s\"",
          MY_MIN((int) event_gvar->variable_name.length,
          (int) (sizeof(buffer) - 8)),
          event_gvar->variable_name.str);

          buffer_data+= sprintf(buffer + buffer_data, " value=\"%.*s\"",
          MY_MIN((int) event_gvar->variable_value.length,
          (int) (sizeof(buffer) - 16)),
          event_gvar->variable_value.str);
          buffer[buffer_data]= '\0';*/

    switch (event_gvar->event_subclass)
    {
        case MYSQL_AUDIT_GLOBAL_VARIABLE_GET:
            number_of_calls_global_variable_get++;
            break;
        case MYSQL_AUDIT_GLOBAL_VARIABLE_SET:
            number_of_calls_global_variable_set++;
            break;
        default:
            break;
    }
    return 0;
}

void ctrip_audit_process_event(MYSQL_THD thd __attribute__((unused)),
                                      unsigned int event_class,
                                      const void *event)
{
    switch (event_class)
    {
        case MYSQL_AUDIT_GENERAL_CLASS:
            ctrip_audit_process_general_event(thd, event_class, event);
            break;
        case MYSQL_AUDIT_CONNECTION_CLASS:
            ctrip_audit_process_connection_event(thd, event_class, event);
            break;
        case MYSQL_AUDIT_PARSE_CLASS:
            ctrip_audit_process_parse_event(thd, event_class, event);
            break;
        case MYSQL_AUDIT_AUTHORIZATION_CLASS:
            break;
        case MYSQL_AUDIT_TABLE_ACCESS_CLASS:
            ctrip_audit_process_table_access_event(thd, event_class, event);
            break;
        case MYSQL_AUDIT_GLOBAL_VARIABLE_CLASS:
            ctrip_audit_process_variable_event(thd, event_class, event);
            break;
        case MYSQL_AUDIT_SERVER_STARTUP_CLASS:
            ctrip_audit_process_startup_event(thd, event_class, event);
            break;
        case MYSQL_AUDIT_SERVER_SHUTDOWN_CLASS:
            ctrip_audit_process_shutdown_event(thd, event_class, event);
            break;
        case MYSQL_AUDIT_COMMAND_CLASS:
            ctrip_audit_process_command_event(thd, event_class, event);
            break;
        case MYSQL_AUDIT_QUERY_CLASS:
            ctrip_audit_process_query_event(thd, event_class, event);
            break;
        case MYSQL_AUDIT_STORED_PROGRAM_CLASS:
            break;
        default:
            DBUG_ASSERT(FALSE);
    }
}
