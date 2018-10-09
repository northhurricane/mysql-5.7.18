#include <stdio.h>
#include <string.h>
#include <my_global.h>
#include <mysql/plugin.h>
#include <mysql/plugin_audit.h>
#include <sql_plugin.h>
//#include "htp_audit.h"
#include <list>
#include <ctype.h>
#include <string>
#include "config.h"
#include "log.h"

using namespace std;

#define HTP_AUDIT_VERSION "1.0"

/*插件所需的配置文件名*/
#define HTP_AUDIT_CONFIG_FILE "htp_audit.cnf"

/*配置文件config section*/
#define HTP_AUDIT_RULE_GROUP_NAME "audit rule"
#define HTP_AUDIT_GENERAL_GROUP_NAME "general"
/*audit rule section下的配置项的名字*/
#define HTP_AUDIT_RULE_KEY_NAME "name"
#define HTP_AUDIT_RULE_KEY_HOST "host"
#define HTP_AUDIT_RULE_KEY_USER "user"
#define HTP_AUDIT_RULE_KEY_EVENT "event"
#define HTP_AUDIT_RULE_KEY_CMD "command"
#define HTP_AUDIT_RULE_KEY_SQL_CMD "sql_command"
#define HTP_AUDIT_RULE_KEY_SQL_KEYWORD "sql_keyword"

/*general section下的配置项的名字*/
#define HTP_AUDIT_GENERAL_SECTION_AUDIT_FILE "audit_file"
#define HTP_AUDIT_GENERAL_SECTION_AUDIT_ERROR_FILE "audit_error_file"
#define HTP_AUDIT_GENERAL_SECTION_AUDIT_ENABLE_BUFFER "enable_buffer"

#define MAX_BUFFER_SIZE (4 * 1024)
#define MIN_BUFFER_SIZE (32)


void audit_connection_connect(const struct mysql_event_connection *event);

void audit_connection_disconnect(const struct mysql_event_connection *event);

void audit_connection_change_user(const struct mysql_event_connection *event);

void audit_general_error(const struct mysql_event_general *event);

void audit_general_status(const struct mysql_event_general *event);

void audit_parse_preparse(const struct mysql_event_parse *event);

void audit_parse_postparse(const struct mysql_event_parse *event);

void audit_authorization_user(const struct mysql_event_authorization *event);

void audit_authorization_db(const struct mysql_event_authorization *event);

void audit_authorization_table(const struct mysql_event_authorization *event);

void audit_authorization_column(const struct mysql_event_authorization *event);

void audit_authorization_procedure(const struct mysql_event_authorization *event);

void audit_authorization_proxy(const struct mysql_event_authorization *event);

void audit_server_shutdown_shutdown(const struct mysql_event_server_shutdown *event);

void audit_command_start(const struct mysql_event_command *event);

void audit_command_end(const struct mysql_event_command *event);

void audit_query_status_start(const struct mysql_event_query *event);

void audit_query_status_end(const struct mysql_event_query *event);

void audit_query_nested_start(const struct mysql_event_query *event);

void audit_query_nested_status_end(const struct mysql_event_query *event);

void audit_table_access_insert(const struct mysql_event_table_access *event);

void audit_table_access_read(const struct mysql_event_table_access *event);

void audit_table_access_update(const struct mysql_event_table_access *event);

void audit_table_access_delete(const struct mysql_event_table_access *event);

void audit_global_variable_get(const struct mysql_event_global_variable *event);

void audit_global_variable_set(const struct mysql_event_global_variable *event);

void audit_query_start(const struct mysql_event_query *event);

void htp_audit_process_event(MYSQL_THD thd __attribute__((unused)), unsigned int event_class, const void *event);

//void htp_audit_init_filter_item(filter_item_t *item)
//void htp_audit_process_event(MYSQL_THD thd __attribute__((unused)),unsigned int event_class,const void *event);
/*
void htp_audit_set_buffer_size_validate(THD* thd, struct st_mysql_sys_var* var,void* save, struct st_mysql_value* value);
void htp_audit_set_buffer_size_update(THD* thd, struct st_mysql_sys_var*	var,void* var_ptr, const void* save);
void htp_audit_add_rule_update( THD* thd, struct st_mysql_sys_var* var,void* var_ptr,const void* save);
*/
/*!< in: incoming string */
//add lock production

int htp_audit_init_lock();

void htp_audit_deinit_lock();

#define HTP_AUDIT_LOG_LEVEL_INFO 1
#define HTP_AUDIT_LOG_LEVEL_WARN 2
#define HTP_AUDIT_LOG_LEVEL_ERROR 3
#define HTP_AUDIT_LOG_LEVEL_FATAL 4

#define HTP_AUDIT_EVENT_CLASS_INVALID (-1)

#define HTP_AUDIT_EVENT_ALL "all"

#define HTP_AUDIT_EVENT_GENERAL_CLASS "general"
#define HTP_AUDIT_EVENT_GENERAL_SUB_LOG "log"
#define HTP_AUDIT_EVENT_GENERAL_SUB_ERROR "error"
#define HTP_AUDIT_EVENT_GENERAL_SUB_RESULT "result"
#define HTP_AUDIT_EVENT_GENERAL_SUB_STATUS "status"

#define HTP_AUDIT_EVENT_CONNECTION_CLASS "connection"
#define HTP_AUDIT_EVENT_CONNECTION_SUB_CONNECT "connect"
#define HTP_AUDIT_EVENT_CONNECTION_SUB_DISCONNECT "disconnect"
#define HTP_AUDIT_EVENT_CONNECTION_SUB_CHANGE_USER "change user"



/* 审计事件过滤 */
#define MAX_FILTER_NAME_LENGTH (128)
#define MAX_FILTER_NAME_BUFFER_SIZE (MAX_FILTER_NAME_LENGTH + 1)
#define MAX_FILTER_HOST_LENGTH (128)
#define MAX_FILTER_HOST_BUFFER_SIZE (MAX_FILTER_HOST_LENGTH + 1)
#define MAX_FILTER_IP_LENGTH (128)
#define MAX_FILTER_IP_BUFFER_SIZE (MAX_FILTER_IP_LENGTH + 1)
#define MAX_FILTER_USER_LENGTH (128)
#define MAX_FILTER_USER_BUFFER_SIZE (MAX_FILTER_USER_LENGTH + 1)
#define MAX_FILTER_ITEMS (32)
//根据plugin_audit的subclass的数目决定
#define MAX_FILTER_GENERAL_EVENTS (4)
#define MAX_FILTER_CONNECTION_EVENTS (3)

#define MAX_FILTER_COMMAND (128)
#define MAX_FILTER_COMMAND_BUFFER_SIZE (MAX_FILTER_COMMAND + 1)
#define MAX_FILTER_SQL_COMMAND (128)
#define MAX_FILTER_SQL_COMMAND_BUFFER_SIZE (MAX_FILTER_SQL_COMMAND + 1)
#define MAX_FILTER_SQL_KEYWORD (128)
#define MAX_FILTER_SQL_KEYWORD_BUFFER_SIZE (MAX_FILTER_SQL_KEYWORD + 1)
#define EVENT_UNSETTED   (-1)
#define EVENT_SETTED   (1)

#define FILTER_ITEM_UNUSABLE 0
#define FILTER_ITEM_USABLE 1
#define SETTING_ALL_EVENT HTP_AUDIT_EVENT_ALL

/*只指定主类型的情况，没有指定子类型。如general;connection，表示general的所有类型都进行过滤*/
#define EVENT_ALL   (-1)

enum filter_result_enum {
  AUDIT_EVENT, NOT_AUDIT_EVENT
};


void htp_audit_logf(
    int level,  /*!< in: warning level */
    const char *format, /*!< printf format */
    ...
);

class LogBuffer;

class Logger {
  public :
    /*
      return : 0 success, -1 fail
     */
    static int Initialize(const char *log, const char *elog, my_bool enable_buffer);

    /*
      return : 0 success, -1 fail
     */
    static int Deinitialize();

    static Logger *GetLogger();

    static Logger *GetELogger();

    /*已有信息写入文件，保存老文件为备份，并创建新的log文件*/
    static int FlushNew();

    /* 设置日志缓冲区的大小，以KB大小计算*/
    static int SetBufferSize(int size);

    void Write(const char *info, const char *splitter);

    void EnableBuffer(bool enable);

  private :
    char *file_name_;
    bool enable_buffer_;
    FILE *file_;
    LogBuffer *log_buffer_;
    mysql_mutex_t lock_;

    inline void Lock() {
      mysql_mutex_lock(&lock_);
    }

    inline void Unlock() {
      mysql_mutex_unlock(&lock_);
    }

    int FlushNewInner();

    int SetBufferSizeInner(int);

    Logger(const char *path);

    ~Logger();
};


struct filter_item_struct {
  bool name_setted;
  char name[MAX_FILTER_NAME_BUFFER_SIZE];
  bool host_setted;
  char host[MAX_FILTER_HOST_BUFFER_SIZE];
  int host_length;
  bool user_setted;
  char user[MAX_FILTER_USER_BUFFER_SIZE];
  int user_length;
  //事件(event)相关
  bool event_setted;
  bool audit_all_event;  //event=all
  //初始化为-1，表示未设置
  bool audit_all_connection; //event=connection
  int connection_events[MAX_FILTER_CONNECTION_EVENTS];
  //bool connection_events_setted;
  bool audit_all_general;  //event=general
  int general_events[MAX_FILTER_GENERAL_EVENTS];
  //bool general_events_setted;
  bool command_setted;
  char command[MAX_FILTER_COMMAND_BUFFER_SIZE];
  int command_length;
  bool sql_command_setted;
  char sql_command[MAX_FILTER_SQL_COMMAND_BUFFER_SIZE];
  int sql_command_length;
  bool sql_keyword_setted;
  char sql_keyword[MAX_FILTER_SQL_KEYWORD_BUFFER_SIZE];
  int sql_keyword_length;
};

typedef struct filter_item_struct filter_item_t;

void htp_audit_init_filter_item(filter_item_t *item);

struct event_info_struct {
  const char *host;
  const char *ip;
  const char *user;
  int main_class;
  int sub_class;
  const char *command;
  const char *query;
  const char *sql_command;
};
typedef struct event_info_struct event_info_t;

#define MAX_REMOVE_ITEM MAX_FILTER_ITEMS
struct remove_parse_struct {
  int count;
  char removes[MAX_REMOVE_ITEM][MAX_FILTER_NAME_BUFFER_SIZE];
};
typedef struct remove_parse_struct remove_parse_t;


void htp_audit_init_filter_item(filter_item_t *item);

void htp_audit_init_filter();

void htp_audit_deinit_filter();

int htp_audit_find_filter_by_name(const char *name);

int htp_audit_check_value_valid(const char *value, int length);

int htp_audit_find_filter_by_name(const char *name);

int htp_audit_parse_event(const char *event, int event_len, filter_item_t *item);

int htp_audit_add_filter(filter_item_t *item);

int htp_audit_reorg_filter_item(filter_item_t *filter_item);

//filter item
//filter_item_t filter_items[MAX_FILTER_ITEMS];
//current_used_filter
//list<int> filters;
//char filter_using_map[MAX_FILTER_ITEMS];
extern my_bool _debug_on_;

void htp_audit_lock_filter_and_var();

void htp_audit_unlock_filter_and_var();

int htp_audit_parse_filter(const char *filter_str, filter_item_t *item);

void remove_parse_init(remove_parse_t *parse);

int htp_audit_parse_remove_input(const char *remove_str, remove_parse_t *parse);

int htp_audit_remove_rule_check_exist(remove_parse_t *removes);

int htp_audit_remove_filter(remove_parse_t *removes);

filter_result_enum htp_audit_filter_event(event_info_t *info, filter_item_t *item, unsigned int event_class);

filter_result_enum htp_audit_filter_event(event_info_t *info, unsigned int event_class);