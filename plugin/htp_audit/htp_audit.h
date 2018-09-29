#ifndef HTP_AUDIT_H
#define HTP_AUDIT_H

#include <stdio.h>
#include <mysql/plugin_audit.h>
#include <sql_plugin.h>

/*
  version changer spec
  1.0:first version under MySQL 5.7.18
*/
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

bool lock_initialized = false;
mysql_mutex_t LOCK_filter_and_var;

void audit_connection_connect(const struct mysql_event_connection *event);
void audit_connection_disconnect(const struct mysql_event_connection *event);
void audit_connection_change_user(const struct mysql_event_connection *event);
void audit_general_error(const struct mysql_event_general *event);
void audit_general_status(const struct mysql_event_general *event);
void ctrip_audit_init_filter_item(filter_item_t *item)
void ctrip_audit_process_event(MYSQL_THD thd __attribute__((unused)),unsigned int event_class,const void *event);
/*
void ctrip_audit_set_buffer_size_validate(THD* thd, struct st_mysql_sys_var* var,void* save, struct st_mysql_value* value);
void ctrip_audit_set_buffer_size_update(THD* thd, struct st_mysql_sys_var*	var,void* var_ptr, const void* save);
void ctrip_audit_add_rule_update( THD* thd, struct st_mysql_sys_var* var,void* var_ptr,const void* save);
*/
/*!< in: incoming string */
//add lock production

static int ctrip_audit_init_lock();
static void ctrip_audit_deinit_lock()



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

void
tp_audit_logf(
  int level,  /*!< in: warning level */
  const char*    format, /*!< printf format */
  ...
);

class LogBuffer;

class Logger
{
public :
  /*
    return : 0 success, -1 fail
   */
  static int Initialize(const char *log, const char *elog
                        , my_bool enable_buffer);
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

  inline void Lock()
  {
    mysql_mutex_lock(&lock_);
  }

  inline void Unlock()
  {
    mysql_mutex_unlock(&lock_);
  }

  int FlushNewInner();
  int SetBufferSizeInner(int);

  Logger(const char *path);
  ~Logger();
};

#endif //HTP_AUDIT_H
