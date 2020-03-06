#ifndef CTRIP_AUDIT_H
#define CTRIP_AUDIT_H

#include <stdio.h>
#include <mysql/plugin_audit.h>
#include <sql_plugin.h>

/*
  version changer spec
  1.3:first version under MySQL 5.7.17
*/
#define CTRIP_AUDIT_VERSION "1.3"

/*插件所需的配置文件名*/
#define CTRIP_AUDIT_CONFIG_FILE "ctrip_audit.cnf"

/*配置文件config section*/
#define CTRIP_AUDIT_RULE_GROUP_NAME "audit rule"
#define CTRIP_AUDIT_GENERAL_GROUP_NAME "general"

/*audit rule section下的配置项的名字*/
#define CTRIP_AUDIT_RULE_KEY_NAME "name"
#define CTRIP_AUDIT_RULE_KEY_HOST "host"
#define CTRIP_AUDIT_RULE_KEY_USER "user"
#define CTRIP_AUDIT_RULE_KEY_EVENT "event"
#define CTRIP_AUDIT_RULE_KEY_CMD "command"
#define CTRIP_AUDIT_RULE_KEY_SQL_CMD "sql_command"
#define CTRIP_AUDIT_RULE_KEY_SQL_KEYWORD "sql_keyword"



/*general section下的配置项的名字*/
#define CTRIP_AUDIT_GENERAL_SECTION_AUDIT_FILE "audit_file"
#define CTRIP_AUDIT_GENERAL_SECTION_AUDIT_ERROR_FILE "audit_error_file"
#define CTRIP_AUDIT_GENERAL_SECTION_AUDIT_ENABLE_BUFFER "enable_buffer"

#define MAX_BUFFER_SIZE (4 * 1024)
#define MIN_BUFFER_SIZE (32)

void audit_connection_connect(const struct mysql_event_connection *event);
void audit_connection_disconnect(const struct mysql_event_connection *event);
void audit_connection_change_user(const struct mysql_event_connection *event);
void audit_general_error(const struct mysql_event_general *event);
void audit_general_status(const struct mysql_event_general *event);
void ctrip_audit_process_event(MYSQL_THD thd __attribute__((unused)),unsigned int event_class,const void *event);


#define CTRIP_AUDIT_LOG_LEVEL_INFO 1
#define CTRIP_AUDIT_LOG_LEVEL_WARN 2
#define CTRIP_AUDIT_LOG_LEVEL_ERROR 3
#define CTRIP_AUDIT_LOG_LEVEL_FATAL 4

#define CTRIP_AUDIT_EVENT_CLASS_INVALID (-1)

#define CTRIP_AUDIT_EVENT_ALL "all"

#define CTRIP_AUDIT_EVENT_GENERAL_CLASS "general"
#define CTRIP_AUDIT_EVENT_GENERAL_SUB_LOG "log"
#define CTRIP_AUDIT_EVENT_GENERAL_SUB_ERROR "error"
#define CTRIP_AUDIT_EVENT_GENERAL_SUB_RESULT "result"
#define CTRIP_AUDIT_EVENT_GENERAL_SUB_STATUS "status"

#define CTRIP_AUDIT_EVENT_CONNECTION_CLASS "connection"
#define CTRIP_AUDIT_EVENT_CONNECTION_SUB_CONNECT "connect"
#define CTRIP_AUDIT_EVENT_CONNECTION_SUB_DISCONNECT "disconnect"
#define CTRIP_AUDIT_EVENT_CONNECTION_SUB_CHANGE_USER "change user"

void
ctrip_audit_logf(
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

#endif //CTRIP_AUDIT_H
