#include <stdio.h>
#include <time.h>
#include <my_global.h>
#include <mysql/plugin.h>
#include <mysql/plugin_audit.h>
//#include "htp_audit_filter.h"
#include "ctrip_audit.h"
#include "cJSON.h"

/*
根据传入的审计类型，构造输出的审计字符串，并进行输出
每个函数对应一个审计事件的类型
*/

/*
  关于mysql audit审计开发中一些事情的描述。
  1、审计分为两个大类，general和connection。前者发生在sql语句的执行时（待定），后者发生在连接时。
  2、general类型的分类说明。
    2-1、MYSQL_AUDIT_GENERAL_ERROR:发生错误的时候进行的审计
    2-2、MYSQL_AUDIT_GENERAL_RESULT:客户端的命令执行后无错误的审计
    2-3、MYSQL_AUDIT_GENERAL_STATUS:每个命令执行后都会进行的审计
*/

/*
  connection类型，对应plugin_audi.h中的connection class
*/
/*
  审计连接信息
  审计信息
  {
  "host":"client host"
  , "ip":"clinet ip"
  , "user":"mysql user"
  }
*/
void audit_connection_connect(const struct mysql_event_connection *event)
{
  DBUG_ASSERT(event->event_subclass == MYSQL_AUDIT_CONNECTION_CONNECT);

  char current_str[100];
  //to do : 获取当前时间
  time_t current;
  struct tm current_broken;
  current=time(NULL);
  localtime_r(&current, &current_broken);
  
  strftime(current_str, sizeof(current_str), "%F %T", &current_broken);
  //  sprintf(now, "%s", "2015-2-3 08:10 25");

  //TODO : build audit info from event
  cJSON *root;
  root=cJSON_CreateObject();
  cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(current_str));
  cJSON_AddItemToObject(root, "type", cJSON_CreateString("connection"));
  cJSON_AddItemToObject(root, "connection type", cJSON_CreateString("connect"));
  if (event->host.str != NULL)
    cJSON_AddItemToObject(root, "host", cJSON_CreateString(event->host.str));
  if (event->ip.str != NULL)
    cJSON_AddItemToObject(root, "ip", cJSON_CreateString(event->ip.str));
  if (event->user.str != NULL)
    cJSON_AddItemToObject(root, "user", cJSON_CreateString(event->user.str));

  //获得json字符串，输出到审计日志
  char *json_str = cJSON_Print(root);
  Logger::GetLogger()->Write(json_str, ",");

  //释放资源
  cJSON_Delete(root);
  free(json_str);
}

void audit_connection_disconnect(const struct mysql_event_connection *event)
{
  DBUG_ASSERT(event->event_subclass == MYSQL_AUDIT_CONNECTION_DISCONNECT);

  char current_str[100];
  //to do : 获取当前时间
  time_t current;
  struct tm current_broken;
  current=time(NULL);
  localtime_r(&current, &current_broken);
  
  strftime(current_str, sizeof(current_str), "%F %T", &current_broken);

  cJSON *root;
  root=cJSON_CreateObject();
  cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(current_str));
  cJSON_AddItemToObject(root, "type", cJSON_CreateString("connection"));
  cJSON_AddItemToObject(root, "connection type", cJSON_CreateString("disconnect"));
  if (event->host.str != NULL)
    cJSON_AddItemToObject(root, "host", cJSON_CreateString(event->host.str));
  if (event->ip.str != NULL)
    cJSON_AddItemToObject(root, "ip", cJSON_CreateString(event->ip.str));
  if (event->user.str != NULL)
    cJSON_AddItemToObject(root, "user", cJSON_CreateString(event->user.str));

  //获得json字符串，输出到审计日志
  char *json_str = cJSON_Print(root);
  Logger::GetLogger()->Write(json_str, ",");

  //释放资源
  cJSON_Delete(root);
  free(json_str);
}

void audit_connection_change_user(const struct mysql_event_connection *event)
{
  DBUG_ASSERT(event->event_subclass == MYSQL_AUDIT_CONNECTION_CHANGE_USER);

  char current_str[100];
  //to do : 获取当前时间
  time_t current;
  struct tm current_broken;
  current=time(NULL);
  localtime_r(&current, &current_broken);
  
  strftime(current_str, sizeof(current_str), "%F %T", &current_broken);

  cJSON *root;
  root=cJSON_CreateObject();
  cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(current_str));
  cJSON_AddItemToObject(root, "type", cJSON_CreateString("connection"));
  cJSON_AddItemToObject(root, "connection type", cJSON_CreateString("change user"));
  if (event->host.str != NULL)
    cJSON_AddItemToObject(root, "host", cJSON_CreateString(event->host.str));
  if (event->ip.str != NULL)
    cJSON_AddItemToObject(root, "ip", cJSON_CreateString(event->ip.str));
  if (event->user.str != NULL)
    cJSON_AddItemToObject(root, "user", cJSON_CreateString(event->user.str));

  //获得json字符串，输出到审计日志
  char *json_str = cJSON_Print(root);
  Logger::GetLogger()->Write(json_str, ",");

  //释放资源
  cJSON_Delete(root);
  free(json_str);
}


/*
  普通类型，对应plugin_audit.h中的general class
*/
/*
  
 */
void audit_general_error(const struct mysql_event_general *event)
{
  DBUG_ASSERT(event->event_subclass == MYSQL_AUDIT_GENERAL_ERROR);

  char current_str[100];
  //to do : 获取当前时间
  time_t current;
  struct tm current_broken;
  current=time(NULL);
  localtime_r(&current, &current_broken);
  
  strftime(current_str, sizeof(current_str), "%F %T", &current_broken);

  cJSON *root;
  root=cJSON_CreateObject();
  cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(current_str));
  cJSON_AddItemToObject(root, "type", cJSON_CreateString("general"));
  if (event->general_user.str != NULL)
    cJSON_AddItemToObject(root, "user",
                          cJSON_CreateString(event->general_user.str));
  if (event->general_host.str != NULL)
    cJSON_AddItemToObject(root, "host",
                          cJSON_CreateString(event->general_host.str));
  if (event->general_ip.str != NULL)
    cJSON_AddItemToObject(root, "ip",
                          cJSON_CreateString(event->general_ip.str));
  if (event->general_sql_command.str != NULL)
    cJSON_AddItemToObject(root, "command_class",
                          cJSON_CreateString(event->general_sql_command.str));
  if (event->general_query.length > 0)
    cJSON_AddItemToObject(root, "sqltext",
                          cJSON_CreateString(event->general_query.str));
  cJSON_AddItemToObject(root, "code",
                        cJSON_CreateNumber(event->general_error_code));
  

  //获得json字符串，输出到审计日志
  char *json_str = cJSON_Print(root);
  Logger::GetELogger()->Write(json_str, ",");

  //释放资源
  cJSON_Delete(root);
  free(json_str);
}

void audit_general_status(const struct mysql_event_general *event)
{
  DBUG_ASSERT(event->event_subclass == MYSQL_AUDIT_GENERAL_STATUS);

  char current_str[100];
  //to do : 获取当前时间
  time_t current;
  struct tm current_broken;
  current=time(NULL);
  localtime_r(&current, &current_broken);
  
  strftime(current_str, sizeof(current_str), "%F %T", &current_broken);

  cJSON *root;
  root=cJSON_CreateObject();
  cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(current_str));
  cJSON_AddItemToObject(root, "type", cJSON_CreateString("general"));
  if (event->general_user.str != NULL)
    cJSON_AddItemToObject(root, "user",
                          cJSON_CreateString(event->general_user.str));
  if (event->general_host.str != NULL)
    cJSON_AddItemToObject(root, "host",
                          cJSON_CreateString(event->general_host.str));
  if (event->general_ip.str != NULL)
    cJSON_AddItemToObject(root, "ip",
                          cJSON_CreateString(event->general_ip.str));
  if (event->general_sql_command.str != NULL)
    cJSON_AddItemToObject(root, "command_class",
                          cJSON_CreateString(event->general_sql_command.str));
  if (event->general_query.length > 0)
    cJSON_AddItemToObject(root, "sqltext",
                          cJSON_CreateString(event->general_query.str));
  cJSON_AddItemToObject(root, "code",
                        cJSON_CreateNumber(event->general_error_code));

  //获得json字符串，输出到审计日志
  char *json_str = cJSON_Print(root);
  Logger::GetLogger()->Write(json_str, ",");

  //释放资源
  cJSON_Delete(root);
  free(json_str);
}
