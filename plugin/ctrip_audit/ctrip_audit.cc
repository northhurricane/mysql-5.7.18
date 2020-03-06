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

#if !defined(__attribute__) && (defined(__cplusplus) || !defined(__GNUC__)  || __GNUC__ == 2 && __GNUC_MINOR__ < 8)
#define __attribute__(A)
#endif

using namespace std;

extern my_bool _dbug_on_;

/*
  mysql的日志写入
*/
void
ctrip_audit_logf(
  int level,             /*!< in: warning level */
  const char*    format, /*!< printf format */
  ...
)
{
  char*		str;
  va_list         args;

  va_start(args, format);

#ifdef __WIN__
  int		size = _vscprintf(format, args) + 1;
  str = static_cast<char*>(malloc(size));
  str[size - 1] = 0x0;
  vsnprintf(str, size, format, args);
#elif HAVE_VASPRINTF
  //int	ret;
  //ret = vasprintf(&str, format, args);
  vasprintf(&str, format, args);
#else
  /* Use a fixed length string. */
  str = static_cast<char*>(malloc(BUFSIZ));
  my_vsnprintf(str, BUFSIZ, format, args);
#endif /* __WIN__ */

  switch(level) {
  case CTRIP_AUDIT_LOG_LEVEL_INFO:
    sql_print_information("Ctrip Audit: %s", str);
    break;
  case CTRIP_AUDIT_LOG_LEVEL_WARN:
    sql_print_warning("Ctrip Audit: %s", str);
    break;
  case CTRIP_AUDIT_LOG_LEVEL_ERROR:
    sql_print_error("Ctrip Audit: %s", str);
    break;
  case CTRIP_AUDIT_LOG_LEVEL_FATAL:
    sql_print_error("Ctrip Audit: %s", str);
    break;
  }

  va_end(args);
  free(str);

  if (level == CTRIP_AUDIT_LOG_LEVEL_FATAL) {
  }
}


/*
  审计的互斥保护
  需要保护的对象为：1、审计的过滤条件；2、审计的变量
  保护的时间段
  在插件初始化的时候，由mysql的保护机制实现变量的保护
  在增加/删除过滤条件的时候，由插件实现变量的保护
 */
static mysql_mutex_t LOCK_filter_and_var;
static bool lock_initialized = false;

static int ctrip_audit_init_lock()
{
  mysql_mutex_init(0, &LOCK_filter_and_var, MY_MUTEX_INIT_FAST);
  lock_initialized = true;

  return 0;
}

static void ctrip_audit_deinit_lock()
{
  if (!lock_initialized)
    return;

  mysql_mutex_destroy(&LOCK_filter_and_var);
  lock_initialized = false;
}

inline void ctrip_audit_lock_filter_and_var()
{
  mysql_mutex_lock(&LOCK_filter_and_var);
}

inline void ctrip_audit_unlock_filter_and_var()
{
  mysql_mutex_unlock(&LOCK_filter_and_var);
}


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
//
#define MAX_FILTER_COMMAND (128)
#define MAX_FILTER_COMMAND_BUFFER_SIZE (MAX_FILTER_COMMAND + 1)
#define MAX_FILTER_SQL_COMMAND (128)
#define MAX_FILTER_SQL_COMMAND_BUFFER_SIZE (MAX_FILTER_SQL_COMMAND + 1)
#define MAX_FILTER_SQL_KEYWORD (128)
#define MAX_FILTER_SQL_KEYWORD_BUFFER_SIZE (MAX_FILTER_SQL_KEYWORD + 1)

#define EVENT_UNSETTED   (-1)
#define EVENT_SETTED     (1)

/*只指定主类型的情况，没有指定子类型。如general;connection，表示general的所有类型都进行过滤*/
#define EVENT_ALL   (-1)

struct filter_item_struct
{
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

struct event_info_struct
{
  const char *host;
  const char *ip;
  const char *user;
  int main_class;
  int sub_class;
  const char *command;
  const char *query;
  const char *sql_command;
};
typedef event_info_struct event_info_t;

#define MAX_REMOVE_ITEM MAX_FILTER_ITEMS
struct remove_parse_struct
{
  int count;
  char removes[MAX_REMOVE_ITEM][MAX_FILTER_NAME_BUFFER_SIZE];
};
typedef struct remove_parse_struct remove_parse_t;
static void remove_parse_init(remove_parse_t *parse)
{
  parse->count = 0;
  for (int i = 0; i < MAX_REMOVE_ITEM; i++)
  {
    ;
  }
}

static void remove_parse_add_item(
  remove_parse_t *parse, const char *name, int len)
{
  int item_pos = parse->count;
  strncpy(parse->removes[item_pos], name, len);
  parse->removes[item_pos][len] = 0;
  parse->count++;
}

enum filter_result_enum
{
  AUDIT_EVENT
  , NOT_AUDIT_EVENT
};

//filter item
static filter_item_t filter_items[MAX_FILTER_ITEMS];
//当前使用的filter
static list<int> filters;

#define FILTER_ITEM_UNUSABLE 0
#define FILTER_ITEM_USABLE 1
static char filter_using_map[MAX_FILTER_ITEMS];

static void ctrip_audit_init_filter_item(filter_item_t *item)
{
  item->name_setted = false;
  item->name[0] = 0;
  item->host_setted = false;
  item->host[0] = 0;
  item->host_length = 0;
  item->user_setted = false;
  item->user[0] = 0;
  item->user_length = 0;
  item->event_setted = false;
  item->audit_all_event = false;
  item->audit_all_general = false;
  item->audit_all_connection = false;
  for (int i = 0; i < MAX_FILTER_GENERAL_EVENTS; i++)
  {
    item->general_events[i] = EVENT_UNSETTED;
  }
  //item->general_events_setted = false;
  for (int i = 0; i < MAX_FILTER_CONNECTION_EVENTS; i++)
  {
    item->connection_events[i] = EVENT_UNSETTED;
  }
  //item->connection_events_setted = false;
  item->command_setted = false;
  item->command[0] = 0;
  item->command_length = 0;
  item->sql_command_setted = false;
  item->sql_command[0] = 0;
  item->sql_command_length = 0;
  item->sql_keyword_setted = false;
  item->sql_keyword[0] = 0;
  item->sql_keyword_length = 0;
}

static void ctrip_audit_init_filter()
{
  DBUG_ASSERT(filters.size() == 0);
  for (int i = 0; i < MAX_FILTER_ITEMS; i++)
  {
    filter_using_map[i] = FILTER_ITEM_UNUSABLE;
    ctrip_audit_init_filter_item(filter_items + i);
  }
}

static void ctrip_audit_deinit_filter()
{
  filters.clear();
}

/*static void test_mock_a_filter(filter_item_t *item)
{
  strcpy(item->host, "localhost");
  item->host_length = strlen(item->host);
  strcpy(item->user, "root");
  item->user_length = strlen(item->user);
  }*/

inline bool ctrip_audit_is_kv_unit_splitter(char c)
{
  if (c == ';' || c == '\n' || c == '\r')
    return true;
  return false;
}

inline bool ctrip_audit_is_event_class_splitter(char c)
{
  if (c == ':')
    return true;
  return false;
}

inline bool ctrip_audit_is_event_splitter(char c)
{
  if (c == ';')
    return true;

  return false;
}

/*获取event的信息*/
static int ctrip_audit_get_event_inchar(
  const char *event, int event_len
  , const char **main_class, int *main_len
  , const char **sub_class, int *sub_len)
{
  int main_class_len = 0, sub_class_len = 0;

  *main_class = NULL; *main_len = 0;
  *sub_class = NULL; *sub_len = 0;

  *main_class = event;
  for (int i = 0; i < event_len; i++)
  {
    if (ctrip_audit_is_event_class_splitter(event[i]))
      break;
    main_class_len++;
  }
  *main_len = main_class_len;

  //只输入主类型
  if (main_class_len == event_len)
    return 0;

  //获取子类型长度
  sub_class_len = event_len - main_class_len - 1;
  if (sub_class_len == 0)
    return 0;

  *sub_class = event + main_class_len + 1;
  *sub_len = sub_class_len;

  return 0;
}

/*获取class对应的宏定义内容*/
static int ctrip_audit_get_event_init(
  const char *main_class , int main_len, int *main_class_int
  , const char *sub_class, int sub_len, int *sub_class_int)
{
  if (strncasecmp(main_class, CTRIP_AUDIT_EVENT_GENERAL_CLASS, main_len) == 0)
  {
    *main_class_int = MYSQL_AUDIT_GENERAL_CLASS;
    if (sub_len == 0)
    {
      *sub_class_int = EVENT_ALL;
      return 0;
    }

    if (
      strncasecmp(sub_class, CTRIP_AUDIT_EVENT_GENERAL_SUB_ERROR, sub_len) == 0)
    {
      *sub_class_int = MYSQL_AUDIT_GENERAL_ERROR;
    }
    else if (strncasecmp(
      sub_class, CTRIP_AUDIT_EVENT_GENERAL_SUB_STATUS, sub_len) == 0)
    {
      *sub_class_int = MYSQL_AUDIT_GENERAL_STATUS;
    }
    else
    {
      return -1;
    }
    /* 现在不支持，如果进行配置，则报告错误
    if (strncasecmp(sub_class, CTRIP_AUDIT_EVENT_GENERAL_SUB_LOG, sub_len) == 0)
    {
      return -1;
    }
    else if (strncasecmp(
      sub_class, CTRIP_AUDIT_EVENT_GENERAL_SUB_RESULT, sub_len) == 0)
    {
      return -1;
    }
    */
  }
  else if (strncasecmp(
    main_class, CTRIP_AUDIT_EVENT_CONNECTION_CLASS, main_len) == 0)
  {
    *main_class_int = MYSQL_AUDIT_CONNECTION_CLASS;
    if (sub_len == 0)
    {
      *sub_class_int = EVENT_ALL;
      return 0;
    }

    if (strncasecmp(
          sub_class, CTRIP_AUDIT_EVENT_CONNECTION_SUB_CONNECT, sub_len) == 0)
    {
      *sub_class_int = MYSQL_AUDIT_CONNECTION_CONNECT;
    }
    else if (strncasecmp(
      sub_class, CTRIP_AUDIT_EVENT_CONNECTION_SUB_DISCONNECT, sub_len) == 0)
    {
      *sub_class_int = MYSQL_AUDIT_CONNECTION_DISCONNECT;
    }
    else if (strncasecmp(
      sub_class, CTRIP_AUDIT_EVENT_CONNECTION_SUB_CHANGE_USER, sub_len) == 0)
    {
      *sub_class_int = MYSQL_AUDIT_CONNECTION_CHANGE_USER;
    }
    else
    {
      return -1;
    }
  }
  else
  {
    return -1;
  }

  return 0;
}

static int ctrip_audit_get_single_event_len(const char *event, int event_len)
{
  int single_event_len = 0;
  for (int i = 0; i < event_len; i++)
  {
    if (ctrip_audit_is_event_splitter(event[i]))
      break;
    single_event_len++;
  }
  return single_event_len;
}

static void ctrip_audit_fill_event(
  filter_item_t *item, int main_class, int sub_class)
{
  if (main_class == MYSQL_AUDIT_GENERAL_CLASS)
  {
    //item->general_events_setted = true;
    if (sub_class == EVENT_ALL)
    {
      item->audit_all_general = true;
      for (int i = 0; i < MAX_FILTER_GENERAL_EVENTS; i++)
      {
        item->general_events[i] = EVENT_SETTED;
      }
      return ;
    }

    item->general_events[sub_class] = EVENT_SETTED;
  }
  else
  {
    DBUG_ASSERT(main_class == MYSQL_AUDIT_CONNECTION_CLASS);

    //item->connection_events_setted = true;
    if (sub_class == EVENT_ALL)
    {
      item->audit_all_connection = true;
      for (int i = 0; i < MAX_FILTER_CONNECTION_EVENTS; i++)
      {
        item->connection_events[i] = EVENT_SETTED;
      }
      return ;
    }

    item->connection_events[sub_class] = EVENT_SETTED;
  }
}

#define SETTING_ALL_EVENT CTRIP_AUDIT_EVENT_ALL
static int ctrip_audit_parse_event(const char *event
                                   , int event_len, filter_item_t *item)
{
  int index = 0, rest_len = event_len;
  const char *event_pos;
  const char *main_class, *sub_class;
  int main_class_len, sub_class_len;
  int main_class_int, sub_class_int;
  int single_len;
  int r = 0;

  //是否为审计全部信息
  if (strcasecmp(event, SETTING_ALL_EVENT) == 0)
  {
    item->audit_all_event = true;
    return 0;
  }

  while (index < event_len)
  {
    event_pos = event + index;

    single_len = ctrip_audit_get_single_event_len(event_pos, rest_len);
    DBUG_ASSERT(single_len >= 0);

    if (single_len == 0)
    {
      return -1;
    }

    ctrip_audit_get_event_inchar(event_pos, single_len
                                , &main_class, &main_class_len
                                , &sub_class, &sub_class_len);

    r = ctrip_audit_get_event_init(main_class, main_class_len, &main_class_int
                                , sub_class, sub_class_len, &sub_class_int);
    if (r)
    {
      item->event_setted = false;
      return -1;
    }
    
    ctrip_audit_fill_event(item, main_class_int, sub_class_int);
    item->event_setted = true;

    index += single_len;
    if (ctrip_audit_is_event_splitter(*(event + index)))
    {
      index++;
    }
    rest_len = event_len - index;

    DBUG_ASSERT(rest_len >= 0);
    if (rest_len == 0)
    {
      break;
    }
  }

  //检查event是否被设置
  if (item->event_setted != true)
  {
    return -1;
  }

  return (0);
}

static int ctrip_audit_get_kv_unit(const char *current, const char **next
                                   , const char **k, int *k_len
                                   , const char **v, int *v_len)
{
  const char *index = current;
  const char *key = NULL;
  const char *value = NULL;
  //int kv_counter = 0, k_counter = 0, v_counter = 0;
  int k_counter = 0, v_counter = 0;
  bool in_key_phase = true;
  //int line_counter = 0;

  //获取key-value
  key = index;
  while (*index != 0)
  {
    //是否一个kv输入结束
    if (ctrip_audit_is_kv_unit_splitter(*index))
      break;

    if (*index == '=')
    {
      in_key_phase = false;
      value = index + 1;
      index++;
      if (ctrip_audit_is_kv_unit_splitter(*index))
      {
        break;
      }
    }

    if (in_key_phase)
    {
      k_counter++;
    }
    else
    {
      v_counter++;
    }

    index++;
  }
  *k = key; *k_len = k_counter;
  *v = value; *v_len = v_counter;

  //过滤掉用于分割kv的分割符
  while (*index != 0)
  {
    if (!ctrip_audit_is_kv_unit_splitter(*index))
      break;
    index++;
  }
  *next = index;
  //kv_counter = index - current;

  //无后续的内容
  if (*index == 0)
    *next = NULL;
  return 0;
}

static int ctrip_audit_check_value_valid(const char *value, int length)
{
  for (int i = 0; i < length; i++)
  {
    if ('a' <= value[i] && value[i] <= 'z')
      continue;
    if ('A' <= value[i] && value[i] <= 'Z')
      continue;
    if ('0' <= value[i] && value[i] <= '9')
      continue;
    if (value[i] == '_' || value[i] == '.')
      continue;
    return -1;
  }
  return 0;
}

static int ctrip_audit_parse_kv_unit(const char *current, const char ** next
                                     , filter_item_t *item)
{
  const char *key = NULL;
  const char *value = NULL;
  int k_len = 0, v_len = 0;
  int r;

  r = ctrip_audit_get_kv_unit(current, next, &key, &k_len, &value, &v_len);
  if (r)
    return r;

  if (strncasecmp(key, CTRIP_AUDIT_RULE_KEY_NAME, k_len) == 0)
  {
    if (item->name_setted == true)
      return -1;

    strncpy(item->name, value, v_len);
    item->name[v_len] = 0;
    if (ctrip_audit_check_value_valid(item->name, v_len))
      return -1;

    item->name_setted = true;
  }
  else if (strncasecmp(key, CTRIP_AUDIT_RULE_KEY_HOST, k_len) == 0)
  {
    if (item->host_setted == true)
      return -1;

    strncpy(item->host, value, v_len);
    item->host[v_len] = 0;
    item->host_length = v_len;
    if (ctrip_audit_check_value_valid(item->host, v_len))
      return -1;

    item->host_setted = true;
  }
  else if (strncasecmp(key, CTRIP_AUDIT_RULE_KEY_USER, k_len) == 0)
  {
    if (item->user_setted == true)
      return -1;

    strncpy(item->user, value, v_len);
    item->user[v_len] = 0;
    item->user_length = v_len;

    item->user_setted = true;
  }
  else if (strncasecmp(key, CTRIP_AUDIT_RULE_KEY_EVENT, k_len) == 0)
  {
    //获取事件的配置情况
    if (item->event_setted == true)
      return -1;

    r = ctrip_audit_parse_event(value, v_len, item);
    if (r)
      return -1;

    item->event_setted = true;
  }
  else if (strncasecmp(key, CTRIP_AUDIT_RULE_KEY_CMD, k_len) == 0)
  {
    if (v_len >= MAX_FILTER_COMMAND_BUFFER_SIZE)
      return -1;
    strncpy(item->command, value, v_len);
    item->command[v_len] = 0;
    item->command_length = v_len;
  }
  else if (strncasecmp(key, CTRIP_AUDIT_RULE_KEY_SQL_CMD, k_len) == 0)
  {
    if (v_len >= MAX_FILTER_SQL_COMMAND_BUFFER_SIZE)
      return -1;
    strncpy(item->sql_command, value, v_len);
    item->sql_command[v_len] = 0;
    item->sql_command_length = v_len;
  }
  else if (strncasecmp(key, CTRIP_AUDIT_RULE_KEY_SQL_KEYWORD, k_len) == 0)
  {
    if (v_len >= MAX_FILTER_SQL_KEYWORD_BUFFER_SIZE)
      return -1;
    strncpy(item->sql_keyword, value, v_len);
    item->sql_command[v_len] = 0;
    item->sql_command_length = v_len;
  }
  else
  {
    //不可识别的内容
    return -1;
  }
  
  return 0;
}

static int ctrip_audit_parse_input(const char *filter_str, filter_item_t *item)
{
  const char *current = filter_str;
  const char *next = NULL;
  int r;

  while (current != NULL)
  {
    r = ctrip_audit_parse_kv_unit(current, &next, item);
    if (r)
      return r;
    current = next;
  }

  return 0;
}

static int ctrip_audit_parse_filter(const char *filter_str, filter_item_t *item)
{
  //test_mock_a_filter(item);
  //return 0;

  item->host[0] = 0;
  item->user[0] = 0;

  for (int i = 0; i < MAX_FILTER_CONNECTION_EVENTS; i++)
  {
    item->connection_events[i] = -1;
  }
  for (int i = 0; i < MAX_FILTER_GENERAL_EVENTS; i++)
  {
    item->general_events[i] = -1;
  }

  return ctrip_audit_parse_input(filter_str, item);
}

static int ctrip_audit_add_filter(filter_item_t *item)
{
  for (int i = 0; i < MAX_FILTER_ITEMS; i++)
  {
    if (filter_using_map[i] == FILTER_ITEM_UNUSABLE)
    {
      filters.push_back(i);
      filter_using_map[i] = FILTER_ITEM_USABLE;
      filter_items[i] = *item;
      break;
    }
  }
  return (0);
}

static int ctrip_audit_find_filter_by_name(const char *name)
{
  list<int>::iterator it;
  filter_item_t *item;
  for (it = filters.begin(); it != filters.end(); it++)
  {
    int pos = *it;
    item = filter_items + pos;
    if (strcasecmp(item->name, name) == 0)
    {
      //匹配到过滤内容，删除过滤内容
      return pos;
    }
  }
  return -1;
}

static int ctrip_audit_remove_filter_by_name(const char *name)
{
  list<int>::iterator it;
  filter_item_t *item;
  for (it = filters.begin(); it != filters.end(); it++)
  {
    int pos = *it;
    item = filter_items + pos;
    if (strcasecmp(item->name, name) == 0)
    {
      //匹配到过滤内容，删除过滤内容
      filter_using_map[pos] = FILTER_ITEM_USABLE;
      it = filters.erase(it);
      break;
    }
  }
  return 0;
}

static int ctrip_audit_remove_filter(remove_parse_t *removes)
{
  int i;

  for (i = 0; i < removes->count; i++)
  {
    ctrip_audit_remove_filter_by_name(removes->removes[i]);
  }
  return 0;
}

static int ctrip_audit_remove_rule_check_exist(remove_parse_t *removes)
{
  int i;

  for (i = 0; i < removes->count; i++)
  {
    if (ctrip_audit_find_filter_by_name(removes->removes[i]) == -1)
      return (-1);
  }

  return 0;
}

static int ctrip_audit_parse_remove_input(
  const char *remove_str, remove_parse_t *parse)
{
  const char *key = NULL;
  const char *value = NULL;
  const char *current = NULL, *next=NULL;
  int k_len = 0, v_len = 0;

  current = remove_str;
  while (current != NULL)
  {
    ctrip_audit_get_kv_unit(current, &next, &key, &k_len, &value, &v_len);

    remove_parse_add_item(parse, value, v_len);
    
    current = next;
  }
  return 0;
}

inline filter_result_enum  ctrip_audit_filter_event(event_info_t *info, filter_item_t *item
                         , unsigned int event_class)
{
  //host
  if ((info->ip != NULL && strlen(info->ip) != 0
       && item->host_length != 0
       && strncmp(info->ip, item->host, item->host_length) != 0)
    &&
      (info->host != NULL && strlen(info->host) != 0
       && item->host_length != 0
       && strncmp(info->host, item->host, item->host_length) != 0))
    return NOT_AUDIT_EVENT;
  //user
  if (info->user != NULL && strlen(info->user) != 0
      && item->user_length != 0
      && strncmp(info->user, item->user, item->user_length) != 0)
    return NOT_AUDIT_EVENT;

  //event
  if (item->audit_all_event != true)
  {
    if (info->main_class == MYSQL_AUDIT_GENERAL_CLASS)
    {
      if (item->general_events[info->sub_class] != EVENT_SETTED)
        return NOT_AUDIT_EVENT;
    }
    else
    {
      if (item->connection_events[info->sub_class] != EVENT_SETTED)
        return NOT_AUDIT_EVENT;
    }
  }

  if (MYSQL_AUDIT_GENERAL_CLASS == event_class)
  {
    //command & sql_command & query
    //command is toppest level and query is lowest level
    if (item->command_length > 0)
    {
      if (info->command != NULL && strlen(info->command) > 0)
      {
        if (strcasecmp(info->command, item->command) != 0)
        {
          return NOT_AUDIT_EVENT;
        }
      }
    }

    if (item->sql_command_length > 0)
    {
      if (info->sql_command != NULL && strlen(info->sql_command) > 0)
      {
        if (strcasecmp(info->sql_command, item->sql_command) != 0)
        {
          return NOT_AUDIT_EVENT;
        }
      }
    }

    if (item->sql_keyword_length > 0)
    {
      if (info->query != NULL && strlen(info->query) != 0)
      {
        /*char tmp_info_query[MAX_FILTER_SQL_KEYWORD_BUFFER_SIZE];
        char tmp_item_keyword[MAX_FILTER_SQL_KEYWORD_BUFFER_SIZE];

        strncpy(tmp_info_query, info->query
                , MAX_FILTER_SQL_KEYWORD_BUFFER_SIZE);
        strncpy(tmp_item_keyword, item->sql_keyword
                , MAX_FILTER_SQL_KEYWORD_BUFFER_SIZE);
        int i = 0;
        while (tmp_info_query[i])
        {
          tmp_info_query[i] = tolower(tmp_info_query[i]);
          i++;
        }
        i = 0;
        while (tmp_item_keyword[i])
        {
          tmp_item_keyword[i] = tolower(tmp_item_keyword[i]);
          i++;
        }
        */
        if (strcasestr(info->query, item->sql_keyword) == NULL)
        {
          return NOT_AUDIT_EVENT;
        }
      }
    }
  }
  else
  {
  }

  return AUDIT_EVENT;
}

inline filter_result_enum ctrip_audit_filter_event(event_info_t *info
                                                   , unsigned int event_class)
{
  if (filters.size() == 0)
    return NOT_AUDIT_EVENT;

  list<int>::iterator it;
  filter_item_t *item;
  for (it = filters.begin(); it != filters.end(); it++)
  {
    int pos = *it;
    item = filter_items + pos;
    if (ctrip_audit_filter_event(info, item, event_class) == AUDIT_EVENT)
      return AUDIT_EVENT;
  }
  return NOT_AUDIT_EVENT;
}

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

static void ctrip_audit_rule_2_str(filter_item_t *item, char *buffer, int size)
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

static void rules2str_buffer_write(const char *rule, rules2str_buffer_t *buffer)
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

static void ctrip_audit_add_rule_update(
  THD*				thd,		/*!< in: thread handle */
  struct st_mysql_sys_var*	var,		/*!< in: pointer to
							system variable */
  void*				var_ptr,	/*!< out: where the
							formal string goes */
  const void*			save);		/*!< in: immediate result
							from check function */

static int ctrip_audit_add_rule_validate(
  /*=============================*/
  THD*                            thd,    /*!< in: thread handle */
  struct st_mysql_sys_var*        var,    /*!< in: pointer to system
                                            variable */
  void*                           save,   /*!< out: immediate result
                                            for update function */
  struct st_mysql_value*          value);  /*!< in: incoming string */


static void ctrip_audit_remove_rule_update(
  THD*				thd,		/*!< in: thread handle */
  struct st_mysql_sys_var*	var,		/*!< in: pointer to
							system variable */
  void*				var_ptr,	/*!< out: where the
							formal string goes */
  const void*			save);		/*!< in: immediate result
							from check function */

static int ctrip_audit_remove_rule_validate(
  /*=============================*/
  THD*                            thd,    /*!< in: thread handle */
  struct st_mysql_sys_var*        var,    /*!< in: pointer to system
                                            variable */
  void*                           save,   /*!< out: immediate result
                                            for update function */
  struct st_mysql_value*          value);  /*!< in: incoming string */

static void ctrip_audit_set_enable_buffer_update(
  THD*				thd,		/*!< in: thread handle */
  struct st_mysql_sys_var*	var,		/*!< in: pointer to
							system variable */
  void*				var_ptr,	/*!< out: where the
							formal string goes */
  const void*			save);		/*!< in: immediate result
							from check function */

static int ctrip_audit_flush_log_validate(
  /*=============================*/
  THD*                            thd,    /*!< in: thread handle */
  struct st_mysql_sys_var*        var,    /*!< in: pointer to system
                                            variable */
  void*                           save,   /*!< out: immediate result
                                            for update function */
  struct st_mysql_value*          value);  /*!< in: incoming string */

static void ctrip_audit_flush_log_update(
  THD*				thd,		/*!< in: thread handle */
  struct st_mysql_sys_var*	var,		/*!< in: pointer to
							system variable */
  void*				var_ptr,	/*!< out: where the
							formal string goes */
  const void*			save);		/*!< in: immediate result
							from check function */
static int ctrip_audit_set_buffer_size_validate(
  /*=============================*/
  THD*                            thd,    /*!< in: thread handle */
  struct st_mysql_sys_var*        var,    /*!< in: pointer to system
                                            variable */
  void*                           save,   /*!< out: immediate result
                                            for update function */
  struct st_mysql_value*          value);  /*!< in: incoming string */

static void ctrip_audit_set_buffer_size_update(
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
static int ctrip_audit_add_rule_validate(
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

static void ctrip_audit_add_rule_update(
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
static int ctrip_audit_remove_rule_validate(
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

static void ctrip_audit_remove_rule_update(
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

static void ctrip_audit_set_enable_buffer_update(
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

static int ctrip_audit_flush_log_validate(
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

static void ctrip_audit_flush_log_update(
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

static int ctrip_audit_set_buffer_size_validate(
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

static void ctrip_audit_set_buffer_size_update(
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

static int ctrip_audit_reorg_filter_item(filter_item_t *filter_item)
{
  return 0;
}

/* 配置读入，并根据配置构造运行环境 */
static int ctrip_audit_rules_from_config(config_group_t *group)
{
  config_item_t *config_item;
  filter_item_t filter_item;

  ctrip_audit_init_filter_item(&filter_item);

  //从group中构造filter item的内容
  config_item = group->items;
  while (config_item != NULL)
  {
    if (strcasecmp(config_item->key, CTRIP_AUDIT_RULE_KEY_NAME) == 0)
    {
      if (filter_item.name_setted == true)
      {
        //同一组中相同属性被多次指定
        ctrip_audit_logf(CTRIP_AUDIT_LOG_LEVEL_ERROR,
                         "duplicate name setting in group %d",
                         group->number);
        return -1;
      }

      if (ctrip_audit_find_filter_by_name(config_item->value) >= 0)
      {
        //配置文件中出现重名的配置项
        ctrip_audit_logf(CTRIP_AUDIT_LOG_LEVEL_ERROR,
                         "group %s already defined.", config_item->value);
        return -1;
      }

      strcpy(filter_item.name, config_item->value);
      filter_item.name_setted = true;
    }
    else if (strcasecmp(config_item->key, CTRIP_AUDIT_RULE_KEY_HOST) == 0)
    {
      if (filter_item.host_setted == true)
      {
        ctrip_audit_logf(CTRIP_AUDIT_LOG_LEVEL_ERROR,
                         "duplicate host setting in group %d",
                         group->number);
        return -1;
      }

      strcpy(filter_item.host, config_item->value);
      filter_item.host_length = strlen(config_item->value);
      if (ctrip_audit_check_value_valid(
            filter_item.host, filter_item.host_length))
      {
        ctrip_audit_logf(CTRIP_AUDIT_LOG_LEVEL_ERROR,
                         "invalid host setting value in group %d",
                         group->number);
        return -1;
      }

      filter_item.host_setted = true;
    }
    else if (strcasecmp(config_item->key, CTRIP_AUDIT_RULE_KEY_USER) == 0)
    {
      if (filter_item.user_setted == true)
      {
        ctrip_audit_logf(CTRIP_AUDIT_LOG_LEVEL_ERROR,
                         "duplicate user setting in group %d",
                         group->number);
        return -1;
      }

      strcpy(filter_item.user, config_item->value);
      filter_item.user_length = strlen(config_item->value);
      if (ctrip_audit_check_value_valid(
            filter_item.user, filter_item.user_length))
      {
        ctrip_audit_logf(CTRIP_AUDIT_LOG_LEVEL_ERROR,
                         "invalid user setting value in group %d",
                         group->number);
        return -1;
      }

      filter_item.user_setted = true;
    }
    else if (strcasecmp(config_item->key, CTRIP_AUDIT_RULE_KEY_EVENT) == 0)
    {
      if (filter_item.event_setted == true)
      {
        ctrip_audit_logf(CTRIP_AUDIT_LOG_LEVEL_ERROR,
                         "duplicate event setting in group %d",
                         group->number);
        return -1;
      }

      int r = 0;
      int event_len = strlen(config_item->value);
      r = ctrip_audit_parse_event(config_item->value, event_len, &filter_item);
      if (r)
      {
        ctrip_audit_logf(CTRIP_AUDIT_LOG_LEVEL_ERROR,
                         "invalid event setting value in group %d",
                         group->number);
        return -1;
      }

      filter_item.event_setted = true;
    }
    else if (strcasecmp(config_item->key, CTRIP_AUDIT_RULE_KEY_CMD) == 0)
    {
      if (filter_item.command_setted == true)
      {
        ctrip_audit_logf(CTRIP_AUDIT_LOG_LEVEL_ERROR,
                         "duplicate command setting in group %d",
                         group->number);
        return -1;
      }

      if (config_item->value_len >= MAX_FILTER_COMMAND_BUFFER_SIZE)
      {
        ctrip_audit_logf(CTRIP_AUDIT_LOG_LEVEL_ERROR,
                         "too long value for command setting");
        return -1;
      }
      strncpy(filter_item.command
              , config_item->value, config_item->value_len);
      filter_item.command[config_item->value_len] = 0;
      filter_item.command_length = config_item->value_len;
      filter_item.command_setted = true;
    }
    else if (strcasecmp(config_item->key, CTRIP_AUDIT_RULE_KEY_SQL_CMD) == 0)
    {
      if (filter_item.sql_command_setted == true)
      {
        ctrip_audit_logf(CTRIP_AUDIT_LOG_LEVEL_ERROR,
                         "duplicate sql_command setting in group %d",
                         group->number);
        return -1;
      }

      if (config_item->value_len >= MAX_FILTER_SQL_COMMAND_BUFFER_SIZE)
      {
        ctrip_audit_logf(CTRIP_AUDIT_LOG_LEVEL_ERROR,
                         "too long value for sql_command setting in group %d",
                         group->number);
        return -1;
      }
      strncpy(filter_item.sql_command
              , config_item->value, config_item->value_len);
      filter_item.sql_command[config_item->value_len] = 0;
      filter_item.sql_command_length = config_item->value_len;
      filter_item.sql_command_setted = true;
    }
    else if (strcasecmp(config_item->key
                        , CTRIP_AUDIT_RULE_KEY_SQL_KEYWORD) == 0)
    {
      if (filter_item.sql_keyword_setted == true)
      {
        ctrip_audit_logf(CTRIP_AUDIT_LOG_LEVEL_ERROR,
                         "duplicate sql_keyword setting in group %d",
                         group->number);
        return -1;
      }

      if (config_item->value_len >= MAX_FILTER_SQL_KEYWORD_BUFFER_SIZE)
      {
        ctrip_audit_logf(CTRIP_AUDIT_LOG_LEVEL_ERROR,
                         "too long value for sql_keyword setting in group %d",
                         group->number);
        return -1;
      }
      strncpy(filter_item.sql_keyword
              , config_item->value, config_item->value_len);
      filter_item.sql_keyword[config_item->value_len] = 0;
      filter_item.sql_keyword_length = config_item->value_len;
      filter_item.sql_keyword_setted = true;
    }
    else
    {
      //不可识别的内容
      string err_msg = "unknow settings : ";
      err_msg += config_item->key;
      const char *c_err_msg = err_msg.c_str();
      ctrip_audit_logf(CTRIP_AUDIT_LOG_LEVEL_ERROR,
                       c_err_msg);
      return -1;
    }

    config_item = (config_item_t*)config_item->next;
  }
  //进行rule filter item的检查和补充
  int r = ctrip_audit_reorg_filter_item(&filter_item);
  if (r != 0)
    return r;

  //将filter加入
  ctrip_audit_add_filter(&filter_item);

  return (0);
}

static int ctrip_audit_general_from_config(config_group_t *group)
{
  config_item_t *item;
  item = group->items;
  while (item != NULL)
  {
    if (strcasecmp(item->key, CTRIP_AUDIT_GENERAL_SECTION_AUDIT_FILE) == 0)
    {
      strcpy(ctrip_audit_log_file, item->value);
    }
    else if (strcasecmp
             (item->key, CTRIP_AUDIT_GENERAL_SECTION_AUDIT_ERROR_FILE) == 0)
    {
      strcpy(ctrip_audit_error_log_file, item->value);
    }
    else if (strcasecmp
             (item->key, CTRIP_AUDIT_GENERAL_SECTION_AUDIT_ENABLE_BUFFER) == 0)
    {
      if (strcasecmp(item->value, "1") == 0
          || strcasecmp(item->value, "on") == 0)
      {
        enable_buffer = TRUE;
      }
      else if (strcasecmp(item->value, "off") == 0
          || strcasecmp(item->value, "0") == 0)
      {
        enable_buffer = FALSE;
      }
      else
      {
      }
    }
    else
    {
      //不可识别的配置内容
      return 1;
    }

    item = (config_item_t*)item->next;
  }
  return 0;
}

static int ctrip_audit_init_env_from_config(config_t *config)
{
  config_group_t *group;

  ctrip_audit_log_file[0] = 0;
  ctrip_audit_error_log_file[0] = 0;

  group = config->groups;
  while (group != NULL)
  {
    if (strcasecmp(group->name,  CTRIP_AUDIT_RULE_GROUP_NAME) == 0)
    {
      if (ctrip_audit_rules_from_config(group))
      {
        ctrip_audit_logf(CTRIP_AUDIT_LOG_LEVEL_ERROR,
                         "group %d error", group->number);
        return -1;
      }
    }
    else if (strcasecmp(group->name, CTRIP_AUDIT_GENERAL_GROUP_NAME) == 0)
    {
      if (ctrip_audit_general_from_config(group))
        return -1;
    }
    else
    {
      ctrip_audit_logf(CTRIP_AUDIT_LOG_LEVEL_ERROR,
                       "unknown group name : %s", group->name);
      return -1;
    }

    group = (config_group_t*)group->next;
  }

  return (0);
}

static int ctrip_audit_read_config_and_init_env()
{
  config_t *config = NULL;
  char config_file[256];
  int ret;

  sprintf(config_file, "%s%s", opt_plugin_dir, CTRIP_AUDIT_CONFIG_FILE);

  config = config_read(config_file);
  if (config == NULL)
    return (0);

  ret = ctrip_audit_init_env_from_config(config);

  config_destroy(config);

  return (ret);
}

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

static int ctrip_audit_process_general_event(
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

static int ctrip_audit_process_connection_event(
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

static int ctrip_audit_process_parse_event(
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

static int ctrip_audit_process_startup_event(
  MYSQL_THD thd __attribute__((unused))
  , unsigned int event_class
  ,const void *event)
{
  /* const struct mysql_event_server_startup *event_startup=
     (const struct mysql_event_server_startup *) event; */
  number_of_calls_server_startup++;
  return 0;
}

static int ctrip_audit_process_shutdown_event(
  MYSQL_THD thd __attribute__((unused))
  , unsigned int event_class
  ,const void *event)
{
  /* const struct mysql_event_server_shutdown *event_startup=
     (const struct mysql_event_server_shutdown *) event; */
  number_of_calls_server_shutdown++;
  return 0;
}

static int ctrip_audit_process_command_event(
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

static int ctrip_audit_process_query_event(
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

static int ctrip_audit_process_table_access_event(
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

static int ctrip_audit_process_variable_event(
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

/** plugin usage reference */
volatile ulonglong usage_ref = 0;

ulonglong
increase_usage_ref()
{
  ulonglong curr = 0;
  return curr;
}

ulonglong
decrease_usage_ref()
{
  ulonglong curr = 0;
  __sync_fetch_and_add(&usage_ref, 1);
  return curr;
}

/** probe quiting condition */
volatile bool quiting = false;

bool
probe_quiting_condition()
{
  quiting = true;
  return true;
}


/* 插件接口 */
static bool plugin_inited = false;
/*
  Terminate the plugin at server shutdown or plugin deinstallation.

  SYNOPSIS
    ctrip_audit_plugin_deinit()
    Does nothing.

  RETURN VALUE
    0                    success
    1                    failure

*/

static int ctrip_audit_plugin_deinit(void *arg __attribute__((unused)))
{
  if (!plugin_inited)
    return(0);

  if (!probe_quiting_condition())
  {
    return 1;
  }

  ctrip_audit_deinit_lock();

  ctrip_audit_deinit_status();

  ctrip_audit_deinit_variable();

  ctrip_audit_deinit_filter();

  int ret = Logger::FlushNew();
  if (ret)
  {
    ctrip_audit_logf(CTRIP_AUDIT_LOG_LEVEL_ERROR, "flush log error");
  }

  Logger::Deinitialize();

  plugin_inited = false;

  return(0);
}

/*
  Initialize the plugin at server start or plugin installation.

  SYNOPSIS
    ctrip_audit_plugin_init()

  DESCRIPTION
    Does nothing.

  RETURN VALUE
    0                    success
    1                    failure
*/

static int ctrip_audit_plugin_init(void *arg __attribute__((unused)))
{
  switch (0)
  {
  case 0:
    ctrip_audit_init_lock();

    ctrip_audit_init_status();

    ctrip_audit_init_filter();

    if (ctrip_audit_read_config_and_init_env())
      break;

    ctrip_audit_init_variable();

    Logger::Initialize(log_file, error_log_file, enable_buffer);

    int ret = Logger::FlushNew();
    if (ret)
    {
      ctrip_audit_logf(CTRIP_AUDIT_LOG_LEVEL_ERROR, "flush log error");
      break;
    }

    ctrip_audit_logf(CTRIP_AUDIT_LOG_LEVEL_INFO, "plugin initialized.");

    plugin_inited = true;

    return(0);
  }

  //出现错误，销毁环境
  ctrip_audit_plugin_deinit(arg);
  return (1);
}


/*
  SYNOPSIS
    ctrip_audit_notify()
      thd                connection context
      event_class
      event
  DESCRIPTION
*/

/*static void ctrip_audit_notify(MYSQL_THD thd __attribute__((unused)),
                              unsigned int event_class,
                              const void *event)*/
static int ctrip_audit_notify(MYSQL_THD thd,
                             mysql_event_class_t event_class,
                             const void *event)
{
  if (quiting == true)
    return 0;

  number_of_calls++;

  ctrip_audit_process_event(thd, event_class, event);

  //TO DO : error check
  return 0;
}


/*
  Plugin type-specific descriptor
*/

static struct st_mysql_audit ctrip_audit_descriptor=
{
  MYSQL_AUDIT_INTERFACE_VERSION,                    /* interface version    */
  NULL,                                             /* release_thd function */
  ctrip_audit_notify,                                /* notify function      */
  { (unsigned long) MYSQL_AUDIT_GENERAL_ALL,
    (unsigned long) MYSQL_AUDIT_CONNECTION_ALL,
    (unsigned long) MYSQL_AUDIT_PARSE_ALL,
    0, /* This event class is currently not supported. */
    (unsigned long) MYSQL_AUDIT_TABLE_ACCESS_ALL,
    (unsigned long) MYSQL_AUDIT_GLOBAL_VARIABLE_ALL,
    (unsigned long) MYSQL_AUDIT_SERVER_STARTUP_ALL,
    (unsigned long) MYSQL_AUDIT_SERVER_SHUTDOWN_ALL,
    (unsigned long) MYSQL_AUDIT_COMMAND_ALL,
    (unsigned long) MYSQL_AUDIT_QUERY_ALL,
    (unsigned long) MYSQL_AUDIT_STORED_PROGRAM_ALL }
};


/*
  Plugin library descriptor
*/

mysql_declare_plugin(ctrip_audit)
{
  MYSQL_AUDIT_PLUGIN,         /* type                               */
  &ctrip_audit_descriptor,    /* descriptor                         */
  "CTRIP_AUDIT",              /* name, install plugin's plugin_name */
  "Ctrip Corp Jiangyx",       /* author                             */
  "Ctrip audit plugin",       /* description                        */
  PLUGIN_LICENSE_GPL,
  ctrip_audit_plugin_init,    /* init function (when loaded)     */
  ctrip_audit_plugin_deinit,  /* deinit function (when unloaded) */
  0x0001,                     /* version                         */
  ctrip_audit_status,         /* status variables                */
  ctrip_audit_sys_var,        /* system variables                */
  NULL,
  0,
}
mysql_declare_plugin_end;


