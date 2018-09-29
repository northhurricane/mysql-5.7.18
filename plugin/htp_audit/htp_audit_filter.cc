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

extern my_bool _debug_on_;

/*
  writing mysql log
*/
void
ctrip_audit_logf(
  int level,             /*!< in: warning level */
  const char*    format, /*!< printf format */
  ...   //三个点的问题
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

//static mysql_mutex_t LOCK_filter_and_var;
//static bool lock_initialized = false;

int ctrip_audit_init_lock()
{
  mysql_mutex_init(0, &LOCK_filter_and_var, MY_MUTEX_INIT_FAST);
  lock_initialized = true;

  return 0;
}

void ctrip_audit_deinit_lock()
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
//current_used_filter
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
  for (int i = 0; i < MAX_FILTER_CONNECTION_EVENTS; i++)
  {
    item->connection_events[i] = EVENT_UNSETTED;
  }
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
  key=index;
    while (*index != 0)
  {
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
  while (*index != 0)
  {
    if (!ctrip_audit_is_kv_unit_splitter(*index))
      break;
    index++;
  }
  *next = index;
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

static
int
ctrip_audit_remove_rule_check_exist(remove_parse_t *removes)
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

inline filter_result_enum 
ctrip_audit_filter_event(event_info_t *info, filter_item_t *item
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


