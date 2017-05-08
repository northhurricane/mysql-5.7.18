#include "client_priv.h"
#include "my_default.h"
/*#include <m_ctype.h>
#include <stdarg.h>
#include <my_dir.h>*/
#include <mysqld_error.h>
#include "welcome_copyright_notice.h"

#include <iostream>
#include <fstream>
#include <string>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <list>

#include "mysql.h"
using namespace std;

static MYSQL mysql;			/* The connection */
static MEM_ROOT hash_mem_root; /* memory object */

static my_bool connected = 0;
static const CHARSET_INFO *charset_info= &my_charset_latin1;
static my_bool tty_password = 0;
//args
static char *opt_host = NULL;
static uint opt_mysql_port=0;
static char * opt_mysql_unix_port=0;
static char *opt_user = NULL;
static char *opt_password = NULL;
static char *opt_input_file = NULL;
static char *opt_filter_user = NULL;

static struct my_option my_long_options[] =
{
  {"help", '?', "Display this help and exit.", 0, 0, 0, GET_NO_ARG, NO_ARG, 0,
   0, 0, 0, 0, 0},
  {"help", 'I', "Synonym for -?", 0, 0, 0, GET_NO_ARG, NO_ARG, 0,
   0, 0, 0, 0, 0},
  {"version", 'V', "Output version information and exit.", 0, 0, 0,
   GET_NO_ARG, NO_ARG, 0, 0, 0, 0, 0, 0},
  {"host", 'h', "Connect to host.", &opt_host,
   &opt_host, 0, GET_STR_ALLOC, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"port", 'P', "Port number to use for connection or 0 for default to, in "
   "order of preference, my.cnf, $MYSQL_TCP_PORT, "
#if MYSQL_PORT_DEFAULT == 0
   "/etc/services, "
#endif
   "built-in default (" STRINGIFY_ARG(MYSQL_PORT) ").",
   &opt_mysql_port,
   &opt_mysql_port, 0, GET_UINT, REQUIRED_ARG, 0, 0, 0, 0, 0,  0},
  {"socket", 'S', "The socket file to use for connection.",
   &opt_mysql_unix_port, &opt_mysql_unix_port, 0, GET_STR_ALLOC,
   REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"user", 'u', "User for login if not current user.", &opt_user,
   &opt_user, 0, GET_STR_ALLOC, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"password", 'p',
   "Password to use when connecting to server. If password is not given it's asked from the tty.",
   0, 0, 0, GET_PASSWORD, OPT_ARG, 0, 0, 0, 0, 0, 0},
  {"filter-user", 'U', "get filter user's flash back SQL.", &opt_filter_user,
   &opt_filter_user, 0, GET_STR_ALLOC, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  { 0, 0, 0, 0, 0, 0, GET_NO_ARG, NO_ARG, 0, 0, 0, 0, 0, 0}
};

typedef char table_name_t[256];
typedef char db_name_t[256];
typedef char column_name_t[256];

struct column_struct
{
  column_name_t name;
  bool is_timestamp;
};
typedef column_struct column_t;

#define COLUMN_SIZE (1024)
struct table_struct
{
  db_name_t db;
  table_name_t name;
  int column_number;
  column_t cols[COLUMN_SIZE];
  table_struct() { column_number = 0; }
};
typedef table_struct table_t;

#define MAX_TABLE_DICT_SIZE (128)
struct table_dict_struct
{
  int number;
  table_t tables[MAX_TABLE_DICT_SIZE];
  table_dict_struct() {number = 0;}
};
typedef table_dict_struct table_dict_t;

#define DEFAULTS_LINE_BUFFER_SIZE (8 * 1024 * 1024)

char line_buffer[DEFAULTS_LINE_BUFFER_SIZE];
uint64_t line_no = 0;
ifstream *ifs = NULL;
ostream *outstream = NULL;

const char *fb_invoker = "###invoker:";
const int fb_invoker_len = strlen(fb_invoker);

const char *fb_flag ="###flashback";
const int fb_flag_len = strlen(fb_flag);

const char *fb_line_start = "###";
const int fb_line_start_len = strlen(fb_line_start);

char user_buffer[256] = {0};
const int user_buffer_len = sizeof(user_buffer);
char host_buffer[512] = {0};
const int host_buffer_len = sizeof(host_buffer);

table_dict_t table_dict;

bool fb_flag_ = false;
inline void set_fb_flag(bool v)
{
  fb_flag_ = v;
}

inline bool get_fb_flag()
{
  return fb_flag_;
}

enum fb_type
{
  FB_INVALID = 0,
  FB_INVOKER,
  FB_FLAG,
  FB_LINE
};
typedef enum fb_type fb_type_t;

enum fb_event
{
  FB_EVENT_INVALID = 0,
  FB_EVENT_INSERT,
  FB_EVENT_DELETE,
  FB_EVENT_UPDATE
};
typedef enum fb_event fb_event_t;

#define CTRIP_WELCOME_COPYRIGHT_NOTICE(first_year) \
  (strcmp(first_year, COPYRIGHT_NOTICE_CURRENT_YEAR) ? \
   "Copyright (c) " first_year ", " COPYRIGHT_NOTICE_CURRENT_YEAR ", " \
   "Ctrip and/or its affiliates. All rights reserved.\n\nCtrip is a " \
   "registered trademark of Ctrip Corporation and/or its\naffiliates. " \
   "Other names may be trademarks of their respective\nowners.\n" : \
   "Copyright (c) " first_year ", Ctrip and/or its affiliates. " \
   "All rights reserved.\n\nCtrip is a registered trademark of " \
   "Ctrip Corporation and/or its\naffiliates. Other names may be " \
   "trademarks of their respective\nowners.\n")

#define VER "0.01"

//static const char *load_default_groups[]= { "mysql","client",0 };

static void usage(int version)
{

  printf("%s  Ver %s Distrib %s, for %s (%s)\n", my_progname, VER,
	MYSQL_SERVER_VERSION, SYSTEM_TYPE, MACHINE_TYPE);

  if (version)
    return;
  puts(CTRIP_WELCOME_COPYRIGHT_NOTICE("1999"));
  printf("Usage: %s [OPTIONS] [database]\n", my_progname);
  /*
    Turn default for zombies off so that the help on how to 
    turn them off text won't show up.
    This is safe to do since it's followed by a call to exit().
  */
  for (struct my_option *optp= my_long_options; optp->name; optp++)
  {
    if (optp->id == OPT_SECURE_AUTH)
    {
      optp->def_value= 0;
      break;
    }
  }
  my_print_help(my_long_options);
  //  print_defaults("my", load_default_groups);
  my_print_variables(my_long_options);
}

my_bool
get_one_option(int optid, const struct my_option *opt MY_ATTRIBUTE((unused)),
	       char *argument)
{
  switch(optid) {
  case 'p':
    tty_password= 1;
    break;
  case 'I':
  case '?':
    usage(0);
    exit(0);
  }
  return 0;
}

static int get_options(int argc, char **argv)
{
  int ho_error;

  if ((ho_error=handle_options(&argc, &argv, my_long_options, get_one_option)))
    exit(ho_error);

  if (argc != 1)
  {
    usage(0);
    exit(1);
  }
  opt_input_file = my_strdup(PSI_NOT_INSTRUMENTED, *argv, MYF(MY_WME));
  if (tty_password)
    opt_password= get_tty_password(NullS);

  return(0);
}

void
stop_for_dbg()
{
  printf("stop_for_dbg\n");
}

static void
init_connection_options(MYSQL *mysql)
{
  /*  my_bool handle_expired= (opt_connect_expired_password || !status.batch) ?
    TRUE : FALSE;

  if (opt_init_command)
    mysql_options(mysql, MYSQL_INIT_COMMAND, opt_init_command);

  if (opt_connect_timeout)
  {
    uint timeout= opt_connect_timeout;
    mysql_options(mysql, MYSQL_OPT_CONNECT_TIMEOUT, (char*) &timeout);
  }

  if (opt_bind_addr)
    mysql_options(mysql, MYSQL_OPT_BIND, opt_bind_addr);

  if (opt_compress)
    mysql_options(mysql, MYSQL_OPT_COMPRESS, NullS);

  if (using_opt_local_infile)
    mysql_options(mysql, MYSQL_OPT_LOCAL_INFILE, (char*) &opt_local_infile);

  SSL_SET_OPTIONS(mysql);

  if (opt_protocol)
    mysql_options(mysql, MYSQL_OPT_PROTOCOL, (char*) &opt_protocol);

#if defined (_WIN32) && !defined (EMBEDDED_LIBRARY)
  if (shared_memory_base_name)
    mysql_options(mysql, MYSQL_SHARED_MEMORY_BASE_NAME, shared_memory_base_name);
#endif

  if (safe_updates)
  {
    char init_command[100];
    sprintf(init_command,
	    "SET SQL_SAFE_UPDATES=1,SQL_SELECT_LIMIT=%lu,MAX_JOIN_SIZE=%lu",
	    select_limit, max_join_size);
    mysql_options(mysql, MYSQL_INIT_COMMAND, init_command);
  }

  mysql_set_character_set(mysql, default_charset);

  if (opt_plugin_dir && *opt_plugin_dir)
    mysql_options(mysql, MYSQL_PLUGIN_DIR, opt_plugin_dir);

  if (opt_default_auth && *opt_default_auth)
    mysql_options(mysql, MYSQL_DEFAULT_AUTH, opt_default_auth);

#if !defined(HAVE_YASSL)
  if (opt_server_public_key && *opt_server_public_key)
    mysql_options(mysql, MYSQL_SERVER_PUBLIC_KEY, opt_server_public_key);
#endif

  if (using_opt_enable_cleartext_plugin)
    mysql_options(mysql, MYSQL_ENABLE_CLEARTEXT_PLUGIN,
                  (char*) &opt_enable_cleartext_plugin);

  mysql_options(mysql, MYSQL_OPT_CONNECT_ATTR_RESET, 0);
  mysql_options4(mysql, MYSQL_OPT_CONNECT_ATTR_ADD, "program_name", "mysql");

  mysql_options(mysql, MYSQL_OPT_CAN_HANDLE_EXPIRED_PASSWORDS, &handle_expired);*/
}

static int
sql_real_connect(const char *host, const char *user, const char *password)
{
  assert(connected == 0);

  mysql_init(&mysql);
  init_connection_options(&mysql);

#ifdef _WIN32
  uint cnv_errors;
  String converted_database, converted_user;
  if (!my_charset_same(&my_charset_utf8mb4_bin, mysql.charset))
  {
    /* Convert user and database from UTF8MB4 to connection character set */
    if (user)
    {
      converted_user.copy(user, strlen(user) + 1,
                          &my_charset_utf8mb4_bin, mysql.charset,
                          &cnv_errors);
      user= (char *) converted_user.ptr();
    }
    if (database)
    {
      converted_database.copy(database, strlen(database) + 1,
                              &my_charset_utf8mb4_bin, mysql.charset,
                              &cnv_errors);
      database= (char *) converted_database.ptr();
    }
  }
#endif

  if (!mysql_real_connect(&mysql, host, user, password,
                          NULL, opt_mysql_port, opt_mysql_unix_port,
                          CLIENT_INTERACTIVE | CLIENT_MULTI_STATEMENTS))
  {
    if(mysql_errno(&mysql) == ER_MUST_CHANGE_PASSWORD_LOGIN)
    {
      fprintf(stdout, "Please use --connect-expired-password option or " \
                           "invoke mysql in interactive mode.\n");
      return -1;
    }
    if ((mysql_errno(&mysql) != CR_CONN_HOST_ERROR &&
         mysql_errno(&mysql) != CR_CONNECTION_ERROR))
    {
      printf("error connect");
    }
    return -1;					// Retryable
  }

#ifdef _WIN32
  /* Convert --execute buffer from UTF8MB4 to connection character set */
  if (!execute_buffer_conversion_done++ &&
      status.line_buff &&
      !status.line_buff->file && /* Convert only -e buffer, not real file */
      status.line_buff->buffer < status.line_buff->end && /* Non-empty */
      !my_charset_same(&my_charset_utf8mb4_bin, mysql.charset))
  {
    String tmp;
    size_t len= status.line_buff->end - status.line_buff->buffer;
    uint dummy_errors;
    /*
      Don't convert trailing '\n' character - it was appended during
      last batch_readline_command() call. 
      Oherwise we'll get an extra line, which makes some tests fail.
    */
    if (status.line_buff->buffer[len - 1] == '\n')
      len--;
    if (tmp.copy(status.line_buff->buffer, len,
                 &my_charset_utf8mb4_bin, mysql.charset, &dummy_errors))
      return 1;

    /* Free the old line buffer */
    batch_readline_end(status.line_buff);

    /* Re-initialize line buffer from the converted string */
    if (!(status.line_buff= batch_readline_command(NULL, (char *) tmp.c_ptr_safe())))
      return 1;
  }
#endif /* _WIN32 */

  charset_info= mysql.charset;
  
  connected=1;

  return 0;
}

const int MAX_RECONNECT_TIME = 5;
static int
sql_connect()
{
  int try_count = 1;

  while (true)
  {
    int error = sql_real_connect(opt_host, opt_user, opt_password);
    if (error > 0)
    {
      if (try_count > MAX_RECONNECT_TIME)
      {
        printf("fail to connect. retry %d times", MAX_RECONNECT_TIME);
        exit (-1);
      }
      try_count++;
    }
    else
    {
      break;
    }
  }
  return 0;
}

uint64_t
read_line()
{
  ifs->getline(line_buffer, sizeof(line_buffer));
  line_no++;
  return 0;
}

bool is_fb_line()
{
  if (strncmp(line_buffer, "###", 3) == 0)
  {
    return true;
  }
  return false;
}

inline bool is_white_char(char c)
{
  if (isspace(c))
    return true;
  return false;
}

bool is_line_empty()
{
  int len = strlen(line_buffer);
  if (len == 0)
    return true;
  for (int i = 0; i < len; i++)
  {
    if (!is_white_char(line_buffer[i]))
      return false;
  }
  return true;
}

void get_invoker()
{
  char *user_ptr;
  user_ptr = line_buffer + fb_invoker_len;
  int user_host_len = strlen(line_buffer) - fb_invoker_len;
  int i;
  for (i = 0; i < user_host_len; i++)
  {
    if (user_ptr[i] == '@')
      break;
  }
  char *host_ptr = user_ptr + i + 1;
  if (i >= user_buffer_len)
  {
    printf("!!!too long invoker user name\n");
    assert(0);
  }
  memcpy(user_buffer, user_ptr, i);
  user_buffer[i] = '\0';
  int host_name_len = strlen(host_ptr);
  if (host_name_len >= host_buffer_len)
  {
    printf("!!!too long invoker host name\n");
    assert(0);
  }
  memcpy(host_buffer, host_ptr, host_name_len);
  host_buffer[host_name_len] = '\0';
}

string build_insert_sql(table_t *table, list<string> &values)
{
  string sql;

  sql.append("insert into ");
  sql.append(table->db);
  sql.append(".");
  sql.append(table->name);
  sql.append(" (");
  //构造插入的列名
  for (int i = 0; i < table->column_number; i++)
  {
    if (i != 0)
      sql.append(", ");
    sql.append(table->cols[i].name);
  }
  sql.append(")");
  //构造插入的值
  sql.append(" values (");
  list<string>::iterator iter;
  iter = values.begin();
  bool first = true;
  int i = 0;
  while (iter != values.end())
  {
    if (!first)
      sql.append(",");
    else
      first = false;
    assert(iter != values.end());
    string value = *iter;
    if (table->cols[i].is_timestamp)
    {
      sql.append("from_unixtime(");
      sql.append(value);
      sql.append(")");
    }
    else
    {
      sql.append(value);
    }
    i++;
    iter++;
  }
  sql.append(");");
  assert(iter == values.end());

  return sql;
}

string build_delete_sql(table_t *table, list<string> &values)
{
  string sql;

  sql.append("delete from ");
  sql.append(table->db);
  sql.append(".");
  sql.append(table->name);
  sql.append(" where ");

  //构造where clause
  list<string>::iterator iter;
  iter = values.begin();
  bool first = true;
  for (int i = 0; i < table->column_number; i++)
  {
    if (!first)
      sql.append(" and ");
    else
      first = false;
    assert(iter != values.end());
    string value = *iter;
    sql.append(table->cols[i].name);
    sql.append("=");
    if (table->cols[i].is_timestamp)
    {
      sql.append("from_unixtime(");
      sql.append(value);
      sql.append(")");
    }
    else
    {
      sql.append(value);
    }
    iter++;
  }
  sql.append(";");
  assert(iter == values.end());
  return sql;
}

string build_update_sql(table_t *table
  , list<string> &set_values
  , list<string> &where_values)
{
  string sql;

  sql.append("update ");
  sql.append(table->db);
  sql.append(".");
  sql.append(table->name);
  sql.append(" set ");

  //构造set clause
  list<string>::iterator iter;
  iter = set_values.begin();
  bool first = true;
  int i = 0;
  for (i = 0; i < table->column_number; i++)
  {
    if (!first)
      sql.append(",");
    else
      first = false;
    string value = *iter;
    assert(iter != set_values.end());
    sql.append(table->cols[i].name);
    sql.append("=");
    if (table->cols[i].is_timestamp)
    {
      sql.append("from_unixtime(");
      sql.append(value);
      sql.append(")");
    }
    else
    {
      sql.append(value);
    }
    iter++;
  }
  assert(iter == set_values.end());

  //构造where clause
  sql.append(" where ");
  iter = where_values.begin();
  first = true;
  for (i = 0; i < table->column_number; i++)
  {
    if (!first)
      sql.append(" and ");
    else
      first = false;
    string value = *iter;
    assert(iter != set_values.end());
    sql.append(table->cols[i].name);
    sql.append("=");
    if (table->cols[i].is_timestamp)
    {
      sql.append("from_unixtime(");
      sql.append(value);
      sql.append(")");
    }
    else
    {
      sql.append(value);
    }
    iter++;
  }
  sql.append(";");
  assert(iter == where_values.end());

  return sql;
}

string get_desc_sql(const char *db, const char *table)
{
  string sql("show columns from ");
  sql.append(db);
  sql.append(".");
  sql.append(table);
  return sql;
}

void get_table_columns(const char *db, const char *table
                       , list<string> &columns, list<bool> &timestamp_flags)
{
  MYSQL_RES *result = NULL;
  MYSQL_ROW row;
  string desc_sql = get_desc_sql(db, table);;

  free_root(&hash_mem_root,MYF(0));

  mysql_query(&mysql, desc_sql.c_str());
  if (!(result = mysql_store_result(&mysql)))
  {
    printf("error query column name");
    exit(-1);
  }
  else
  {
    while ((row=mysql_fetch_row(result)))
    {
      char *str=strdup_root(&hash_mem_root, (char*) row[0]);
      string column_name(str);
      columns.push_back(column_name);
      str = strdup_root(&hash_mem_root, (char*) row[1]);
      if (strcasecmp(str, "timestamp") == 0)
        timestamp_flags.push_back(true);
      else
        timestamp_flags.push_back(false);
    }
  }
}

void add_table_to_dict(table_t *entry, const char *db, const char *table)
{
  list<string> columns;
  list<bool> timestamp_flags;
  get_table_columns(db, table, columns, timestamp_flags);

  list<string>::iterator iter;
  list<bool>::iterator flags_iter;
  iter = columns.begin();
  flags_iter = timestamp_flags.begin();
  int i = 0;
  while (iter != columns.end())
  {
    string col_name = *iter;
    bool is_timestamp = *flags_iter;
    iter++;
    flags_iter++;
    if (i == COLUMN_SIZE)
    {
      printf("too many columns in table %s. Max is %d\n", table, COLUMN_SIZE);
      exit(-1);
    }
    strcpy(entry->cols[i].name, col_name.c_str());
    entry->cols[i].is_timestamp = is_timestamp;
    
    entry->column_number++;
    i++;
  }
  strcpy(entry->db, db);
  strcpy(entry->name, table);
}

table_t*
find_table(const char *db, const char *table)
{
  int i;
  table_t *entry = NULL;
  for (i = 0; i < table_dict.number; i++)
  {
    entry = table_dict.tables + i;
    if (strcasecmp(db, entry->db) == 0 && strcasecmp(table, entry->name) == 0)
      break;
  }
  if (i == MAX_TABLE_DICT_SIZE)
  {
    printf("too many flashback table in table.Max is 128\n");
    assert(0);
  }
  if (entry == NULL)
  {
    entry = table_dict.tables + i;
    add_table_to_dict(entry, db, table);
    table_dict.number++;
  }

  return entry;
}

void
get_insert_values(list<string> &values)
{
  const char * v;
  while (!ifs->eof())
  {
    read_line();
    if (strcmp(line_buffer, "### SET") == 0)
    {
      continue;
    }
    if (!is_fb_line())
      break;
    v = strchr(line_buffer, '=');
    string sv(v + 1);
    values.push_back(sv);
  }
}

void
get_delete_values(list<string> &values)
{
  const char * v;
  while (!ifs->eof())
  {
    read_line();
    if (strcmp(line_buffer, "### WHERE") == 0)
    {
      continue;
    }
    if (!is_fb_line())
      break;
    v = strchr(line_buffer, '=');
    string sv(v + 1);
    values.push_back(sv);
  }
}

void
get_update_values(list<string> &set_values, list<string> &where_values)
{
  const char * v;
  bool in_where = false;
  bool in_set = false;
  while (!ifs->eof())
  {
    read_line();
    if (strcmp(line_buffer, "### WHERE") == 0)
    {
      in_where = true;
      in_set = false;
      continue;
    }
    if (strcmp(line_buffer, "### SET") == 0)
    {
      in_where = false;
      in_set = true;
      continue;
    }
    if (!is_fb_line())
      break;
    v = strchr(line_buffer, '=');
    string sv(v + 1);
    if (in_where)
    {
      where_values.push_back(sv);
    }
    if (in_set)
    {
      set_values.push_back(sv);
    }
  }
}

void
process_insert_event()
{
  const char *ptr = line_buffer + 3;
  int len = strlen(ptr);
  //skip white char befor insert
  for (int i = 0; i < len; i++)
  {
    if (is_white_char(ptr[i]))
      ptr++;
    else
      break;
  }
  ptr += 12; //skip INSERT INTO 

  len = strlen(ptr);
  //skip white char after insert
  for (int i = 0; i < len; i++)
  {
    if (is_white_char(ptr[i]))
      ptr++;
    else
      break;
  }

  int pos = 0;
  const char *db_name = ptr;
  char db[1024];
  len = strlen(db_name);
  assert(*db_name == '`');
  pos = 1;
  while (pos < len)
  {
    if (db_name[pos] == '`')
      break;
    pos++;
  }
  memcpy(db, db_name + 1, pos - 1);
  db[pos - 1] = 0;
  const char *table_name = db_name + pos + 2;
  char table[1024];
  assert(*table_name == '`');
  len = strlen(table_name);
  pos = 1;
  while (pos < len)
  {
    if (table_name[pos] == '`')
      break;
    pos++;
  }
  memcpy(table, table_name + 1, pos - 1);
  table[pos - 1] = 0;

  table_t *t = find_table(db, table);
  assert(t != NULL);

  list<string> values;
  get_insert_values(values);
  string sql = build_insert_sql(t, values);

  //print sql start line
  *outstream << sql << endl;
}

void
process_delete_event()
{
  const char *ptr = line_buffer + 3;
  int len = strlen(ptr);
  //skip white char befor delete
  for (int i = 0; i < len; i++)
  {
    if (is_white_char(ptr[i]))
      ptr++;
    else
      break;
  }
  ptr += 12; //skip DELETE FROM 

  len = strlen(ptr);
  //skip white char after delete from
  for (int i = 0; i < len; i++)
  {
    if (is_white_char(ptr[i]))
      ptr++;
    else
      break;
  }


  int pos = 0;
  const char *db_name = ptr;
  char db[1024];
  len = strlen(db_name);
  assert(*db_name == '`');
  pos = 1;
  while (pos < len)
  {
    if (db_name[pos] == '`')
      break;
    pos++;
  }
  memcpy(db, db_name + 1, pos - 1);
  db[pos - 1] = 0;
  const char *table_name = db_name + pos + 2;
  char table[1024];
  assert(*table_name == '`');
  len = strlen(table_name);
  pos = 1;
  while (pos < len)
  {
    if (table_name[pos] == '`')
      break;
    pos++;
  }
  memcpy(table, table_name + 1, pos - 1);
  table[pos - 1] = 0;

  table_t *t = find_table(db, table);
  assert(t != NULL);

  list<string> values;

  get_delete_values(values);
  string sql = build_delete_sql(t, values);
  *outstream << sql << endl;
}

void
process_update_event()
{
  const char *ptr = line_buffer + 3;
  int len = strlen(ptr);
  //skip white char befor update
  for (int i = 0; i < len; i++)
  {
    if (is_white_char(ptr[i]))
      ptr++;
    else
      break;
  }
  ptr += 6; //skip UPDATE

  len = strlen(ptr);
  //skip white char after update
  for (int i = 0; i < len; i++)
  {
    if (is_white_char(ptr[i]))
      ptr++;
    else
      break;
  }


  int pos = 0;
  const char *db_name = ptr;
  char db[1024];
  len = strlen(db_name);
  assert(*db_name == '`');
  pos = 1;
  while (pos < len)
  {
    if (db_name[pos] == '`')
      break;
    pos++;
  }
  memcpy(db, db_name + 1, pos - 1);
  db[pos - 1] = 0;
  const char *table_name = db_name + pos + 2;
  char table[1024];
  assert(*table_name == '`');
  len = strlen(table_name);
  pos = 1;
  while (pos < len)
  {
    if (table_name[pos] == '`')
      break;
    pos++;
  }
  memcpy(table, table_name + 1, pos - 1);
  table[pos - 1] = 0;

  table_t *t = find_table(db, table);
  assert(t != NULL);

  list<string> set_values, where_values;

  get_update_values(set_values, where_values);
  string sql = build_update_sql(t, set_values, where_values);
  *outstream << sql << endl;
}

fb_event_t
get_fb_event()
{
  const char *ptr = line_buffer + 3;
  int len = strlen(ptr);
  int pos = 0;
  while (pos < len)
  {
    if (is_white_char(ptr[pos]))
      pos++;
    else
      break;
  }
  if (pos == len)
    return FB_EVENT_INVALID;
  if (strncasecmp(ptr + pos, "INSERT", 6) == 0)
    return FB_EVENT_INSERT;
  if (strncasecmp(ptr + pos, "DELETE", 6) == 0)
    return FB_EVENT_DELETE;
  if (strncasecmp(ptr + pos, "UPDATE", 6) == 0)
    return FB_EVENT_UPDATE;

  return FB_EVENT_INVALID;
}

void process_fb_event()
{
  fb_event_t event = get_fb_event();
  switch (event)
  {
  case FB_EVENT_INSERT:
  {
    process_insert_event();
    break;
  }
  case FB_EVENT_DELETE:
  {
    process_delete_event();
    break;
  }
  case FB_EVENT_UPDATE:
  {
    process_update_event();
    break;
  }
  default:
    assert(0);
  }
}

fb_type_t get_fb_type()
{
  if (strncmp(fb_invoker, line_buffer, fb_invoker_len) == 0)
  {
    return FB_INVOKER;
  }
  if (strncmp(fb_flag, line_buffer, fb_flag_len) == 0)
  {
    return FB_FLAG;
  }
  if (strncmp(fb_line_start, line_buffer, fb_line_start_len) == 0)
  {
    return FB_LINE;
  }
  return FB_INVALID;
}

static bool filter_user_matched = false;

void check_filter_user()
{
  if (opt_filter_user == NULL)
  {
    filter_user_matched = true;
  }
  else if (strcasecmp(user_buffer, opt_filter_user) == 0)
  {
    filter_user_matched = true;
  }
  else
  {
    filter_user_matched = false;
  }
}

void process_fb()
{
  fb_type_t type = get_fb_type();
  switch (type)
  {
  case FB_INVOKER:
  {
    get_invoker();
    check_filter_user();
    break;
  }
  case FB_FLAG:
  {
    if (!filter_user_matched)
      break;
    set_fb_flag(true);
    break;
  }
  case FB_LINE:
  {
    if (!filter_user_matched)
      break;
    if (get_fb_flag())
    {
      process_fb_event();
      set_fb_flag(false);
    }
    break;
  }
  default:
    assert(0);
  }
}

static void open_input_file()
{
  //打开opt_input_file所指向的文件
  ifs = new ifstream();
  if (ifs == NULL)
  {
    printf("Out of memory when create ifstream.\n");
    exit(-1);
  }
  ifs->open(opt_input_file);
}

static void close_input_file()
{
  if (ifs != NULL)
    ifs->close();
  ifs = NULL;
}

static void open_output_file()
{
  //指向标准输出
  outstream = &cout;
}

static void close_output_file()
{
  if (outstream != NULL && outstream != &cout)
  {
    ((ofstream*)outstream)->close();
  }
  outstream = NULL;
}

void
gen_fb_sql()
{
  sql_connect();

  open_input_file();
  open_output_file();

  while (!ifs->eof())
  {
    read_line();
    if (is_fb_line())
    {
      process_fb();
    }
  }

  close_input_file();
  close_output_file();
}

int main(int argc,char *argv[])
{
  init_alloc_root(PSI_NOT_INSTRUMENTED, &hash_mem_root, 65535, 0);

  if (get_options(argc, (char **) argv))
  {
    exit(1);
  }

  gen_fb_sql();
  return 0;
}
