/**************************************************//**
@file client/ctriparchive.cc

features
1、batch delete table rows.
2、log deleted rows to file

Created 05/07/2017 Jiangy Yuxiang
*******************************************************/
#include "client_priv.h"
#include "my_default.h"
#include <mysqld_error.h>
#include "welcome_copyright_notice.h"

#include <iostream>
#include <fstream>
#include <string>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <list>
#include <dirent.h>

#include "mysql.h"
using namespace std;

static void
stop_for_dbg()
{
  cout << "";
}

static MYSQL mysql;			/* The connection */
static MEM_ROOT hash_mem_root; /* memory object */

#define DEF_ARCHIVE_BATCH_NUMBER (1000)

static my_bool connected = 0;
static const CHARSET_INFO *charset_info= &my_charset_latin1;
static my_bool tty_password = 0;
//args
static char *opt_host = NULL;
static uint opt_mysql_port=0;
static char *opt_mysql_unix_port=0;
static char *opt_user = NULL;
static char *opt_db = NULL;
static char *opt_password = NULL;

static my_bool opt_backup = 0;
static char *opt_file_dir = NULL;
static uint opt_batch_number = DEF_ARCHIVE_BATCH_NUMBER;
static char *opt_clause = NULL;

static my_bool opt_verbose = 0;

//server version
static char svr_version[64];
//server instance read_only variable value
static bool status_read_only = false;
//server instance supper_read_only variable value
static bool status_supper_read_only = false;

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
  {"db", 'D', "porting database.", &opt_db,
   &opt_db, 0, GET_STR_ALLOC, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"password", 'p',
   "Password to use when connecting to server. If password is not given it's asked from the tty.",
   0, 0, 0, GET_PASSWORD, OPT_ARG, 0, 0, 0, 0, 0, 0},
  {"clause", 'c', "Clause using for filter data.", &opt_clause,
   &opt_clause, 0, GET_STR_ALLOC, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"verbose", 'v', "Print more process infomation.",
   &opt_verbose, &opt_verbose, 0, GET_BOOL, NO_ARG, 0, 0, 0,
   0, 0, 0},
  {"filedir", 'f', "Directory to store ported type file.", &opt_file_dir,
   &opt_file_dir, 0, GET_STR_ALLOC, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"backup", 'b', "Backup deleted rows.",
   &opt_backup, &opt_backup, 0, GET_BOOL, NO_ARG, 0, 0, 0,
   0, 0, 0},
  { 0, 0, 0, 0, 0, 0, GET_NO_ARG, NO_ARG, 0, 0, 0, 0, 0, 0}
};

char buffer[1024 * 1024];

typedef char table_name_t[256];
typedef char db_name_t[256];

struct table_struct
{
  table_name_t name;
};
typedef table_struct table_t;

#define MAX_TABLE_BUFFER_SIZE (1024 * 64)
struct table_buffer_struct
{
  int number;
  table_t tables[MAX_TABLE_BUFFER_SIZE];
  table_buffer_struct() {number = 0;}
};
typedef table_buffer_struct table_buffer_t;
table_buffer_t table_buffer;

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

  if (argc != 0)
  {
    usage(0);
    exit(1);
  }
  if (tty_password)
    opt_password= get_tty_password(NullS);

  return(0);
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
    if (error != 0)
    {
      if (try_count > MAX_RECONNECT_TIME)
      {
        printf("fail to connect. retry %d times\n", MAX_RECONNECT_TIME);
        printf("%s\n", mysql_error(&mysql));
        exit (-1);
      }
      try_count++;
    }
    else
    {
      break;
    }
  }

  sprintf(buffer, "set names utf8mb4");
  int r = 0;
  if ((r = mysql_query(&mysql, buffer)) != 0)
  {
    cout << mysql_error(&mysql);
  }

  return 0;
}

static bool
get_server_version(string *err)
{
  MYSQL_RES *result = NULL;
  MYSQL_ROW row;
  sprintf(buffer , "select version();");
  mysql_query(&mysql, buffer);
  if (!(result = mysql_store_result(&mysql)))
  {
    err->append("failed when get tables from database.");
    strcpy(buffer, mysql_error(&mysql));
    err->append(buffer);
    return false;
  }
  else
  {
    row=mysql_fetch_row(result);
    if (row == NULL)
    {
      err->append("failed get version.");
      mysql_free_result(result);
      return false;
    }
    const char *version = row[0];
    const char *pos = version;
    unsigned int idx = 0;
    while (pos[0] != '-' && idx < sizeof(svr_version))
    {
      svr_version[idx] = pos[0];
      idx++;
      pos++;
    }
    svr_version[idx] = 0;

    mysql_free_result(result);

    if (strstr(svr_version, "5.7") || strstr(svr_version, "5.6"))
      return true;

    err->append("unsupportted version ");
    err->append(version);
    return false;
  }
}

static bool
get_svr_read_only(string *err)
{
  MYSQL_ROW row;
  MYSQL_RES *result = NULL;

  if (mysql_query(&mysql, "show global variables like 'read_only';") ||
    !(result = mysql_store_result(&mysql)))
  {
    err->append(mysql_error(&mysql));
    return false;
  }
  row= mysql_fetch_row(result);
  if (row)
  {
    if (row[1] && strcasecmp(row[1], "ON") == 0)
    {
      status_read_only = true;
    }
  }
  mysql_free_result(result);

  result  = NULL;
  //super_read_only intruduced in 5.7.18. For lower version, 
  if (mysql_query(&mysql, "show global variables like 'supper_read_only';") ||
      !(result = mysql_store_result(&mysql)))
  {
    err->append(mysql_error(&mysql));
    return false;
  }
  row= mysql_fetch_row(result);
  if (row)
  {
    if (row[1] && strcasecmp(row[1], "ON") == 0)
    {
      status_supper_read_only = true;
    }
  }
  mysql_free_result(result);

  return true;
}

/*记录数据库中的表。
导出时，按照该列表逐个导出表数据。
导入时，参照该列表确认是否存在导入表在数据库中。
*/
static list<char*> tables;
bool
get_tables_from_db(string *err)
{
  MYSQL_RES *result = NULL;
  MYSQL_ROW row;
  sprintf(buffer , "show tables;");
  mysql_query(&mysql, buffer);
  if (!(result = mysql_store_result(&mysql)))
  {
    err->append("failed when get tables from database.");
    strcpy(buffer, mysql_error(&mysql));
    err->append(buffer);
    return false;
  }
  else
  {
    int table_count = 0;
    while ((row=mysql_fetch_row(result)))
    {
      char *table_name = strdup_root(&hash_mem_root, (char*) row[0]);
      table_count++;
      if (table_count > MAX_TABLE_BUFFER_SIZE)
      {
        sprintf(buffer, "max tables can be processed is %d. Tables in current "
                "database exceed the limit of mysqlphyport. "
                , MAX_TABLE_BUFFER_SIZE);
        err->append(buffer);
        mysql_free_result(result);
        return false;
      }
      table_buffer.number++;
      strcpy(table_buffer.tables[table_count].name, table_name);
      tables.push_back(table_buffer.tables[table_count].name);
    }
    mysql_free_result(result);
  }

  return true;
}

//tables from options
//list<char*> opt_tables;
/*static bool
get_option_tables()
{
}*/

bool
get_tables(string *err)
{
  return get_tables_from_db(err);
}

/*
  Setting database
*/
bool
set_database(string *err)
{
  sprintf(buffer, "use %s", opt_db);
  if (mysql_query(&mysql, buffer))
  {
    sprintf(buffer, "Error in setting database %s.", opt_db);
    err->append(buffer);
    err->append(mysql_error(&mysql));
    return false;
  }
  return true;
}

bool
args_check(string *err)
{
  if (opt_db == NULL || strlen(opt_db) == 0)
  {
    err->append("MySQL database must be setted");
    return false;
  }

  return true;
}

static bool
batch_delete_table(MYSQL *mysql, const char *table_name
                   , const char * primary_colname
                   , const char *where_clause
                   , int *del_count, string *err)
{
  char buffer[4096];
  char where_buffer[4096] = {0};

  DBUG_ASSERT(del_count != NULL);

  if (where_clause != NULL)
  {
    sprintf(where_buffer, " where %s", where_clause);
  }

  if (opt_backup)
    sprintf(buffer, "select * from `%s` %s limit %d;"
            , table_name, where_buffer, opt_batch_number);
  else
    sprintf(buffer, "select %s from `%s` %s limit %d;"
            , primary_colname, table_name, where_buffer, opt_batch_number);

  int r = mysql_query(mysql, buffer);
  if (r != 0)
  {
    err->append(mysql_error(mysql));
    return false;
  }
  MYSQL_RES *result = NULL;
  if (!(result = mysql_store_result(mysql)))
  {
    strcpy(buffer, mysql_error(mysql));
    err->append(buffer);
    return false;
  }
  else
  {
    MYSQL_ROW row;
    string del_clause;
    row=mysql_fetch_row(result);
    bool first = true;
    del_clause.append("in (");
    while (row != NULL)
    {
      if (first)
      {
        del_clause.append(row[0]);
      }
      else
      {
        del_clause.append(",");
        del_clause.append(row[0]);
      }

      if (opt_backup)
      {
        //build insert sql for restore
      }
    }
    del_clause.append(";");
    mysql_free_result(result);

    string sql;
    sql.append("delete from ");
    sql.append(table_name);
    sql.append(" where ");
    sql.append(primary_colname);
    sql.append(del_clause);

    r = mysql_query(mysql, buffer);
    if (r != 0)
    {
      err->append(mysql_error(mysql));
      return false;
    }
  }
  
  return true;
}

static bool
batch_delete(MYSQL *mysql, const char *clause, string *err)
{
  list<char*>::iterator iter;
  iter = tables.begin();
  char *table_name = NULL;
  int table_count = 0;
  bool succ;
  int del_count;
  while (iter != tables.end())
  {
    table_name = *iter;
    succ = batch_delete_table(mysql, table_name, NULL
                              , clause, &del_count, err);
    table_count++;
    iter++;
  }
  return true;
}

int main(int argc,char *argv[])
{
  init_alloc_root(PSI_NOT_INSTRUMENTED, &hash_mem_root, 65535, 0);

  if (get_options(argc, (char **) argv))
  {
    exit(1);
  }

  if (false)
    stop_for_dbg();

  string err;
  bool succ = args_check(&err);
  if (!succ)
  {
    cout << err << endl;
    exit(1);
  }

  sql_connect();
  succ = get_server_version(&err);
  if (!succ)
  {
    cout << err << endl;
    exit(1);
  }
  succ = get_svr_read_only(&err);
  if (!succ)
  {
    cout << err << endl;
    exit(1);
  }
  succ = set_database(&err);
  if (!succ)
  {
    cout << err << endl;
    exit(1);
  }

  succ = get_tables(&err);
  if (!succ)
  {
    cout << err << endl;
    exit(1);
  }

  succ = batch_delete(&mysql, opt_clause, &err);
  if (!succ)
  {
    cout << err << endl;
    exit(1);
  }

  return 0;
}
