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

//operation of 
enum port_op
{
  OP_INVALID = 0,
  OP_EXPORT,
  OP_IMPORT,
};
typedef enum port_op port_op_t;

static MYSQL mysql;			/* The connection */
static MEM_ROOT hash_mem_root; /* memory object */

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
static char *opt_op = NULL;
static char *opt_data_dir = NULL;
static char *opt_file_dir = NULL;
static port_op_t op = OP_INVALID;
static uint opt_lv_size = 128;
static char *opt_lv_name = NULL;
static char *opt_mount_dir = NULL;
static char *opt_lv_data_dir = NULL;
static char *opt_owner = NULL;
static my_bool opt_repl = 1;
static my_bool opt_force = 0;
static my_bool opt_copyonly = 1;
static my_bool opt_ignore = 1;
static my_bool opt_verbose = 0;

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
  {"operation", 'o', "Valid value is export or import.", &opt_op,
   &opt_op, 0, GET_STR_ALLOC, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"datadir", 'd', "MySQL table data directory.", &opt_data_dir,
   &opt_data_dir, 0, GET_STR_ALLOC, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"filedir", 'f', "Directory to store ported type file.", &opt_file_dir,
   &opt_file_dir, 0, GET_STR_ALLOC, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"lvname", 'l', "lvm name.", &opt_lv_name,
   &opt_lv_name, 0, GET_STR_ALLOC, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"lvsize", 's', "lvm size in GiB.", &opt_lv_size,
   &opt_lv_size, 0, GET_UINT, REQUIRED_ARG, 64, 0, 0, 0, 0,
   0},
  {"mount", 'm', "mount lvm dir.", &opt_mount_dir,
   &opt_mount_dir, 0, GET_STR_ALLOC, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"lvmdata", 'L', "Mounted lvm MySQL data dir from which data copied",
   &opt_lv_data_dir,
   &opt_lv_data_dir, 0, GET_STR_ALLOC, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"owner", 'O', "change files' ownership to owner",
   &opt_owner, &opt_owner, 0, GET_STR_ALLOC, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"replication", 'R', "Start replication in importing.",
   &opt_repl, &opt_repl, 0, GET_BOOL, NO_ARG, 1, 0, 0,
   0, 0, 0},
  {"force", 'F', "Remove existed table data when import.",
   &opt_force, &opt_force, 0, GET_BOOL, NO_ARG, 0, 0, 0,
   0, 0, 0},
  {"copyonly", 'c', "When exporting, copy files without lvm actions. "
   "Server will be writable after files copied.",
   &opt_copyonly, &opt_copyonly, 0, GET_BOOL, NO_ARG, 1, 0, 0,
   0, 0, 0},
  {"ignore", 'i', "Ignore error.",
   &opt_ignore, &opt_ignore, 0, GET_BOOL, NO_ARG, 1, 0, 0,
   0, 0, 0},
  {"verbose", 'v', "Print more process infomation.",
   &opt_verbose, &opt_verbose, 0, GET_BOOL, NO_ARG, 0, 0, 0,
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
  case 'o':
    if (strcasecmp(opt_op, "export") == 0)
    {
      op = OP_EXPORT;
    }
    else if (strcasecmp(opt_op, "import") == 0)
    {
      op = OP_IMPORT;
    }
    else
    {
    }
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
  sprintf(buffer , "show tables");
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

bool
get_tables(string *err)
{
  return get_tables_from_db(err);
}

bool
export_check(string *err)
{
  return true;
}

/*
  For data consistency, we must stop slave SQL_THREAD to prevent DML SQL.
*/
bool export_stop_slave_sql(string *err)
{
  //check slave current status
  sprintf(buffer, "SHOW SLAVE STATUS");
  int r = 0;
  if ((r = mysql_query(&mysql, buffer)) != 0)
  {
    return false;
  }

  MYSQL_RES *result = NULL;
  if (!(result = mysql_store_result(&mysql)))
  {
    return false;
  }

  MYSQL_ROW row= mysql_fetch_row(result);
  //result set is empty
  if (row == NULL)
  {
    mysql_free_result(result);
    return true;
  }

  //check SQL_THREAD status
  if (row[11])
  {
    if (!strcmp(row[11],"No"))
    {
      //SQL_THREAD is not running
      mysql_free_result(result);
      return true;
    }
  }
  mysql_free_result(result);

  //stop SQL_THREAD
  sprintf(buffer, "STOP SLAVE SQL_THREAD");
  if ((r = mysql_query(&mysql, buffer)) != 0)
  {
    return false;
  }

  return(true);
}

static int export_show_master_status(string *err)
{
  bool succ = true;
  MYSQL_ROW row;
  MYSQL_RES *result;
  mysql_query(&mysql, "SHOW MASTER STATUS");
  if (!(result = mysql_store_result(&mysql)))
  {
    err->append(mysql_error(&mysql));
    return false;
  }
  sprintf(buffer, "%s/master.info", opt_file_dir);
  FILE *master_info = fopen(buffer, "w+");
  if (master_info == NULL)
  {
    err->append("failed open file ");
    err->append(buffer);
    succ = false;
  }
  else
  {
    row= mysql_fetch_row(result);
    if (row && row[0] && row[1])
    {
      /* SHOW MASTER STATUS reports file and position */
      fprintf(master_info,
              "\n--\n-- Position to start replication or point-in-time "
              "recovery from\n--\n\n");
      fprintf(master_info,
              "CHANGE MASTER TO MASTER_LOG_FILE='%s', MASTER_LOG_POS=%s;\n",
              row[0], row[1]);
    }
    fflush(master_info);
    fclose(master_info);
  }
  mysql_free_result(result);
  return succ;
}

static bool export_set_server_read_only(string *err)
{
  int r = 0;
  r = mysql_query(&mysql, "set global read_only=1;");
  if (r != 0)
  {
    err->append(mysql_error(&mysql));
    return false;
  }

  r = mysql_query(&mysql, "set global super_read_only=1;");
  if (r != 0)
  {
    err->append(mysql_error(&mysql));
    return false;
  }
  return true;
}

static bool export_restore_server_writable(string *err)
{
  char err_buffer[2048];
  int r = mysql_query(&mysql, "set global read_only=0;");
  if (r != 0)
  {
    strcpy(err_buffer, mysql_error(&mysql));
    err->append(err_buffer);
    return false;
  }
  r = mysql_query(&mysql, "set global super_read_only=0;");
  if (r != 0)
  {
    strcpy(err_buffer, mysql_error(&mysql));
    err->append(err_buffer);
    return false;
  }
  return true;
}

static bool export_flush_tables_with_read_lock(string *err)
{
  /*
    flush tables with read lock
    锁定数据库，确保数据的一致性
  */
  int r = mysql_query(&mysql, "FLUSH TABLES");
  if (r != 0)
  {
    err->append(mysql_error(&mysql));
    return false;
  }
  r = mysql_query(&mysql, "FLUSH TABLES WITH READ LOCK");
  if (r != 0)
  {
    err->append(mysql_error(&mysql));
    return false;
  }
  bool succ = export_set_server_read_only(err);
  if (!succ)
    return succ;
  return true;
}

/*
  该部分存在可能的问题，lvcreate中关联的目录是按照携程现有的目录结构所设计。在
  更加通用的环境下，目录的适配没有进行验证。该部分是应该被重点关注改进的。
  dbbackup是我们内部使用目录，是否需要进行灵活性配置，或者将用户屏蔽于该细节
  之外，能否将用户屏蔽于该细节之外？
  /data-backup目录也是如同dbbackup一样，是固定目录
*/
bool
export_snapshot_copy(string *err)
{
  //创建逻辑卷的快照（-s表示快照的意思）
  sprintf(buffer, "sudo lvcreate -L%dG -s -n dbbackup %s > /dev/null 2>&1"
          , opt_lv_size, opt_lv_name);
  if (opt_verbose)
    cout << buffer << endl;
  int r = system(buffer);
  if (r != 0)
  {
    err->append("failed executing ");
    err->append(buffer);
    return false;
  }
  cout << "Create logical volumn successfully." << endl;

  //进行快照的加载
  char lv_pdir[256];
  char *index = opt_lv_name;
  char *last_pos = opt_lv_name;
  while (*index != 0)
  {
    if ( *index == '/' && (*(index + 1) != 0) )
    {
      last_pos = index;
    }
    index++;
  }
  int lv_pdir_len = last_pos - opt_lv_name;
  strncpy(lv_pdir, opt_lv_name, lv_pdir_len);

  //加载
  switch (0)
  {
  case 0:
    sprintf(buffer, "sudo mount %s/dbbackup %s > /dev/null 2>&1"
            , lv_pdir, opt_mount_dir);
    if (opt_verbose)
      cout << buffer << endl;
    r = system(buffer);
    if (r == 0) //mount success
      break;
    sprintf(buffer, "sudo mount -o nouuid %s/dbbackup %s > /dev/null 2>&1"
            , lv_pdir, opt_mount_dir);
    if (opt_verbose)
      cout << buffer << endl;
    r = system(buffer);
    if (r != 0)
    {
      err->append("failed executing ");
      err->append(buffer);
      return false;
    }
    break;
  }
  cout << "mount logical volumn successfully." << endl;

  //拷贝数据
  sprintf(buffer, "cp %s/* %s > /dev/null 2>&1"
          , opt_lv_data_dir, opt_file_dir);
  if (opt_verbose)
    cout << buffer << endl;
  r = system(buffer);
  sprintf(buffer, "rm %s/*.frm > /dev/null 2>&1", opt_file_dir);
  if (opt_verbose)
    cout << buffer << endl;
  r = system(buffer);
  cout << "Copy snapshot successfully." << endl;

  //恢复写状态
  export_restore_server_writable(err);

  //umount/lvremove
  sprintf(buffer, "sudo umount %s > /dev/null 2>&1", opt_mount_dir);
  if (opt_verbose)
    cout << buffer << endl;
  r = system(buffer);
  if (r == 0)
    cout << "umount logical volumn successfully." << endl;
  else
    cout << "umount logical volumn failed" << endl;
  sprintf(buffer, "sudo lvremove -f %s/dbbackup > /dev/null 2>&1", lv_pdir);
  if (opt_verbose)
    cout << buffer << endl;
  r = system(buffer);
  if (r == 0)
    cout << "Romove logical volumn successfully." << endl;
  else
    cout << "Romove logical volumn failed." << endl;
  return true;
}

bool
export_copyonly(string *err)
{
  //拷贝数据
  bool succ = true;
  sprintf(buffer, "cp %s/* %s > /dev/null 2>&1"
          , opt_data_dir, opt_file_dir);
  if (opt_verbose)
    cout << buffer << endl;
  int r = system(buffer);
  if (r != 0)
  {
    err->append("Failed copy data files.");
    succ = false;
  }
  else
  {
    sprintf(buffer, "rm %s/*.frm > /dev/null 2>&1", opt_file_dir);
    if (opt_verbose)
      cout << buffer << endl;
    r = system(buffer);
    cout << "Copy only successfully." << endl;
  }

  //恢复写状态
  export_restore_server_writable(err);
  return succ;
}

bool
export_single_table(const char *table_name)
{
  int r = 0;
  //锁定表，并生成.cfg文件
  sprintf(buffer, "FLUSH TABLES %s FOR EXPORT;", table_name);
  r = mysql_query(&mysql, buffer);
  if (r != 0)
    return false;
  
  MYSQL_RES *result = NULL;
  MYSQL_ROW row;
  sprintf(buffer , "show create table %s", table_name);
  if ((r = mysql_query(&mysql, buffer)) != 0)
    return false;
  if (!(result = mysql_store_result(&mysql)))
  {
    return false;
  }
  else
  {
    row=mysql_fetch_row(result);
    char *table_sql = strdup_root(&hash_mem_root, (char*) row[1]);
    char table_file[512];
    sprintf(table_file, "%s/%s.def", opt_file_dir, table_name);
    FILE *f = fopen(table_file, "w");
    if (f == NULL)
    {
      printf("failed opening file %s", table_file);
      return false;
    }
    fprintf(f, "%s", table_sql);
    fclose(f);
    mysql_free_result(result);
  }

  //拷贝cfg文件
  sprintf(buffer, "cp %s/%s.cfg %s > /dev/null 2>&1"
          , opt_data_dir, table_name, opt_file_dir);
  if (opt_verbose)
    cout << buffer << endl;
  r = system(buffer);
  if (r != 0)
    return false;

  //清除锁，否则在下一次的flush将会报告错误
  sprintf(buffer, "UNLOCK TABLES;");
  r = mysql_query(&mysql, buffer);
  if (r != 0)
    return false;

  return true;
}

bool
export_tables(string *err)
{
  list<char*>::iterator iter;
  iter = tables.begin();
  char *table_name = NULL;
  int exported_table_count = 0;
  while (iter != tables.end())
  {
    table_name = *iter;
    bool succ;
    succ = export_single_table(table_name);
    if (succ)
    {
      exported_table_count++;
      printf("table %s exported\n", table_name);
    }
    else
    {
      printf("table %s exporting failed\n", table_name);
    }
    iter++;
  }
  printf("totally %d tables exported.\n", exported_table_count);

  bool succ = true;
  if (!opt_copyonly)
    succ = export_snapshot_copy(err);
  else
    succ = export_copyonly(err);
  if (!succ)
    return false;
  return true;
}

static void
export_clean()
{
}

bool
do_export()
{
  string err;
  bool succ = true;
  switch (0)
  {
  case 0:
    succ = export_flush_tables_with_read_lock(&err);
    if (!succ)
      break;
    succ = export_show_master_status(&err);
    if (!succ)
      break;
    succ = export_check(&err);
    if (!succ)
      break;
    succ = export_tables(&err);
    if (!succ)
      break;
    break;
  }
  export_clean();
  return succ;
}

bool
import_check(string *err)
{
  return true;
}

table_buffer_t file_table_buffer;
//在给定的opt_file_dir中获取文件数，通过合tables变量的组合，确定倒入的表
list<char*> file_tables;

bool
import_get_file_tables(string *err)
{
  int table_count = 0;
  
  struct dirent *ptr = NULL;
  DIR *dir = NULL;
  dir=opendir(opt_file_dir);
  if (dir == NULL)
  {
    sprintf(buffer, "Directory %s does not exist.", opt_file_dir);
    err->append(buffer);
    return false;
  }
  while((ptr=readdir(dir)) != NULL)
  {
    //跳过'.'和'..'两个目录
    if(ptr->d_name[0] == '.')
      continue;
    //printf("%s\n",ptr->d_name);
    if (strstr(ptr->d_name, ".def") != NULL)
    {
      table_count++;
      if (table_count > MAX_TABLE_BUFFER_SIZE)
      {
        sprintf(buffer, "max tables can be processed is %d. Tables in current "
                "database exceed the limit of mysqlphyport. "
                , MAX_TABLE_BUFFER_SIZE);
        err->append(buffer);
        return false;
      }
      int len = strlen(ptr->d_name);
      strncpy(file_table_buffer.tables[table_count].name
              , ptr->d_name, len - 4);
      table_buffer.number++;
      file_tables.push_back(file_table_buffer.tables[table_count].name);
    }
  }
  closedir(dir);
  return true;
}

bool
import_do_cp_n_alter(const char *table_name)
{
  int r = 0;

  //文件拷贝
  //普通表/以及.def文件的拷贝
  sprintf(buffer, "sudo cp %s/%s.* %s > /dev/null 2>&1"
          , opt_file_dir, table_name, opt_data_dir);
  if (opt_verbose)
    cout << buffer << endl;
  r = system(buffer);
  if (r != 0)
    return false;
  //分区表
  sprintf(buffer, "sudo cp %s/%s#P#* %s > /dev/null 2>&1"
          , opt_file_dir, table_name, opt_data_dir);
  if (opt_verbose)
    cout << buffer << endl;
  r = system(buffer);

  //修改文件的所有者
  if (opt_owner != NULL)
  {
    sprintf(buffer, "sudo chown %s %s/%s.* > /dev/null 2>&1"
            , opt_owner, opt_data_dir, table_name);
    if (opt_verbose)
      cout << buffer << endl;
    r = system(buffer);
    if (r != 0)
      return false;
    sprintf(buffer, "sudo chown %s %s/%s#P#* > /dev/null 2>&1"
            , opt_owner, opt_data_dir, table_name);
    if (opt_verbose)
      cout << buffer << endl;
    r = system(buffer);
  }

  //导入数据文件
  sprintf(buffer, "ALTER TABLE %s IMPORT TABLESPACE;", table_name);
  r = mysql_query(&mysql, buffer);
  if (r != 0)
    return false;

  return true;
}

static
bool
import_check_table_exist(const char *table_name)
{
  list<char*>::iterator iter;
  char *db_table_name = NULL;
  bool table_exist = false;
  iter = tables.begin();
  while (iter != tables.end())
  {
    db_table_name = *iter;
    if (strcmp(table_name, db_table_name) == 0)
    {
      table_exist = true;
      break;
    }
    iter++;
  }
  return table_exist;
}

bool
import_single_table(const char *table_name)
{
  bool table_exist = import_check_table_exist(table_name);
  bool do_it = false;
  if (table_exist)
  {
    if (opt_force != 1)
    {
      //询问是否覆盖原有表
      string answer;
      cout << "table " << table_name << " existed. Import it?(y/n)" << endl;
      cin >> answer;
      if (strcasecmp("y", answer.c_str()) == 0 ||
          strcasecmp("yes", answer.c_str()) == 0)
      {
        do_it = true;
      }
      else
      {
        cout << "skip table " << table_name << " import." << endl;
      }
    }
  }
  else
  {
    //未指定倒入表，所以是整库导入，导入当前的文件表
    //在数据库中创建该表
    int r = 0;
    sprintf(buffer, "%s/%s%s", opt_file_dir, table_name, ".def");
    FILE *f = fopen(buffer, "r");
    if (f == NULL)
    {
      printf("failed opening file %s", buffer);
      return false;
    }
    memset(buffer, 0, sizeof(buffer));
    fread(buffer, 1, sizeof(buffer), f);
    fclose(f);
    r = mysql_query(&mysql, buffer);
    if (r != 0)
      return false;
    do_it = true;
  }
  if (do_it)
  {
    int r = 0;
    //锁定表，并生成.cfg文件
    sprintf(buffer, "ALTER TABLE %s DISCARD TABLESPACE;", table_name);
    r = mysql_query(&mysql, buffer);
    if (r != 0)
      return false;

    bool succ = true;
    succ = import_do_cp_n_alter(table_name);
    if (!succ)
    {
      char err_buffer[2048];
      strcpy(err_buffer, mysql_error(&mysql));
      //导出文件与的元信息不一致
      if (strstr(err_buffer, "and the meta-data file has 0x1"))
      {
        sprintf(buffer, "ALTER TABLE %s row_format=compact;", table_name);
        r = mysql_query(&mysql, buffer);
        if (r != 0)
        {
          return false;
        }
        succ = import_do_cp_n_alter(table_name);
        if (!succ)
          return succ;
      }
    }

    //清除工具所用的.def文件
    sprintf(buffer, "sudo rm %s/%s.def  > /dev/null 2>&1"
            , opt_data_dir, table_name);
    if (opt_verbose)
      cout << buffer << endl;
    r = system(buffer);
  }
  
  return true;
}

/*
  进行主从复制的开启。
*/
bool
import_start_binlog_repl(string *err)
{
  int r = 0;
  sprintf(buffer, "%s/master.info", opt_file_dir);
  FILE *f = fopen(buffer, "r");
  if (f == NULL)
  {
    err->append("File master.info does not exist.");
    return false;
  }
  memset(buffer, 0, sizeof(buffer));
  fread(buffer, 1, sizeof(buffer), f);
  fclose(f);
  r = mysql_query(&mysql, buffer);
  if (r != 0)
  {
    strcpy(buffer, mysql_error(&mysql));
    err->append(buffer);
    return false;
  }
  sprintf(buffer, "start slave;");
  r = mysql_query(&mysql, buffer);
  if (r != 0)
  {
    strcpy(buffer, mysql_error(&mysql));
    err->append(buffer);
    return false;
  }
  return true;
}

/*
  导入表数据
*/
bool
import_tables(string *err)
{
  bool succ = true;

  list<char*>::iterator iter;
  iter = file_tables.begin();
  char *table_name = NULL;
  while (iter != file_tables.end())
  {
    table_name = *iter;
    succ = import_single_table(table_name);
    if (!succ)
    {
      sprintf(buffer, "table %s importing failed.\n", table_name);
      cout << buffer << endl;
      if (opt_ignore != 1)
        break;
    }
    else
    {
      sprintf(buffer, "table %s imported.\n", table_name);
      cout << buffer << endl;
    }
    iter++;
  }

  //启动复制分发
  if (opt_repl)
  {
    succ = import_start_binlog_repl(err);
    if (!succ)
    {
      printf("%s", err->c_str());
    }
  }
  return true;
}

/*
  import database
  导入操作依赖于导出的.def/.cfg/.ibd文件，导入操作会根据.def文件，确定需要导入
  的数据表。
*/
bool
do_import()
{
  string err;
  bool succ = true;
  switch (0)
  {
  case 0:
    succ = import_check(&err);
    if (!succ)
      break;
    succ = import_get_file_tables(&err);
    if (!succ)
      break;
    succ = import_tables(&err);
    break;
  }
  return succ;
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
args_export_check(string *err)
{
  if (opt_copyonly != 1)
  {
    if (opt_lv_name == NULL || strlen(opt_lv_name) == 0)
    {
      err->append("lvname must be setted.");
      return false;
    }
    if (opt_mount_dir == NULL || strlen(opt_mount_dir) == 0)
    {
      err->append("mout must be setted.");
      return false;
    }
    if (opt_lv_data_dir == NULL || strlen(opt_lv_data_dir) == 0)
    {
      err->append("lvmdata must be setted.");
      return false;
    }
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
  if (opt_data_dir == NULL || strlen(opt_data_dir) == 0)
  {
    err->append("datadir must be setted");
    return false;
  }
  if (opt_file_dir == NULL || strlen(opt_file_dir) == 0)
  {
    err->append("filedir must be setted");
    return false;
  }
  bool succ = true;
  if (op == OP_EXPORT)
  {
    succ = args_export_check(err);
    if (!succ)
      return false;
  }
  else
  {
    //do nothing
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
  if (op == OP_INVALID)
  {
    printf("invalid operation input.Valid value is export or import");
    exit(1);
  }

  string err;
  
  bool succ = args_check(&err);
  if (!succ)
  {
    cout << err << endl;
    exit(1);
  }

  sql_connect();
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

  if (op == OP_EXPORT)
    succ = do_export();
  else
    succ = do_import();
  if (!succ)
  {
    cout << err << endl;
    exit(1);
  }

  return 0;
}
