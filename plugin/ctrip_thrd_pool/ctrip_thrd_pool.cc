#include <my_sys.h>
#include <string>
#include <mysql/plugin.h>
#include "connection_handler_ctrip.h"

static st_plugin_int *plugin_ptr;

/*
  initialize 
*/
static int ctrip_thrd_pool_init(void *p)
{
  /*仅支持linux下的thread pool功能*/
#if not defined (__linux__)
  return -1;
#endif

  struct st_plugin_int *plugin= (struct st_plugin_int *)p;
  plugin_ptr = plugin;
  Ctrip_connection_handler::init();
  return (0);
}

/*  
*/
static int ctrip_thrd_pool_deinit(void *p)
{
  struct st_plugin_int *plugin= (struct st_plugin_int *)p;
  DBUG_ASSERT(plugin == plugin_ptr);
  Ctrip_connection_handler::deinit();
  return (0);
}

/* Plugin system variables */
#define MIN_THRD_NUM (1)
#define MAX_THRD_NUM (1024 * 64)
#define DEF_CTRIP_WORK_THRD_NUMBER (8)
int ctrip_worker_number = DEF_CTRIP_WORK_THRD_NUMBER;
static MYSQL_SYSVAR_INT(worker_number, ctrip_worker_number
                        , PLUGIN_VAR_READONLY
                        , "work thread number"
                        , NULL
                        , NULL
                        , DEF_CTRIP_WORK_THRD_NUMBER
                        , MIN_THRD_NUM, MAX_THRD_NUM
                        , 0);

#define MIN_TASK_NUM (1)
#define MAX_TASK_NUM (1024 * 64)
#define DEF_CTRIP_TASK_NUMBER (1024)
int ctrip_task_number = DEF_CTRIP_TASK_NUMBER;
static MYSQL_SYSVAR_INT(task_number, ctrip_task_number
                        , PLUGIN_VAR_READONLY
                        , "work thread number"
                        , NULL
                        , NULL
                        , DEF_CTRIP_TASK_NUMBER
                        , MIN_TASK_NUM, MAX_TASK_NUM
                        , 0);

static struct st_mysql_sys_var* ctrip_thrd_pool_system_variables[]= {
  MYSQL_SYSVAR(worker_number)
  , MYSQL_SYSVAR(task_number)
  , NULL
};

static struct st_mysql_show_var ctrip_thrd_pool_status_variables[]= {
    { NullS, NullS, SHOW_LONG, SHOW_SCOPE_GLOBAL }
};

struct st_mysql_daemon ctrip_thrd_pool_info =
{ MYSQL_DAEMON_INTERFACE_VERSION  };

mysql_declare_plugin(ctrip_thrd_pool)
{
  MYSQL_DAEMON_PLUGIN,                /*   type                            */
  &ctrip_thrd_pool_info,              /*   descriptor                      */
  "ctrip_thrd_pool",                  /*   name                            */
  "Ctrip Corporation",                /*   author                          */
  "ctrip connection thread pool",     /*   description                     */
  PLUGIN_LICENSE_GPL,
  ctrip_thrd_pool_init,               /*   init function (when loaded)     */
  ctrip_thrd_pool_deinit,             /*   deinit function (when unloaded) */
  0x0101,                             /*   version                         */
  ctrip_thrd_pool_status_variables,   /*   status variables                */
  ctrip_thrd_pool_system_variables, /*   system variables                */
  NULL,
  0,
}
mysql_declare_plugin_end;
