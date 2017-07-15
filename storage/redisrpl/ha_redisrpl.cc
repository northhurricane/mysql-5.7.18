/* Copyright (c) 2005, 2016, Oracle and/or its affiliates. All rights reserved.

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */


#define MYSQL_SERVER 1
#include "probes_mysql.h"
#include "ha_redisrpl.h"
#include "sql_class.h"                          // THD, SYSTEM_THREAD_SLAVE_*

#include <dlfcn.h>
#include "hiredis.h"

//////////////////////////////////////////
typedef redisContext* (*redisConnect_func_t)(const char *ip, int port);
typedef void *(*redisCommand_func_t)(redisContext *c, const char *format, ...);
typedef void (*freeReplyObject_func_t)(void *reply);

struct redis_funcs_struct
{
  redisConnect_func_t redisConnect_func;
  redisCommand_func_t redisCommand_func;
  freeReplyObject_func_t freeReplyObject_func;
};
typedef struct redis_funcs_struct redis_funcs_t;
static redis_funcs_t redis_funcs;
static redisContext *ctx = NULL;

bool
hiredis_connect()
{
  ctx = redis_funcs.redisConnect_func("127.0.0.1", 6379);
  if (ctx == NULL)
    return false;
  return true;
}

bool
hiredis_command(redisContext *ctx, char *cmd)
{
  redisReply *reply;
  reply = (redisReply*)
             redis_funcs.redisCommand_func(ctx, cmd);
  redis_funcs.freeReplyObject_func(reply);

  return true;
}

static void *libhiredis = NULL;
static bool load_hiredis()
{
  libhiredis = dlopen("libhiredis.so", RTLD_NOW);
  if(libhiredis == NULL)
    return false;

  redis_funcs.redisConnect_func
  = (redisConnect_func_t)dlsym(libhiredis, "redisConnect");
  if (redis_funcs.redisConnect_func == NULL)
    return false;

  redis_funcs.redisCommand_func
  = (redisCommand_func_t)dlsym(libhiredis, "redisCommand");
  if (redis_funcs.redisCommand_func == NULL)
    return false;

  redis_funcs.freeReplyObject_func
  = (freeReplyObject_func_t)dlsym(libhiredis, "freeReplyObject");
  if (redis_funcs.freeReplyObject_func == NULL)
    return false;

  hiredis_connect();

  return true;
}

static void unload_hiredis()
{
  DBUG_ASSERT(libhiredis != NULL);
  dlclose(libhiredis);
}

//////////////////////////////////////////

static PSI_memory_key bh_key_memory_blackhole_share;

static bool is_slave_applier(THD *thd)
{
  return thd->system_thread == SYSTEM_THREAD_SLAVE_SQL ||
    thd->system_thread == SYSTEM_THREAD_SLAVE_WORKER;
}

/* Static declarations for handlerton */

static handler *blackhole_create_handler(handlerton *hton,
                                         TABLE_SHARE *table,
                                         MEM_ROOT *mem_root)
{
  return new (mem_root) ha_redisrpl(hton, table);
}


/* Static declarations for shared structures */

static mysql_mutex_t blackhole_mutex;
static HASH blackhole_open_tables;

static st_blackhole_share *get_share(const char *table_name);
static void free_share(st_blackhole_share *share);

/*****************************************************************************
** BLACKHOLE tables
*****************************************************************************/

ha_redisrpl::ha_redisrpl(handlerton *hton,
                           TABLE_SHARE *table_arg)
  :handler(hton, table_arg)
{}


static const char *ha_redisrpl_exts[] = {
  NullS
};

const char **ha_redisrpl::bas_ext() const
{
  return ha_redisrpl_exts;
}

int ha_redisrpl::open(const char *name, int mode, uint test_if_locked)
{
  DBUG_ENTER("ha_redisrpl::open");

  if (!(share= get_share(name)))
    DBUG_RETURN(HA_ERR_OUT_OF_MEM);

  thr_lock_data_init(&share->lock, &lock, NULL);
  DBUG_RETURN(0);
}

int ha_redisrpl::close(void)
{
  DBUG_ENTER("ha_redisrpl::close");
  free_share(share);
  DBUG_RETURN(0);
}

int ha_redisrpl::create(const char *name, TABLE *table_arg,
                         HA_CREATE_INFO *create_info)
{
  DBUG_ENTER("ha_redisrpl::create");
  DBUG_RETURN(0);
}

/*
  Intended to support partitioning.
  Allows a particular partition to be truncated.
*/
int ha_redisrpl::truncate()
{
  DBUG_ENTER("ha_redisrpl::truncate");
  DBUG_RETURN(0);
}

const char *ha_redisrpl::index_type(uint key_number)
{
  DBUG_ENTER("ha_redisrpl::index_type");
  DBUG_RETURN((table_share->key_info[key_number].flags & HA_FULLTEXT) ? 
              "FULLTEXT" :
              (table_share->key_info[key_number].flags & HA_SPATIAL) ?
              "SPATIAL" :
              (table_share->key_info[key_number].algorithm ==
               HA_KEY_ALG_RTREE) ? "RTREE" : "BTREE");
}

int ha_redisrpl::write_row(uchar * buf)
{
  DBUG_ENTER("ha_redisrpl::write_row");

  const char *table_name = table->alias;
  char buffer[1024 *64];
  char key_buffer[1024];
  char field_buffer[256];
  char data_buffer[65536];
  char value_buffer[1024];

  my_bitmap_map *org_bitmap= dbug_tmp_use_all_columns(table, table->read_set);
  bool is_first = true;
  //打印各列的数据类型
  Field *field = NULL;
  for (Field ** field_it = table->field ; (field = *field_it) ; field_it++)
  {
    //获取数据
    if (field->is_null())
    {
      strcpy(data_buffer, "null");
    }
    else
    {
      String value(value_buffer, sizeof(value_buffer),
                   field->charset());

      field->val_str(&value,&value);
      memcpy(data_buffer, value.ptr(), value.length());
      data_buffer[value.length()] = 0;
    }

    if (is_first)
    {
      sprintf(field_buffer, "%s", data_buffer);
      is_first = false;
    }
    else
    {
      sprintf(key_buffer, "%s:%s", table_name, field->field_name);
      sprintf(buffer, "hset %s %s %s", key_buffer, field_buffer, data_buffer);
      hiredis_command(ctx, buffer);
    }
  }
  dbug_tmp_restore_column_map(table->read_set, org_bitmap);

  DBUG_RETURN(table->next_number_field ? update_auto_increment() : 0);
}

int ha_redisrpl::update_row(const uchar *old_data, uchar *new_data)
{
  DBUG_ENTER("ha_redisrpl::update_row");
  THD *thd= ha_thd();
  if (is_slave_applier(thd) && thd->query().str == NULL)
    DBUG_RETURN(0);
  my_bitmap_map *org_bitmap= dbug_tmp_use_all_columns(table, table->read_set);
  const char *table_name = table->alias;

  char buffer[1024 *64];
  char key_buffer[1024];
  char field_buffer[256];
  char data_buffer[65536];
  char value_buffer[1024];

  bool is_first = true;
  //打印各列的数据类型
  Field *field = NULL;
  for (Field ** field_it = table->field ; (field = *field_it) ; field_it++)
  {
    if (is_first)
    {
      String value(value_buffer, sizeof(value_buffer),
                   field->charset());

      field->val_str(&value,&value);
      memcpy(data_buffer, value.ptr(), value.length());
      data_buffer[value.length()] = 0;
      sprintf(field_buffer, "%s", data_buffer);
      is_first = false;
    }
    else
    {
      sprintf(key_buffer, "%s:%s", table_name, field->field_name);
      sprintf(buffer, "hdel %s %s", key_buffer, field_buffer);
      hiredis_command(ctx, buffer);
    }
  }

  dbug_tmp_restore_column_map(table->read_set, org_bitmap);
  DBUG_RETURN(0);
}

int ha_redisrpl::delete_row(const uchar *buf)
{
  DBUG_ENTER("ha_redisrpl::delete_row");
  THD *thd= ha_thd();
  if (is_slave_applier(thd) && thd->query().str == NULL)
    DBUG_RETURN(0);
  my_bitmap_map *org_bitmap= dbug_tmp_use_all_columns(table, table->read_set);

  const char *table_name = table->alias;
  char buffer[1024 *64];
  char key_buffer[1024];
  char field_buffer[256];
  char data_buffer[65536];
  char value_buffer[1024];

  bool is_first = true;
  //打印各列的数据类型
  Field *field = NULL;
  for (Field ** field_it = table->field ; (field = *field_it) ; field_it++)
  {
    if (is_first)
    {
      String value(value_buffer, sizeof(value_buffer),
                   field->charset());

      field->val_str(&value,&value);
      memcpy(data_buffer, value.ptr(), value.length());
      data_buffer[value.length()] = 0;
      sprintf(field_buffer, "%s", data_buffer);
      is_first = false;
    }
    else
    {
      sprintf(key_buffer, "%s:%s", table_name, field->field_name);
      sprintf(buffer, "hdel %s %s", key_buffer, field_buffer);
      hiredis_command(ctx, buffer);
    }
  }

  dbug_tmp_restore_column_map(table->read_set, org_bitmap);
  DBUG_RETURN(HA_ERR_WRONG_COMMAND);
}

int ha_redisrpl::rnd_init(bool scan)
{
  DBUG_ENTER("ha_redisrpl::rnd_init");
  DBUG_RETURN(0);
}


int ha_redisrpl::rnd_next(uchar *buf)
{
  int rc;
  DBUG_ENTER("ha_redisrpl::rnd_next");
  MYSQL_READ_ROW_START(table_share->db.str, table_share->table_name.str,
                       TRUE);
  THD *thd= ha_thd();
  if (is_slave_applier(thd) && thd->query().str == NULL)
    rc= 0;
  else
    rc= HA_ERR_END_OF_FILE;
  MYSQL_READ_ROW_DONE(rc);
  table->status= rc ? STATUS_NOT_FOUND : 0;
  DBUG_RETURN(rc);
}


int ha_redisrpl::rnd_pos(uchar * buf, uchar *pos)
{
  DBUG_ENTER("ha_redisrpl::rnd_pos");
  MYSQL_READ_ROW_START(table_share->db.str, table_share->table_name.str,
                       FALSE);
  DBUG_ASSERT(0);
  MYSQL_READ_ROW_DONE(0);
  DBUG_RETURN(0);
}


void ha_redisrpl::position(const uchar *record)
{
  DBUG_ENTER("ha_redisrpl::position");
  DBUG_ASSERT(0);
  DBUG_VOID_RETURN;
}


int ha_redisrpl::info(uint flag)
{
  DBUG_ENTER("ha_redisrpl::info");

  memset(&stats, 0, sizeof(stats));
  if (flag & HA_STATUS_AUTO)
    stats.auto_increment_value= 1;
  DBUG_RETURN(0);
}

int ha_redisrpl::external_lock(THD *thd, int lock_type)
{
  DBUG_ENTER("ha_redisrpl::external_lock");
  DBUG_RETURN(0);
}


THR_LOCK_DATA **ha_redisrpl::store_lock(THD *thd,
                                         THR_LOCK_DATA **to,
                                         enum thr_lock_type lock_type)
{
  DBUG_ENTER("ha_redisrpl::store_lock");
  if (lock_type != TL_IGNORE && lock.type == TL_UNLOCK)
  {
    /*
      Here is where we get into the guts of a row level lock.
      If TL_UNLOCK is set
      If we are not doing a LOCK TABLE or DISCARD/IMPORT
      TABLESPACE, then allow multiple writers
    */

    if ((lock_type >= TL_WRITE_CONCURRENT_INSERT &&
         lock_type <= TL_WRITE) && !thd_in_lock_tables(thd)
        && !thd_tablespace_op(thd))
      lock_type = TL_WRITE_ALLOW_WRITE;

    /*
      In queries of type INSERT INTO t1 SELECT ... FROM t2 ...
      MySQL would use the lock TL_READ_NO_INSERT on t2, and that
      would conflict with TL_WRITE_ALLOW_WRITE, blocking all inserts
      to t2. Convert the lock to a normal read lock to allow
      concurrent inserts to t2.
    */

    if (lock_type == TL_READ_NO_INSERT && !thd_in_lock_tables(thd))
      lock_type = TL_READ;

    lock.type= lock_type;
  }
  *to++= &lock;
  DBUG_RETURN(to);
}


int ha_redisrpl::index_read_map(uchar * buf, const uchar * key,
                                 key_part_map keypart_map,
                             enum ha_rkey_function find_flag)
{
  int rc;
  DBUG_ENTER("ha_redisrpl::index_read");
  MYSQL_INDEX_READ_ROW_START(table_share->db.str, table_share->table_name.str);
  THD *thd= ha_thd();
  if (is_slave_applier(thd) && thd->query().str == NULL)
    rc= 0;
  else
    rc= HA_ERR_END_OF_FILE;
  MYSQL_INDEX_READ_ROW_DONE(rc);
  table->status= rc ? STATUS_NOT_FOUND : 0;
  DBUG_RETURN(rc);
}


int ha_redisrpl::index_read_idx_map(uchar * buf, uint idx, const uchar * key,
                                 key_part_map keypart_map,
                                 enum ha_rkey_function find_flag)
{
  int rc;
  DBUG_ENTER("ha_redisrpl::index_read_idx");
  MYSQL_INDEX_READ_ROW_START(table_share->db.str, table_share->table_name.str);
  THD *thd= ha_thd();
  if (is_slave_applier(thd) && thd->query().str == NULL)
    rc= 0;
  else
    rc= HA_ERR_END_OF_FILE;
  MYSQL_INDEX_READ_ROW_DONE(rc);
  table->status= rc ? STATUS_NOT_FOUND : 0;
  DBUG_RETURN(rc);
}


int ha_redisrpl::index_read_last_map(uchar * buf, const uchar * key,
                                      key_part_map keypart_map)
{
  int rc;
  DBUG_ENTER("ha_redisrpl::index_read_last");
  MYSQL_INDEX_READ_ROW_START(table_share->db.str, table_share->table_name.str);
  THD *thd= ha_thd();
  if (is_slave_applier(thd) && thd->query().str == NULL)
    rc= 0;
  else
    rc= HA_ERR_END_OF_FILE;
  MYSQL_INDEX_READ_ROW_DONE(rc);
  table->status= rc ? STATUS_NOT_FOUND : 0;
  DBUG_RETURN(rc);
}


int ha_redisrpl::index_next(uchar * buf)
{
  int rc;
  DBUG_ENTER("ha_redisrpl::index_next");
  MYSQL_INDEX_READ_ROW_START(table_share->db.str, table_share->table_name.str);
  rc= HA_ERR_END_OF_FILE;
  MYSQL_INDEX_READ_ROW_DONE(rc);
  table->status= STATUS_NOT_FOUND;
  DBUG_RETURN(rc);
}


int ha_redisrpl::index_prev(uchar * buf)
{
  int rc;
  DBUG_ENTER("ha_redisrpl::index_prev");
  MYSQL_INDEX_READ_ROW_START(table_share->db.str, table_share->table_name.str);
  rc= HA_ERR_END_OF_FILE;
  MYSQL_INDEX_READ_ROW_DONE(rc);
  table->status= STATUS_NOT_FOUND;
  DBUG_RETURN(rc);
}


int ha_redisrpl::index_first(uchar * buf)
{
  int rc;
  DBUG_ENTER("ha_redisrpl::index_first");
  MYSQL_INDEX_READ_ROW_START(table_share->db.str, table_share->table_name.str);
  rc= HA_ERR_END_OF_FILE;
  MYSQL_INDEX_READ_ROW_DONE(rc);
  table->status= STATUS_NOT_FOUND;
  DBUG_RETURN(rc);
}


int ha_redisrpl::index_last(uchar * buf)
{
  int rc;
  DBUG_ENTER("ha_redisrpl::index_last");
  MYSQL_INDEX_READ_ROW_START(table_share->db.str, table_share->table_name.str);
  rc= HA_ERR_END_OF_FILE;
  MYSQL_INDEX_READ_ROW_DONE(rc);
  table->status= STATUS_NOT_FOUND;
  DBUG_RETURN(rc);
}


static st_blackhole_share *get_share(const char *table_name)
{
  st_blackhole_share *share;
  uint length;

  length= (uint) strlen(table_name);
  mysql_mutex_lock(&blackhole_mutex);
    
  if (!(share= (st_blackhole_share*)
        my_hash_search(&blackhole_open_tables,
                       (uchar*) table_name, length)))
  {
    if (!(share= (st_blackhole_share*) my_malloc(bh_key_memory_blackhole_share,
                                                 sizeof(st_blackhole_share) +
                                                 length,
                                                 MYF(MY_WME | MY_ZEROFILL))))
      goto error;

    share->table_name_length= length;
    my_stpcpy(share->table_name, table_name);
    
    if (my_hash_insert(&blackhole_open_tables, (uchar*) share))
    {
      my_free(share);
      share= NULL;
      goto error;
    }
    
    thr_lock_init(&share->lock);
  }
  share->use_count++;
  
error:
  mysql_mutex_unlock(&blackhole_mutex);
  return share;
  return NULL;
}

static void free_share(st_blackhole_share *share)
{
  mysql_mutex_lock(&blackhole_mutex);
  if (!--share->use_count)
    my_hash_delete(&blackhole_open_tables, (uchar*) share);
  mysql_mutex_unlock(&blackhole_mutex);
}

static void blackhole_free_key(st_blackhole_share *share)
{
  thr_lock_delete(&share->lock);
  my_free(share);
}

static uchar* blackhole_get_key(st_blackhole_share *share, size_t *length,
                                my_bool not_used MY_ATTRIBUTE((unused)))
{
  *length= share->table_name_length;
  return (uchar*) share->table_name;
}

#ifdef HAVE_PSI_INTERFACE
static PSI_mutex_key bh_key_mutex_blackhole;

static PSI_mutex_info all_blackhole_mutexes[]=
{
  { &bh_key_mutex_blackhole, "blackhole", PSI_FLAG_GLOBAL}
};

static PSI_memory_info all_blackhole_memory[]=
{
  { &bh_key_memory_blackhole_share, "blackhole_share", 0}
};

void init_blackhole_psi_keys()
{
  const char* category= "blackhole";
  int count;

  count= array_elements(all_blackhole_mutexes);
  mysql_mutex_register(category, all_blackhole_mutexes, count);

  count= array_elements(all_blackhole_memory);
  mysql_memory_register(category, all_blackhole_memory, count);
}
#endif

static int redisrpl_init(void *p)
{
  handlerton *blackhole_hton;

#ifdef HAVE_PSI_INTERFACE
  init_blackhole_psi_keys();
#endif

  blackhole_hton= (handlerton *)p;
  blackhole_hton->state= SHOW_OPTION_YES;
  blackhole_hton->db_type= DB_TYPE_BLACKHOLE_DB;
  blackhole_hton->create= blackhole_create_handler;
  blackhole_hton->flags= HTON_CAN_RECREATE;

  mysql_mutex_init(bh_key_mutex_blackhole,
                   &blackhole_mutex, MY_MUTEX_INIT_FAST);

  (void) my_hash_init(&blackhole_open_tables, system_charset_info,32,0,0,
                      (my_hash_get_key) blackhole_get_key,
                      (my_hash_free_key) blackhole_free_key, 0,
                      bh_key_memory_blackhole_share);

  bool succ;
  succ = load_hiredis();
  if (!succ)
    return -1;

  return 0;
}

static int redisrpl_deinit(void *p)
{
  unload_hiredis();
  my_hash_free(&blackhole_open_tables);
  mysql_mutex_destroy(&blackhole_mutex);

  return 0;
}

struct st_mysql_storage_engine redisrpl_storage_engine=
{ MYSQL_HANDLERTON_INTERFACE_VERSION };

mysql_declare_plugin(redisrpl)
{
  MYSQL_STORAGE_ENGINE_PLUGIN,
  &redisrpl_storage_engine,
  "REDISRPL",
  "Ctrip Corp",
  "data replication to redis",
  PLUGIN_LICENSE_GPL,
  redisrpl_init, /* Plugin Init */
  redisrpl_deinit, /* Plugin Deinit */
  0x0100 /* 1.0 */,
  NULL,                       /* status variables                */
  NULL,                       /* system variables                */
  NULL,                       /* config options                  */
  0,                          /* flags                           */
}
mysql_declare_plugin_end;
