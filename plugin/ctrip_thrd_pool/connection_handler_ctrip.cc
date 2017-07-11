#include "connection_handler_ctrip.h"
#include <conn_handler/channel_info.h>
#include "sql_class.h"                  // THD
#ifdef __linux__
#include <sys/epoll.h>
#endif
#include <semaphore.h>

#include "sql_class.h"                  // THD

#include "connection_handler_impl.h"

#include "channel_info.h"                // Channel_info
#include "connection_handler_manager.h"  // Connection_handler_manager
#include "mysqld.h"                      // max_connections
#include "mysqld_error.h"                // ER_*
#include "mysqld_thd_manager.h"          // Global_THD_manager
#include "sql_audit.h"                   // mysql_audit_release
#include "sql_class.h"                   // THD
#include "sql_connect.h"                 // close_connection
#include "sql_parse.h"                   // do_command
#include "sql_thd_internal_api.h"        // thd_set_thread_stack
#include "log.h"                         // Error_log_throttle

#include <list>
#include <map>

bool thd_map_erase_if_exist(THD *thd);
void thd_map_add(THD *thd);

using namespace std;

/*copy from connection_handler_per_thread.cc*/
static int ctrip_slow_launch_count = 0;

static THD* ctrip_init_new_thd(Channel_info *channel_info)
{
  THD *thd= channel_info->create_thd();
  if (thd == NULL)
  {
    channel_info->send_error_and_close_channel(ER_OUT_OF_RESOURCES, 0, false);
    delete channel_info;
    return NULL;
  }

  thd->set_new_thread_id();

  thd->start_utime= thd->thr_create_utime= my_micro_time();
  if (channel_info->get_prior_thr_create_utime() != 0)
  {
    /*
      A pthread was created to handle this connection:
      increment slow_launch_threads counter if it took more than
      slow_launch_time seconds to create the pthread.
    */
    ulong launch_time= (ulong) (thd->thr_create_utime -
                                channel_info->get_prior_thr_create_utime());
    if (launch_time >= slow_launch_time * 1000000L)
    {
      ctrip_slow_launch_count++;
    }
  }
  delete channel_info;

  /*
    handle_one_connection() is normally the only way a thread would
    start and would always be on the very high end of the stack ,
    therefore, the thread stack always starts at the address of the
    first local variable of handle_one_connection, which is thd. We
    need to know the start of the stack so that we could check for
    stack overruns.
  */
  thd_set_thread_stack(thd, (char*) &thd);
  if (thd->store_globals())
  {
    close_connection(thd, ER_OUT_OF_RESOURCES);
    thd->release_resources();
    delete thd;
    return NULL;
  }

  return thd;
}

/*
  从Chennal对象创建连接对象
 */
static THD*
ctrip_add_connection(Channel_info* channel_info)
{
  Global_THD_manager *thd_manager= Global_THD_manager::get_instance();
  Connection_handler_manager *handler_manager=
    Connection_handler_manager::get_instance();

  THD *thd= ctrip_init_new_thd(channel_info);

  if (thd == NULL)
  {
    connection_errors_internal++;
    handler_manager->inc_aborted_connects();
    Connection_handler_manager::dec_connection_count();
    return NULL;
  }

#ifdef USE_IT
  //该段为监控
#ifdef HAVE_PSI_THREAD_INTERFACE
  if (pthread_reused)
  {
    /*
      Reusing existing pthread:
      Create new instrumentation for the new THD job,
      and attach it to this running pthread.
    */
    PSI_thread *psi= PSI_THREAD_CALL(new_thread)
    (key_thread_one_connection, thd, thd->thread_id());
    PSI_THREAD_CALL(set_thread_os_id)(psi);
    PSI_THREAD_CALL(set_thread)(psi);
  }
#endif
#endif

#ifdef HAVE_PSI_THREAD_INTERFACE
  /* Find the instrumented thread */
  PSI_thread *psi= PSI_THREAD_CALL(get_thread)();
  /* Save it within THD, so it can be inspected */
  thd->set_psi(psi);
#endif /* HAVE_PSI_THREAD_INTERFACE */

  mysql_thread_set_psi_id(thd->thread_id());
  mysql_thread_set_psi_THD(thd);
  mysql_socket_set_thread_owner(
    thd->get_protocol_classic()->get_vio()->mysql_socket);

  thd_manager->add_thd(thd);

  if (thd_prepare_connection(thd))
  {
    handler_manager->inc_aborted_connects();
    close_connection(thd, 0, false, false);
    thd->get_stmt_da()->reset_diagnostics_area();
    thd->release_resources();
    thd_manager->remove_thd(thd);
    Connection_handler_manager::dec_connection_count();
#ifdef HAVE_PSI_THREAD_INTERFACE
    /*
      Delete the instrumentation for the job that just completed.
    */
    thd->set_psi(NULL);
    PSI_THREAD_CALL(delete_current_thread)();
#endif /* HAVE_PSI_THREAD_INTERFACE */
    delete thd;
    return NULL;
  }
  thd_map_add(thd);

  return thd;
}

void
ctrip_remove_connection_from_manager(THD *thd)
{
  //return ;
  // Clean up errors now, before possibly waiting for a new connection.
  //SSL调用，暂时不予考虑
  //ERR_remove_state(0);

  Global_THD_manager *thd_manager= Global_THD_manager::get_instance();
  thd_manager->remove_thd(thd);
  Connection_handler_manager::dec_connection_count();

#ifdef HAVE_PSI_THREAD_INTERFACE
  /*
    Delete the instrumentation for the job that just completed.
  */
  thd->set_psi(NULL);
  PSI_THREAD_CALL(delete_current_thread)();
#endif /* HAVE_PSI_THREAD_INTERFACE */

  delete thd;
}

static int net_poll_delete(int fd);
void
ctrip_remove_connection(THD *thd)
{
  Global_THD_manager *thd_manager= Global_THD_manager::get_instance();
  int fd = thd->get_protocol_classic()->get_net()->fd;;
  net_poll_delete(fd);

  end_connection(thd);
  close_connection(thd, 0, false, false);

  thd->get_stmt_da()->reset_diagnostics_area();
  thd->release_resources();

  // Clean up errors now, before possibly waiting for a new connection.
  //SSL调用，暂时不予考虑
  //ERR_remove_state(0);

  thd_manager->remove_thd(thd);
  Connection_handler_manager::dec_connection_count();

#ifdef HAVE_PSI_THREAD_INTERFACE
  /*
    Delete the instrumentation for the job that just completed.
  */
  thd->set_psi(NULL);
  PSI_THREAD_CALL(delete_current_thread)();
#endif /* HAVE_PSI_THREAD_INTERFACE */

  delete thd;
}

int epoll_fd = 0;
/*
  poll operations
*/
static int net_poll_create()
{
  return epoll_create(1);
}

static int net_poll_close(int fd)
{
  return close(fd);
}

static int net_poll_add(int fd, THD *thd)
{
  struct epoll_event event;
  event.data.fd = fd;
  event.events = EPOLLIN | EPOLLET;
  event.data.ptr = thd;

  epoll_ctl (epoll_fd, EPOLL_CTL_ADD, fd, &event);

  return 0;
}

static int net_poll_delete(int fd)
{
  epoll_ctl (epoll_fd, EPOLL_CTL_DEL, fd, NULL);
  return 0;
}

static int net_poll_wait(int poll_fd, struct epoll_event *events
                         ,int maxevents)
{
  return epoll_wait(poll_fd, events, maxevents, -1);
}

/*
  thread pool manage
*/
bool keep_work = true;
bool keep_working()
{
  return keep_work;
}

struct task_struct
{
  THD *thd;
};
typedef struct task_struct task_t;

sem_t using_sem;
sem_t free_sem;
mysql_mutex_t LOCK_using_queue;
mysql_mutex_t LOCK_free_queue;
mysql_mutex_t LOCK_thd_map;
list<task_t*> task_using_list;
list<task_t*> task_free_list;
map<void*, void*> thd_map;

void using_enqueue(task_t *task)
{
  mysql_mutex_lock(&LOCK_using_queue);
  //将任务放入队列
  task_using_list.push_back(task);
  mysql_mutex_unlock(&LOCK_using_queue);
  sem_post(&using_sem);
}

task_t* using_dequeue()
{
  task_t *task = NULL;
  sem_wait(&using_sem);
  mysql_mutex_lock(&LOCK_using_queue);
  //将任务从队列中取出
  task = task_using_list.front();
  task_using_list.pop_front();
  mysql_mutex_unlock(&LOCK_using_queue);
  return task;
}

void free_enqueue(task_t *task)
{
  task->thd = NULL;
  mysql_mutex_lock(&LOCK_free_queue);
  //将任务放入队列
  task_free_list.push_back(task);
  mysql_mutex_unlock(&LOCK_free_queue);
  sem_post(&free_sem);
}

task_t* free_dequeue()
{
  task_t *task = NULL;
  sem_wait(&free_sem);
  mysql_mutex_lock(&LOCK_free_queue);
  //将任务从队列中取出
  task = task_free_list.front();
  task_free_list.pop_front();
  mysql_mutex_unlock(&LOCK_free_queue);
  return task;
}

void thd_map_add(THD *thd)
{
  mysql_mutex_lock(&LOCK_thd_map);
  thd_map.insert(pair<void*, void*>(thd, thd));
  mysql_mutex_unlock(&LOCK_thd_map);
}

void thd_map_erase(THD *thd)
{
  mysql_mutex_lock(&LOCK_thd_map);
  map<void* ,void* >::iterator it;
  it = thd_map.find(thd);
  if (it != thd_map.end())
  {
    thd_map.erase(it);
  }
  mysql_mutex_unlock(&LOCK_thd_map);
}

bool thd_map_erase_if_exist(THD *thd)
{
  bool exist = false;
  mysql_mutex_lock(&LOCK_thd_map);
  map<void* ,void* >::iterator it;
  it = thd_map.find(thd);
  if (it != thd_map.end())
  {
    thd_map.erase(it);
    exist = true;
  }
  mysql_mutex_unlock(&LOCK_thd_map);
  return exist;
}

void
process_killed_thd()
{
  THD *thd;
  task_t *task;
  mysql_mutex_lock(&LOCK_thd_map);
  map<void* ,void* >::iterator it;
  it = thd_map.begin();
  for (;it != thd_map.end(); it++)
  {
    thd = (THD*)it->first;
    if (thd->killed)
    {
      task = free_dequeue();
      task->thd = thd;
      using_enqueue(task);
    }
  }
  mysql_mutex_unlock(&LOCK_thd_map);
}

/*
  用于监听事件的主线程函数
*/
extern int ctrip_worker_number;
extern int ctrip_task_number;

struct epoll_event *events = NULL;
task_t *tasks = NULL;
extern "C" 
void* ctrip_thrd_pool_main_thread(void *arg)
{
  int ret;
  task_t *task = NULL;
  my_thread_init();
  while (keep_working())
  {
    ret = net_poll_wait(epoll_fd, events, ctrip_worker_number);
    if (ret == 0)
      continue;
    for (int i = 0; i < ret; i++)
    {
      //process the net event
      task = free_dequeue();
      task->thd = (THD*)(events[i].data.ptr);
      using_enqueue(task);
    }
    process_killed_thd();
  }
  process_killed_thd();
  my_thread_end();
  return 0;
}

/*
  用于进行命令执行的工作线程
*/
extern "C"
void* ctrip_thrd_pool_worker_thread(void *arg)
{
  task_t *task;
  THD *thd;
  my_thread_init();
  long long counter = 0;
  while (true)
  {
    task = using_dequeue();
    counter++;
    if (task == NULL)
    {
      //线程退出信号
    }
    else
    {
      thd = task->thd;
      /*
        thd_map_erase_if_exist存在的原因是。由于使用了epoll，当执行quit命令时，
        epoll被触发，当前线程退出，于是有两个线程同时对一个thd进行操作。此时
        会产生内存访问一场，这是由于ctrip_remove_connection释放了thd对象，及
        相关资源。
        为了保证同一时刻只有一个线程对thd对象进行处理，采用该方式进行处理。
      */
      if (thd_map_erase_if_exist(thd))
      {
        if (thd->killed)
        {
          if (!thd->release_resources_done())
          {
            ctrip_remove_connection(thd);
          }
          else
          {
            printf("unknown error for debug\n");
          }
        }
        else if (thd_connection_alive(thd))
        {
          thd_set_thread_stack(thd, (char*) &thd);
          if (thd->store_globals())
          {
            ctrip_remove_connection(thd);
          }
          else
          {
            bool connection_removed = false;
            if (do_command(thd))
            {
              //执行中出现可不恢复错误
              ctrip_remove_connection(thd);
              connection_removed = true;
            }
            else
            {
              thd_map_add(thd);
            }
            if (!connection_removed && !thd_connection_alive(thd))
            {
              ctrip_remove_connection(thd);
            }
          }
        }
        else
        {
          //连接不再有效
          ctrip_remove_connection(thd);
        }
      }
      free_enqueue(task);
    }
  }
  my_thread_end();
  return 0;
}

my_thread_attr_t ctrip_connection_attrib;

static bool initialized = false;

int
Ctrip_connection_handler::init()
{
  epoll_fd = net_poll_create();
  sem_init(&using_sem, 0, 0);
  sem_init(&free_sem, 0, 0);

  mysql_mutex_init(NULL, &LOCK_using_queue, MY_MUTEX_INIT_FAST);
  mysql_mutex_init(NULL, &LOCK_free_queue, MY_MUTEX_INIT_FAST);
  mysql_mutex_init(NULL, &LOCK_thd_map, MY_MUTEX_INIT_FAST);
  my_thread_handle id;
  int error = mysql_thread_create(NULL, &id,
                                  &ctrip_connection_attrib,
                                  ctrip_thrd_pool_main_thread,
                                  (void*) NULL);
  if (error)
    return 1;

  /*int size_event = sizeof(struct epoll_event[1]);
    printf("%d", size_event);*/

  events = (struct epoll_event*)
  malloc(sizeof(struct epoll_event[1]) * ctrip_worker_number);
  for (int i = 0; i < ctrip_worker_number; i++)
  {
    error = mysql_thread_create(NULL, &id,
                                &ctrip_connection_attrib,
                                ctrip_thrd_pool_worker_thread,
                                (void*) NULL);
  }
  tasks = (task_t*)malloc(sizeof(task_t[1]) * ctrip_task_number);
  for (int i = 0; i < ctrip_task_number; i++)
  {
    free_enqueue(tasks + i);
  }

  Connection_handler_manager
  *manager = Connection_handler_manager::get_instance();
  //manager->unload_connection_handler();

  Connection_handler *ctrip_conn_handler = new Ctrip_connection_handler();
  manager->load_connection_handler(ctrip_conn_handler);

  initialized = true;

  return 0;
}

int
Ctrip_connection_handler::deinit()
{
  process_killed_thd();
  sleep(5);
  keep_work = false;
  net_poll_close(epoll_fd);
  sem_destroy(&using_sem);
  sem_destroy(&free_sem);
  mysql_mutex_destroy(&LOCK_using_queue);
  mysql_mutex_destroy(&LOCK_free_queue);
  mysql_mutex_destroy(&LOCK_thd_map);
  free(events);
  free(tasks);

  Connection_handler_manager::get_instance()->unload_connection_handler();
  initialized = false;
  return 0;
}

bool
Ctrip_connection_handler::add_connection(Channel_info* channel_info)
{
  DBUG_ENTER("Ctrip_connection_handler::add_connection");

  THD *thd= ctrip_add_connection(channel_info);
  if (thd == NULL)
  {
    return true;
  }
  int fd = thd->get_protocol_classic()->get_net()->fd;
  //  int fd = (int)(thd->net.fd);
  if (net_poll_add(fd, thd))
  {
    ctrip_remove_connection(thd);
  }

  DBUG_RETURN(false);
}

void
Ctrip_connection_handler::test()
{
}


