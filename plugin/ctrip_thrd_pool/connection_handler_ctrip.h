#ifndef CTRIP_CONNECTION_HANDLER_INCLUDED
#define CTRIP_CONNECTION_HANDLER_INCLUDED

#include "mysql/thread_pool_priv.h"
#include "conn_handler/connection_handler.h"
#include "mysql/thread_pool_priv.h"

class THD;


class Ctrip_connection_handler : public Connection_handler
{
  //Ctrip_connection_handler(const Ctrip_connection_handler&);
  //Ctrip_connection_handler& operator=(const Ctrip_connection_handler&);

public:
  Ctrip_connection_handler() {}

  virtual ~Ctrip_connection_handler()  {}

  static int init();
  static int deinit();

  void test();

protected:
  virtual bool add_connection(Channel_info* channel_info);

  virtual uint get_max_threads() const
  {
    return (uint)get_max_connections();
  }
};

#endif // CTRIP_CONNECTION_HANDLER_INCLUDED
