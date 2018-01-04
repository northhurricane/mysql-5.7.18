#ifndef SQL_IOSTAT_INCLUDED
#define SQL_IOSTAT_INCLUDED

#define SQL_IOSTAT_LOGICAL_READ (1)
#define SQL_IOSTAT_PHYSICAL_READ (2)
#define SQL_IOSTAT_PAGE_WRITE (3)

struct io_stat_struct
{
  unsigned long logic_read;
  unsigned long physic_read;
  unsigned long page_write;
};
typedef struct io_stat_struct io_stat_t;

void thrd_io_incr(uint type);
void thrd_io_stat_reset();
void thrd_io_stat_get(io_stat_t *io_stat);

typedef void (*io_stat_func_t)(uint stat_type);
typedef void (*io_stat_reset_func_t)();
typedef void (*io_stat_get_func_t)(io_stat_t *io_stat);

#endif //SQL_IOSTAT_INCLUDED

