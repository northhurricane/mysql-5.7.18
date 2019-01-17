#include <iostream>
#include <stdint.h>
#include "fil0fil.h"
#include "fsp0fsp.h"
#include "log0types.h"

using namespace std;

struct fil_head_struct
{
  ulint page_offset;
  ulint page_prev;
  ulint page_next;
  lsn_t page_lsn;
  uint16_t type;
  uint8_t file_lsn;
};
typedef struct fil_head_struct fil_head_t;

string get_page_type(uint16_t type)
{
  switch (type)
  {
  case FIL_PAGE_INDEX:
    return "FIL_PAGE_INDEX";
  case FIL_PAGE_RTREE:
    return "FIL_PAGE_RTREE";
  case FIL_PAGE_UNDO_LOG:
    return "FIL_PAGE_UNDO_LOG";
  case FIL_PAGE_INODE:
    return "FIL_PAGE_INODE";
  case FIL_PAGE_IBUF_FREE_LIST:
    return "FIL_PAGE_IBUF_FREE_LIST";
  case FIL_PAGE_IBUF_BITMAP:
    return "FIL_PAGE_IBUF_BITMAP";
  case FIL_PAGE_TYPE_SYS:
    return "FIL_PAGE_TYPE_SYS";
  case FIL_PAGE_TYPE_TRX_SYS:
    return "FIL_PAGE_TYPE_TRX_SYS";
  case FIL_PAGE_TYPE_FSP_HDR:
    return "FIL_PAGE_TYPE_FSP_HDR";
  case FIL_PAGE_TYPE_XDES:
    return "FIL_PAGE_TYPE_XDES";
  case FIL_PAGE_TYPE_BLOB:
    return "FIL_PAGE_TYPE_BLOB";
  case FIL_PAGE_TYPE_ZBLOB:
    return "FIL_PAGE_TYPE_ZBLOB";
  case FIL_PAGE_TYPE_ZBLOB2:
    return "FIL_PAGE_TYPE_ZBLOB2";
  case FIL_PAGE_TYPE_UNKNOWN:
    return "FIL_PAGE_TYPE_UNKNOWN";
  case FIL_PAGE_COMPRESSED:
    return "FIL_PAGE_COMPRESSED";
  case FIL_PAGE_ENCRYPTED:
    return "FIL_PAGE_ENCRYPTED";
  case FIL_PAGE_COMPRESSED_AND_ENCRYPTED:
    return "FIL_PAGE_COMPRESSED_AND_ENCRYPTED";
  case FIL_PAGE_ENCRYPTED_RTREE:
    return "FIL_PAGE_ENCRYPTED_RTREE";
  default:
      return "UNKONW.FATAL ERROR";
  }
  return "";
}

void read_fil_head(void *page, fil_head_t *head)
{
  //mach_read_from_4(page + FIL_PAGE_OFFSET);
  uint8_t* p = (uint8_t*)page;
  head->page_offset = mach_read_from_4(p + FIL_PAGE_OFFSET);
  head->page_prev =  mach_read_from_4(p + FIL_PAGE_PREV);
  head->page_next = mach_read_from_4(p + FIL_PAGE_NEXT);
  head->page_lsn = mach_read_from_8(p + FIL_PAGE_LSN);
  head->type = mach_read_from_2(p + FIL_PAGE_TYPE);
  head->file_lsn = mach_read_from_8(p + FIL_PAGE_FILE_FLUSH_LSN);
}

void print_fil_head(fil_head_t *fil_head)
{
  string page_type = get_page_type(fil_head->type);
  cout
  << "page fil head info : \n"
  << "-page offset : " << fil_head->page_offset
  << "-page prev : " << fil_head->page_prev
  << "-page next : " << fil_head->page_next
  << "-page lsn : " << fil_head->page_lsn
  << "-page type : " << page_type
  << endl;
}

int
print_page_info(void *page, uint16_t page_size)
{
  fil_head_t fil_head;

  read_fil_head(page, &fil_head);
  print_fil_head(&fil_head);
  /*  switch (fil_head.type)
  {
    case 
  }
  */

  return 0;
}

int ibtool_main(int argc, const char *argv[])
{
  char * file = "";
  int flag = 0;
  int fd = open(file, flag);

  return 0;
}
