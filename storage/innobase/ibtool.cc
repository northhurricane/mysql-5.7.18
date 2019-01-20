#include <iostream>
#include <string>
#include <sstream>
#include <stdint.h>
#include "fil0fil.h"
#include "fsp0fsp.h"
#include "log0types.h"
#include "fil0fil.h"
#include <stdlib.h>

using namespace std;

struct flst_base_node_struct
{
  uint32_t len;
  fil_addr_t first;
  fil_addr_t last;
};
typedef struct flst_base_node_struct flst_base_node2_t;

//copied from flst_read_addr without mtr
void
flst_read_addr_raw(uint8_t *paddr, fil_addr_t *addr)
{
  //TODO : 该函数现在是错误的是，flst的格式不是如此
  addr->page = mach_read_from_4((uint8_t*)paddr + FIL_ADDR_PAGE);
  addr->boffset = mach_read_from_2((uint8_t*)paddr + FIL_ADDR_BYTE);
}

void
flst_read_base_node(uint8_t *p, flst_base_node2_t *base_node)
{
  base_node->len = mach_read_from_4(p + FLST_LEN);
  flst_read_addr_raw(p + FLST_FIRST, &base_node->first);
  flst_read_addr_raw(p + FLST_LAST, &base_node->last);
}

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

void ibt_read_fil_head(void *page, fil_head_t *head)
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

void ibt_print_fil_head(fil_head_t *fil_head)
{
  string page_type = get_page_type(fil_head->type);
  cout
  << "page fil head info : \n"
  << "-page offset : " << fil_head->page_offset << "\n"
  << "-page prev : " << fil_head->page_prev << "\n"
  << "-page next : " << fil_head->page_next << "\n"
  << "-page lsn : " << fil_head->page_lsn << "\n"
  << "-page type : " << page_type << "\n"
  << endl;
}

struct fsp_struct
{
  uint32_t space_id;
  uint32_t space_size;
  uint32_t free_limit;
  uint32_t flags;
  uint32_t frag_n_used;
  flst_base_node2_t free;
  flst_base_node2_t free_frag;
  flst_base_node2_t full_frag;
  uint8_t seg_id;
  flst_base_node2_t seg_inode_full;
  flst_base_node2_t seg_inode_free;
};
typedef fsp_struct fsp_t;

void
ibt_read_fsp_hdr(void *page, fsp_t *fsp)
{
  uint8_t *fsp_head = (uint8_t*)page + FSP_HEADER_OFFSET;
  fsp->space_id = mach_read_from_4(FSP_SPACE_ID + fsp_head);
  fsp->space_size = mach_read_from_4(fsp_head + FSP_SIZE);
  fsp->free_limit = mach_read_from_4(fsp_head + FSP_FREE_LIMIT);
  fsp->flags = mach_read_from_4(FSP_SPACE_FLAGS + fsp_head);
  fsp->frag_n_used = mach_read_from_4(FSP_FRAG_N_USED + fsp_head);
  flst_read_base_node(fsp_head + FSP_FREE, &fsp->free);
  flst_read_base_node(fsp_head + FSP_FREE_FRAG, &fsp->free_frag);
  flst_read_base_node(fsp_head + FSP_FULL_FRAG, &fsp->full_frag);
  fsp->seg_id = mach_read_from_8(fsp_head + FSP_SEG_ID);
  flst_read_base_node(fsp_head + FSP_SEG_INODES_FULL, &fsp->seg_inode_full);
  flst_read_base_node(fsp_head + FSP_SEG_INODES_FREE, &fsp->seg_inode_free);
}

void ibt_print_fsp_flags(uint32_t flags)
{
  /*char buf[128];
  itoa(flags, buf, 2);
  cout << "-flags : " << buf << "\n";*/
}

string ibt_flst_base_node2str(flst_base_node2_t *node)
{
  stringstream ss;
  ss
  << "{len : " << node->len
  << " | first : " << node->first.page << "-" << node->first.boffset
  << " | last : " << node->last.page << "-" << node->last.boffset
  << "}\n";
  return ss.str();
}

void ibt_print_fsp_hdr(fsp_t *fsp)
{
  cout
  << "fsp head info : \n"
  << "-space id : " << fsp->space_id << "\n"
  << "-space size : " << fsp->space_size << "\n"
  << "-free limit : " << fsp->free_limit << "\n";
  ibt_print_fsp_flags(fsp->flags);
  cout
  << "-free : " << ibt_flst_base_node2str(&fsp->free) << "\n"
  << "-free frag : " << ibt_flst_base_node2str(&fsp->free_frag) << "\n"
  << "-full_frag : " << ibt_flst_base_node2str(&fsp->full_frag) << "\n"
  << "seg id : " << fsp->seg_id << "\n"
  << "-inode full : " << ibt_flst_base_node2str(&fsp->seg_inode_full) << "\n"
  << "-inode free : " << ibt_flst_base_node2str(&fsp->seg_inode_free) << "\n"
  << endl;
}

void ibt_read_xdes_info()
{
}

void ibt_print_xdes_info()
{
}

int ibt_print_page_info(void *page, uint16_t page_size)
{
  fil_head_t fil_head;

  ibt_read_fil_head(page, &fil_head);
  ibt_print_fil_head(&fil_head);
  switch (fil_head.type)
  {
  case FIL_PAGE_INDEX:
  case FIL_PAGE_RTREE:
  case FIL_PAGE_UNDO_LOG:
  case FIL_PAGE_INODE:
  case FIL_PAGE_IBUF_FREE_LIST:
  case FIL_PAGE_IBUF_BITMAP:
  case FIL_PAGE_TYPE_SYS:
  case FIL_PAGE_TYPE_TRX_SYS:
    break;
  case FIL_PAGE_TYPE_FSP_HDR:
    fsp_t fsp;
    ibt_read_fsp_hdr(page, &fsp);
    ibt_print_fsp_hdr(&fsp);
    //FSP是特殊的XDES类型的页面
    ibt_read_xdes_info();
    ibt_print_xdes_info();
    break;
  case FIL_PAGE_TYPE_XDES:
  case FIL_PAGE_TYPE_BLOB:
  case FIL_PAGE_TYPE_ZBLOB:
  case FIL_PAGE_TYPE_ZBLOB2:
  case FIL_PAGE_TYPE_UNKNOWN:
  case FIL_PAGE_COMPRESSED:
  case FIL_PAGE_ENCRYPTED:
  case FIL_PAGE_COMPRESSED_AND_ENCRYPTED:
  case FIL_PAGE_ENCRYPTED_RTREE:
    break;
  default:
    assert(false); //sanity check fail
  }

  return 0;
}

uint8_t page_buffer[64 * 1024];

int ibtool_main(int argc, const char *argv[])
{
  const char * file = "/home/jiangyx/mywork/app/mysql-5.7.18/data/tdb1/t1.ibd";
  int flag = 0;
  int fd = open(file, flag);

  if (fd < 0)
  {
    exit(-1);
  }

  uint16_t page_size = 1024 * 16;
  uint32_t page_count = 0;
  int r = 0;
  r = read(fd, page_buffer, page_size);
  while (r > 0)
  {
    page_count++;
    ibt_print_page_info(page_buffer, page_size);
    r = read(fd,  page_buffer, page_size);
  }


  close(fd);

  return 0;
}
