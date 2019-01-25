#include <iostream>
#include <string>
#include <sstream>
#include <stdint.h>
#include "fil0fil.h"
#include "fsp0fsp.h"
#include "log0types.h"
#include "fil0fil.h"
#include "page0page.h"
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
  uint64_t seg_id;
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
  << "}";
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

struct xdes_flst_node_struct
{
  fil_addr_t prev;
  fil_addr_t next;
};
typedef struct xdes_flst_node_struct xdes_flst_node_t;

struct xdes_struct
{
  uint64_t id;
  xdes_flst_node_t node;
  uint32_t state;
  uint8_t bitmap[16];
};
typedef struct xdes_struct xdes2_t;


void ibt_read_xdes_info(uint8_t* descr, xdes2_t *xdes)
{
  xdes->id = mach_read_from_8(descr + XDES_ID);
  //flst_read_addr_raw
  flst_read_addr_raw(descr + XDES_FLST_NODE + FLST_PREV, &xdes->node.prev);
  //TODO : read next fil_addr_t data
  flst_read_addr_raw(descr + XDES_FLST_NODE + FLST_NEXT, &xdes->node.next);
  xdes->state = mach_read_from_4(descr + XDES_STATE);
  memcpy(xdes->bitmap, descr + XDES_BITMAP, XDES_SIZE - XDES_BITMAP);
}

string ibt_xdes_info2str(xdes2_t *xdes)
{
  stringstream ss;
  ss
  << "seg id : " << xdes->id << "\n"
  << "flst node : prev "
  << "flst node : next "
  << "\n";
  return ss.str();
}

void ibt_print_xdes_infos(void *page)
{
  uint8_t* descr = (uint8_t*)page + XDES_ARR_OFFSET;
  xdes2_t xdes;
  //未找到定义的页面内，xdes entry的数组的定义长度，根据其他资料知道是256个
  for (int i = 0; i < 256; i++)
  {
    ibt_read_xdes_info(descr, &xdes);
    cout << ibt_xdes_info2str(&xdes) << "\n";
    descr += XDES_SIZE;
  }
}

//此处存在问题，FSEG_FRAG_ARR_N_SLOTS2对于16/32/64k的页面来说是32，对于8k是64，4k是128
//应该是根据页面动态计算，可参考FSEG_FRAG_ARR_N_SLOTS的来由
//const int FSEG_FRAG_ARR_N_SLOTS2 = FSEG_FRAG_ARR_N_SLOTS;
const int FSEG_FRAG_ARR_N_SLOTS2 =32;
const int MAX_FSEG_FRAG_ARR_N_SLOTS2 = 128;
struct inode_entry_struct
{
  uint64_t seg_id;
  uint32_t not_full_n_used;
  flst_base_node2_t free;
  flst_base_node2_t not_full;
  flst_base_node2_t full;
  uint32_t magic;
  uint32_t frag_array_entry[MAX_FSEG_FRAG_ARR_N_SLOTS2];
};
typedef struct inode_entry_struct inode_entry_t;
void ibt_read_inode_info(uint8_t *entry, inode_entry_t *entry2)
{
  entry2->seg_id = mach_read_from_8(entry + FSEG_ID);
  entry2->not_full_n_used = mach_read_from_4(entry + FSEG_NOT_FULL_N_USED);
  flst_read_base_node(entry + FSEG_FREE, &entry2->free);
  flst_read_base_node(entry + FSEG_NOT_FULL, &entry2->not_full);
  flst_read_base_node(entry + FSEG_FULL, &entry2->full);
  entry2->magic = mach_read_from_4(entry + FSEG_MAGIC_N);
  assert(entry2->magic == FSEG_MAGIC_N_VALUE);
  memcpy(entry2->frag_array_entry, entry + FSEG_FRAG_ARR
         , FSEG_FRAG_ARR_N_SLOTS * FSEG_FRAG_SLOT_SIZE);
}

void ibt_print_page_inode(void *page)
{
  uint8_t *page_node = (uint8_t*)page + FSEG_PAGE_DATA;
  fil_addr_t prev, next;
  flst_read_addr_raw(page_node + FLST_PREV, &prev);
  flst_read_addr_raw(page_node + FLST_NEXT, &next);

  //Each INODE page contains 85 file segment INODE entries (for a 16 KiB page)
  //TODO : find definition of segment inode entries number
  uint8_t *entry = (uint8_t*)page + FSEG_ARR_OFFSET;
  inode_entry_t entry2;
  for (int i = 0; i <= 85; i++)
  {
    ibt_read_inode_info(entry, &entry2);
    entry += FSEG_INODE_SIZE;
  }
}

///index page whose type is FIL_PAGE_INDEX
struct index_head_struct
{
  uint16_t n_dir_slot;
  uint16_t heap_top;
  uint16_t n_heap;
  uint16_t free;
  uint16_t garbage;
  uint16_t last_insert;
  uint16_t direction;
  uint16_t n_direction;
  uint16_t n_recs;
  uint64_t max_trx_id;
  uint16_t level;
  uint64_t index_id;
};
typedef struct index_head_struct index_head_t;

void ibt_read_index_head(void *page, index_head_t *head)
{
  uint8_t *page_head = (uint8_t*)page + PAGE_HEADER;
  head->n_dir_slot = mach_read_from_2(page_head + PAGE_N_DIR_SLOTS);
  head->heap_top = mach_read_from_2(page_head + PAGE_HEAP_TOP);
  head->n_heap = mach_read_from_2(page_head + PAGE_N_HEAP);
  head->free = mach_read_from_2(page_head + PAGE_FREE);
  head->garbage = mach_read_from_2(page_head + PAGE_GARBAGE);
  head->last_insert = mach_read_from_2(page_head + PAGE_LAST_INSERT);
  head->direction = mach_read_from_2(page_head + PAGE_DIRECTION);
  head->n_direction = mach_read_from_2(page_head + PAGE_N_DIRECTION);
  head->n_recs = mach_read_from_2(page_head + PAGE_N_RECS);
  head->max_trx_id = mach_read_from_8(page_head + PAGE_MAX_TRX_ID);
  head->level = mach_read_from_8(page_head + PAGE_LEVEL);
  head->index_id = mach_read_from_8(page_head + PAGE_INDEX_ID);
}

void ibt_print_index_head(index_head_t *head)
{
  cout
  << "-n dir slot : " << head->n_dir_slot << "\n"
  << "-heap top : " << head->heap_top << "\n"
  << "-n heap : " << head->n_heap << "\n"
  << "-free : " << head->free << "\n"
  << "-garbage : " << head->garbage << "\n"
  << "-last insert : " << head->last_insert << "\n"
  << "-direction : " << head->direction << "\n"
  << "-n direction : " << head->n_direction << "\n"
  << "-n_recs : " << head->n_recs << "\n"
  << "-max_trx_id : " << head->max_trx_id << "\n"
  << "-level : " << head->level << "\n"
  << "-index_id : " << head->index_id << "\n"
  << endl;
}

void ibt_print_index_recs(void *page, index_head_t *head)
{
  //uint8_t *data = (uint8_t*)page + PAGE_DATA;
  //data + PAGE_NEW_INFIMUM;
}

void ibt_print_index(void *page)
{
  index_head_t head;
  ibt_read_index_head(page, &head);
  ibt_print_index_head(&head);
  ibt_print_index_recs(page, &head);
}

int ibt_print_page_info(void *page, uint16_t page_size)
{
  fil_head_t fil_head;

  ibt_read_fil_head(page, &fil_head);
  ibt_print_fil_head(&fil_head);
  switch (fil_head.type)
  {
  case FIL_PAGE_INDEX:
    ibt_print_index(page);
    break;
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
    //ibt_print_xdes_infos(page);
    break;
  case FIL_PAGE_TYPE_XDES:
    break;
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

bool ibt_check_ibfile_version_compatibility()
{
  //TODO : check if file can be parsed
  //According to "InnoDB: Error: the system tablespace is in a
  //file format that this version doesn't support". Copy innobase's code.
  return true;
}

uint8_t page_buffer[64 * 1024];

const char *opt_file = NULL;

int ibtool_main(int argc, const char *argv[])
{
  if (argc > 1)
    opt_file = argv[1];
  else
    opt_file = "/home/jiangyx/mywork/app/mysql-5.7.18/data/tdb1/t1.ibd";

  int flag = 0;
  int fd = open(opt_file, flag);

  if (fd < 0)
  {
    exit(-1);
  }

  cout << opt_file << endl;
  if (!ibt_check_ibfile_version_compatibility())
  {
    //TODO : print error info
    exit(-1);
  }

  uint16_t page_size = 1024 * 16;
  uint32_t page_count = 0;
  int r = 0;
  r = read(fd, page_buffer, page_size);
  while (r > 0)
  {
    cout << "-----------------------" << endl;
    page_count++;
    ibt_print_page_info(page_buffer, page_size);
    r = read(fd,  page_buffer, page_size);
    cout << "-----------------------" << endl;
  }


  close(fd);

  return 0;
}
