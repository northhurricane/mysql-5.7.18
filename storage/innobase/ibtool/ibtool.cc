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
#include "trx0undo.h" //for undo page

void stop_for_assert()
{
  int i = 0;
  i++;
}

void ibt_assert(bool a)
{
  if (!a)
    stop_for_assert();
  assert(a);
}

#define IBT_ASSERT(V) ibt_assert(V)

/*
  typies of page and parse work situdation
  FIL_PAGE_INDEX        : head part done. records part not yet
  FIL_PAGE_RTREE        : not yet
  FIL_PAGE_UNDO_LOG     : not yet
  FIL_PAGE_INODE        : done
  FIL_PAGE_IBUF_FREE_LIST : not yet
  FIL_PAGE_TYPE_ALLOCATED : not yet
  FIL_PAGE_IBUF_BITMAP  : not yet
  FIL_PAGE_TYPE_SYS     : not yet
  FIL_PAGE_TYPE_TRX_SYS : not yet
  FIL_PAGE_TYPE_FSP_HDR : header parse ok. xdes part reference FIL_PAGE_TYPE_XDES
  FIL_PAGE_TYPE_XDES    : not yet
  FIL_PAGE_TYPE_BLOB    : not yet
  FIL_PAGE_TYPE_ZBLOB   : not yet
  FIL_PAGE_TYPE_ZBLOB2  : not yet
  FIL_PAGE_TYPE_UNKNOWN : not yet
  FIL_PAGE_COMPRESSED   : not yet
  FIL_PAGE_ENCRYPTED    : not yet
  FIL_PAGE_COMPRESSED_AND_ENCRYPTED : not yet
  FIL_PAGE_ENCRYPTED_RTREE : not yet
*/

using namespace std;

//copied from flst_read_addr without mtr
void
flst_read_addr_raw(uint8_t *paddr, fil_addr_t *addr)
{
  //TODO : 该函数现在是错误的是，flst的格式不是如此
  addr->page = mach_read_from_4((uint8_t*)paddr + FIL_ADDR_PAGE);
  addr->boffset = mach_read_from_2((uint8_t*)paddr + FIL_ADDR_BYTE);
}

struct flst_base_node_struct
{
  uint32_t len;
  fil_addr_t first;
  fil_addr_t last;
};
typedef struct flst_base_node_struct flst_base_node2_t;

void
flst_read_base_node(uint8_t *p, flst_base_node2_t *base_node)
{
  base_node->len = mach_read_from_4(p + FLST_LEN);
  flst_read_addr_raw(p + FLST_FIRST, &base_node->first);
  flst_read_addr_raw(p + FLST_LAST, &base_node->last);
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

/*
  every page has fil head
*/
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

/*
  FIL_PAGE_TYPE_FSP_HDR
*/
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

void ibt_read_fsp_hdr(void *page, fsp_t *fsp)
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
  //TODO : 
  stringstream ss;
  ss
  << "seg id : " << xdes->id << "\n"
  << "flst node : prev "
  << "flst node : next "
  << "\n";
  return ss.str();
}

void ibt_print_xdes_infos(void *page, fil_head_t *head)
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

/* inode page whose type is FIL_PAGE_INODE */
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
  if (entry2->seg_id == 0)
    return;
  entry2->not_full_n_used = mach_read_from_4(entry + FSEG_NOT_FULL_N_USED);
  flst_read_base_node(entry + FSEG_FREE, &entry2->free);
  flst_read_base_node(entry + FSEG_NOT_FULL, &entry2->not_full);
  flst_read_base_node(entry + FSEG_FULL, &entry2->full);
  entry2->magic = mach_read_from_4(entry + FSEG_MAGIC_N);
  IBT_ASSERT(entry2->magic == FSEG_MAGIC_N_VALUE);
  //assert(entry2->magic == FSEG_MAGIC_N_VALUE);
  memcpy(entry2->frag_array_entry, entry + FSEG_FRAG_ARR
         , FSEG_FRAG_ARR_N_SLOTS * FSEG_FRAG_SLOT_SIZE);
}

void ibt_print_inode_entry(inode_entry_t *entry)
{
  cout <<
  "seg_id : " << entry->seg_id << ", used : " << entry->not_full_n_used << "\n"
  ;
}

void ibt_print_inode(void *page)
{
  uint8_t *page_node = (uint8_t*)page + FSEG_PAGE_DATA;
  fil_addr_t prev, next;
  flst_read_addr_raw(page_node + FLST_PREV, &prev);
  flst_read_addr_raw(page_node + FLST_NEXT, &next);

  //Each INODE page contains 85 file segment INODE entries (for a 16 KiB page)
  //TODO : find definition of segment inode entries number
  uint8_t *entry = (uint8_t*)page + FSEG_ARR_OFFSET;
  inode_entry_t entry2;
  for (int i = 0; i < 85; i++)
  {
    ibt_read_inode_info(entry, &entry2);
    if (entry2.seg_id != 0)
      ibt_print_inode_entry(&entry2);
    entry += FSEG_INODE_SIZE;
  }
}

///index page whose type is FIL_PAGE_INDEX
struct index_fseg_struct
{
  uint32_t space_id;
  uint32_t page_no;
  uint16_t offset;
};
typedef struct index_fseg_struct index_fseg_t;

void ibt_read_index_seg(uint8_t *seg, index_fseg_t *fseg)
{
  fseg->space_id = mach_read_from_4(seg + FSEG_HDR_SPACE);
  fseg->page_no = mach_read_from_4(seg + FSEG_HDR_PAGE_NO);
  fseg->offset = mach_read_from_2(seg + FSEG_HDR_OFFSET);
}

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
  index_fseg_t leaf_seg;
  index_fseg_t internal_seg;
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
  ibt_read_index_seg(page_head + PAGE_BTR_SEG_LEAF, &head->leaf_seg);
  ibt_read_index_seg(page_head + PAGE_BTR_SEG_TOP, &head->internal_seg);
}

string
ibt_index_fseg2str(index_fseg_t *seg)
{
  stringstream ss;
  ss
  << "{space id : " << seg->space_id
  << " | page no : " << seg->page_no
  << " | offset : " << seg->offset
  << "}";
  return ss.str();
}

void ibt_print_index_head(index_head_t *head)
{
  string page_compact;
  if (head->n_heap & 0x8000)
    page_compact = "-page compact : true\n";
  else
    page_compact = "-page compact : false\n";
  cout
  << "-n dir slot : " << head->n_dir_slot << "\n"
  << "-heap top : " << head->heap_top << "\n"
  << page_compact
  << "-n heap : " << (head->n_heap & 0x7fff) << "\n"
  << "-free : " << head->free << "\n"
  << "-garbage : " << head->garbage << "\n"
  << "-last insert : " << head->last_insert << "\n"
  << "-direction : " << head->direction << "\n"
  << "-n direction : " << head->n_direction << "\n"
  << "-n_recs : " << head->n_recs << "\n"
  << "-max_trx_id : " << head->max_trx_id << "\n"
  << "-level : " << head->level << "\n"
  << "-index_id : " << head->index_id << "\n"
  << "-leaf_seg : " << ibt_index_fseg2str(&head->leaf_seg) << "\n"
  << "-internal_seg : " << ibt_index_fseg2str(&head->internal_seg) << "\n"
  << endl;
}

uint16_t ibt_get_next_rec_off(void *page, index_head_t *head, uint16_t rec_off)
{
  uint16_t next_rec_off = 0;
  uint8_t *rec = (uint8_t*)page + rec_off;
  next_rec_off = mach_read_from_2(rec - REC_NEXT);
  //COMPACT condition different from innobase code, here keep N_HEAP info
  //innobase get compact flag by page_rec_is_comp. align page, and then calc compact flag
  if (head->n_heap & 0x8000)
  {
    //COMPACT
    return ut_align_offset(rec + next_rec_off, UNIV_PAGE_SIZE);
  }

  return next_rec_off;
}

void ibt_print_index_recs(void *page, index_head_t *head)
{
  uint16_t inf_rec_off = 0, sup_rec_off = 0;
  uint16_t rec_off = 0;

  //uint8_t *data = (uint8_t*)page + PAGE_DATA;
  //data + PAGE_NEW_INFIMUM;
  if (head->n_heap & 0x8000)
  {
    //COMPACT mode. Use PAGE_NEW_INFIMUM and PAGE_NEW_SUPREMUM
    inf_rec_off = PAGE_NEW_INFIMUM;
    sup_rec_off = PAGE_NEW_SUPREMUM;
  }
  else
  {
    //REDUNDANT mode. Use PAGE_OLD_INFIMUM and PAGE_OLD_SUPREMUM
    inf_rec_off = PAGE_OLD_INFIMUM;
    sup_rec_off = PAGE_OLD_SUPREMUM;
  }
  rec_off = ibt_get_next_rec_off(page, head, inf_rec_off);
  cout << "infimum rec offset : " << inf_rec_off << "\n";
  int counter = 0;
  while (rec_off != sup_rec_off)
  {
    counter++;
    if (counter > head->n_recs)
    {
      cout << "check page sanity." << endl;
      exit(-1);
    }
    cout << "rec " << counter << " offset : " << rec_off << "\n";
    rec_off = ibt_get_next_rec_off(page, head, rec_off);
  }
  cout << "supremum rec offset : " << sup_rec_off << "\n";
}

void ibt_print_index(void *page)
{
  index_head_t head;
  ibt_read_index_head(page, &head);
  ibt_print_index_head(&head);
  ibt_print_index_recs(page, &head);
}

/* undo page whose type is FIL_PAGE_UNDO_LOG */
/*
  reference
  1,innochecksum.cc:parse_page:case FIL_PAGE_UNDO_LOG
  2,trx0undo.h:TRX_UNDO_PAGE_HDR etc
*/

/*
  structs to store undo information. first part is undo head and then follow seg head,
  undo info after seg head
*/
/*general head*/
typedef struct undo_head_struct undo_head_t;
/*seg head*/
typedef struct undo_seg_head_struct undo_seg_head_t;
typedef struct undo_info_struct undo_info_t;

struct undo_head_struct
{
  uint16_t type;
  uint16_t start;
  uint16_t free;
  fil_addr_t node;
};

void ibt_get_undo_head(void *page, undo_head_t *head)
{
  uint8_t *undo_head = (uint8_t*)page + TRX_UNDO_PAGE_HDR;
  head->type = mach_read_from_2(undo_head + TRX_UNDO_PAGE_TYPE);
  head->start = mach_read_from_2(undo_head + TRX_UNDO_PAGE_START);
  head->free = mach_read_from_2(undo_head + TRX_UNDO_PAGE_FREE);
  flst_read_addr_raw(undo_head + TRX_UNDO_PAGE_NODE, &head->node);
}

void ibt_print_undo_head(undo_head_t *head)
{
  string type;
  if (head->type == TRX_UNDO_INSERT)
    type = "undo_insert";
  else
    type = "undo_update";
  cout
  << "type : " << type << "\n"
  << "start : " << head->start << "\n"
  << "free : " << head->free << "\n"
  << "node : " << head->node.page << "-" << head->node.boffset
  ;
}

struct undo_seg_head_struct
{
  uint16_t state;
  uint16_t last_log;
  index_fseg_t fseg;
  flst_base_node2_t page_list;
};

void ibt_get_undo_seg(void *page, undo_seg_head_t* head)
{
  uint8_t *seg_head = (uint8_t*)page + TRX_UNDO_SEG_HDR;
  head->state = mach_read_from_2(seg_head + TRX_UNDO_STATE);
  head->last_log = mach_read_from_2(seg_head + TRX_UNDO_LAST_LOG);
  ibt_read_index_seg(seg_head + TRX_UNDO_FSEG_HEADER, &head->fseg);
  flst_read_base_node(seg_head + TRX_UNDO_PAGE_LIST, &head->page_list);
}

string ibt_undo_state2str(uint16_t state)
{
  switch (state)
  {
  case TRX_UNDO_ACTIVE:
    return "ACTIVE";
  case TRX_UNDO_CACHED:
    return "CACHED";
  case TRX_UNDO_TO_FREE:
    return "TO FREE";
  case TRX_UNDO_TO_PURGE:
    return "TO PURGE";
  case TRX_UNDO_PREPARED:
    return "PREPARED";
  default:
    assert(false);
  }
  return "";
}

void ibt_print_undo_seg_head(undo_seg_head_t *head)
{
  cout
  << "state : " << ibt_undo_state2str(head->state) << "\n"
  << "last log : " << head->last_log
  << "seg : " << ibt_index_fseg2str(&head->fseg) << "\n"
  << "page list : " << ibt_flst_base_node2str(&head->page_list) << "\n"
  ;
}

struct undo_info_struct
{
  uint64_t trx_id;
  uint64_t trx_no;
  uint16_t del_mark;
  uint16_t last_log;
  uint8_t  xid_exist;
  uint8_t  dict_trans;
  uint64_t table_id;
  uint16_t next_log;
  uint16_t prev_log;
  xdes_flst_node_t node;
  //xa part. meaningful when xid_exist is true.
  XID      xid;
  uint32_t xa_format;
  uint32_t xa_trid_len;
  uint32_t xa_bqual_len;
  uint8_t  xa_xid[XIDDATASIZE];
};

void
ibt_undo_read_xid(
  /*==============*/
  uint8_t*    log_hdr,/*!< in: undo log header */
  XID*        xid)    /*!< out: X/Open XA Transaction Identification */
{
  xid->set_format_id(static_cast<long>(mach_read_from_4(
    log_hdr + TRX_UNDO_XA_FORMAT)));

  xid->set_gtrid_length(static_cast<long>(mach_read_from_4(
    log_hdr + TRX_UNDO_XA_TRID_LEN)));

  xid->set_bqual_length(static_cast<long>(mach_read_from_4(
    log_hdr + TRX_UNDO_XA_BQUAL_LEN)));

  xid->set_data(log_hdr + TRX_UNDO_XA_XID, XIDDATASIZE);
}

void ibt_get_undo_info(void *page, undo_info_t *info, uint16_t undo_offset)
{
  uint8_t *undo = (uint8_t*)page + undo_offset;
  info->trx_id = mach_read_from_8(undo + TRX_UNDO_TRX_ID);
  info->trx_no = mach_read_from_8(undo + TRX_UNDO_TRX_NO);
  info->del_mark = mach_read_from_2(undo + TRX_UNDO_DEL_MARKS);
  info->last_log = mach_read_from_2(undo + TRX_UNDO_LOG_START);
  info->xid_exist = mach_read_from_1(undo + TRX_UNDO_XID_EXISTS);
  info->dict_trans = mach_read_from_1(undo + TRX_UNDO_DICT_TRANS);
  info->table_id = mach_read_from_8(undo + TRX_UNDO_TABLE_ID);
  info->next_log = mach_read_from_2(undo + TRX_UNDO_NEXT_LOG);
  info->prev_log = mach_read_from_2(undo + TRX_UNDO_PREV_LOG);
  flst_read_addr_raw(undo + TRX_UNDO_HISTORY_NODE + FLST_PREV, &info->node.prev);
  flst_read_addr_raw(undo + TRX_UNDO_HISTORY_NODE + FLST_NEXT, &info->node.next);
  if (info->xid_exist)
    ibt_undo_read_xid(undo, &info->xid);
}

string ibt_xid2str(XID *xid)
{
  stringstream ss;
  ss
  << "XID { formatID : " << xid->get_format_id()
  << " | gtrid len :" << xid->get_gtrid_length()
  << " | bqual len : " << xid->get_bqual_length()
  << " | xdata : " << xid->get_data()
  << "}\n"
  ;
  return ss.str();
}

void ibt_print_undo_info(undo_info_t *info)
{
  string xid_info("");
  cout
  << "trx id : " << info->trx_id << "\n"
  << "trx no : " << info->trx_no << "\n"
  << "delete mark : " << info->del_mark << "\n"
  << "last log : " << info->last_log << "\n"
  << "has xid : " << (info->xid_exist ? "true" : "false") << "\n"
  << "dict trans : " << info->dict_trans << "\n"
  << "table id : " << info->table_id << "\n"
  << "next log : " << info->next_log << "\n"
  << "prev_log : " << info->prev_log << "\n"
  //TODO : print flst node
  //TODO : print XID class
  << ibt_xid2str(&info->xid)
  ;
}

void ibt_print_undo(void *page)
{
  undo_head_t head;
  ibt_get_undo_head(page, &head);
  ibt_print_undo_head(&head);
  undo_seg_head_t seg_head;
  ibt_get_undo_seg(page, &seg_head);
  ibt_print_undo_seg_head(&seg_head);
  undo_info_t undo_info;
  ibt_get_undo_info(page, &undo_info, seg_head.last_log);
  ibt_print_undo_info(&undo_info);
}

/* undo page whose type is FIL_PAGE_IBUF_FREE_LIST */
/*
  reference ibuf0ibuf.cc
*/
void ibt_print_ibuf_free_list(void *page, fil_head_t *fil_head)
{
  //TODO : learn insert buffer now.
  cout
  << "ibuf page"
  << endl;
  ;
}

/* allocated page whose type is FIL_PAGE_TYPE_ALLOCATED*/
void ibt_print_allocated(void *page, fil_head_t *fil_head)
{
  //page is newly allocated, nothing to print
}

/* ibuf bitmap page whose type is FIL_PAGE_IBUF_BITMAP*/
void ibt_print_ibuf_bitmap(void *page, fil_head_t *fil_head)
{
  //not sure how to print it
}

/* page whose type is FIL_PAGE_TYPE_SYS*/
void ibt_print_sys(void *page, fil_head_t *fil_head)
{
  //not sure how to print it
}

/* page whose type is FIL_PAGE_TYPE_TRX_SYS*/
void ibt_print_trx_sys(void *page, fil_head_t *fil_head)
{
  //not sure how to print it
}

/* page whose type is FIL_PAGE_TYPE_BLOB*/
void ibt_print_blob(void *page, fil_head_t *fil_head)
{
  //not sure how to print it
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
    break;
  case FIL_PAGE_UNDO_LOG:
    ibt_print_undo(page);
    break;
  case FIL_PAGE_INODE:
    ibt_print_inode(page);
    break;
  case FIL_PAGE_IBUF_FREE_LIST:
    ibt_print_ibuf_free_list(page, &fil_head);
    break;
  case FIL_PAGE_TYPE_ALLOCATED:
    ibt_print_allocated(page, &fil_head);
    break;
  case FIL_PAGE_IBUF_BITMAP:
    ibt_print_ibuf_bitmap(page, &fil_head);
    break;
  case FIL_PAGE_TYPE_SYS:
    ibt_print_sys(page, &fil_head);
    break;
  case FIL_PAGE_TYPE_TRX_SYS:
    ibt_print_trx_sys(page, &fil_head);
    break;
  case FIL_PAGE_TYPE_FSP_HDR:
    fsp_t fsp;
    ibt_read_fsp_hdr(page, &fsp);
    ibt_print_fsp_hdr(&fsp);
    //FSP是特殊的XDES类型的页面
    //ibt_print_xdes_infos(page);
    break;
  case FIL_PAGE_TYPE_XDES:
    ibt_print_xdes_infos(page, &fil_head);
    break;
  case FIL_PAGE_TYPE_BLOB:
    ibt_print_blob(page, &fil_head);
    break;
  case FIL_PAGE_TYPE_ZBLOB:
  case FIL_PAGE_TYPE_ZBLOB2:
  case FIL_PAGE_TYPE_UNKNOWN:
  case FIL_PAGE_COMPRESSED:
  case FIL_PAGE_ENCRYPTED:
  case FIL_PAGE_COMPRESSED_AND_ENCRYPTED:
  case FIL_PAGE_ENCRYPTED_RTREE:
    cout << "not done yet" << endl;
    //print nothing now
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

uint8_t page_buffer_inner[64 * 1024 * 2];

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

  uint8_t *page_buffer = (uint8_t*)ut_align(page_buffer_inner, UNIV_PAGE_SIZE);
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
