#include <stdint.h>

int print_page_info(void *page, uint16_t page_size);

int main(int argc, const char *argv[])
{
  print_page_info(0, 16 * 1024);
  return 0;
}
