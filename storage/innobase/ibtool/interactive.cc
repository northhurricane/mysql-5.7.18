#include <string>
#include <iostream>
#include <algorithm>
#include <string.h>

using namespace std;

const char *OP_LOAD = "load";

string ibt_read_command()
{
  cout << "ibt:";
  string s;
  getline(std::cin, s);
  return s;
}

void ibt_do_command(string cmd)
{
  string op = "load";
  if (strcmp(op.c_str(), OP_LOAD) == 0)
  {
    //TODO : load ibd file
  }
}

bool ibt_interactive_quit(string cmd)
{
  transform(cmd.begin(), cmd.end(), cmd.begin(), ::tolower);
  if (strcmp(cmd.c_str(), "quit") == 0)
    return true;
  return false;
}

int ibt_interactive()
{
  while (true)
  {
    string cmd = ibt_read_command();

    if (ibt_interactive_quit(cmd))
      break;

    ibt_do_command(cmd);
  }
  return 0;
}
