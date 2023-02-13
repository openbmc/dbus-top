#include <ncurses.h>
#include <stdio.h>

int main() {
  initscr();
  printw("Hello dbus-top.");
  refresh();
  getch();
  endwin();
  return 0;
}
