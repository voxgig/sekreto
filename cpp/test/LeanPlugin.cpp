// ONE PLUGIN, ON ITS OWN - what a lean consumer's link line looks like.
//
// `make lean` links this against ONE plugin object plus only the shared
// files that plugin declares it needs, the core and the plugin host. A kind
// that reached into a neighbour would still compile as part of the whole
// archive with nothing to give it away; here it fails to link, naming the
// symbol.
//
// It takes no plugin at compile time and calls nothing: the object files on
// the link line are the whole subject. Every symbol a plugin translation
// unit references has to be satisfied by what is beside it, and that is the
// question being asked.

#include <iostream>

int main() {
  std::cout << "lean: linked\n";
  return 0;
}
