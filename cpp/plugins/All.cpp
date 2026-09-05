#include "All.hpp"

#include "Aws.hpp"
#include "Azuresecrets.hpp"
#include "Boru.hpp"
#include "Doppler.hpp"
#include "Gcpsecrets.hpp"
#include "Hashicorp.hpp"
#include "Infisical.hpp"
#include "Onepassword.hpp"
#include "Secretspec.hpp"

namespace sekreto {

std::vector<Definition> allplugins() {
  return {
      hashicorp(), boru(),        awssecrets(), awsparams(), gcpsecrets(),
      azuresecrets(), onepassword(), doppler(),    infisical(), secretspec(),
  };
}

}  // namespace sekreto
