# THE FULL SET - every plugin this library ships, in one call.
#
# It exists for the callers that genuinely want all ten kinds: the CLI,
# the conformance suite, an app whose chain is decided at run time.
#
#     Sekreto.new(chain, plugins: Sekreto.Plugins.all())
#
# IT IS ALSO THE THING TO AVOID IF YOU CARE ABOUT WHAT GETS LOADED.
# Calling it loads every plugin module - AWS request signing, the HTTP
# client and the TLS binding under it, and the two CLIs - which is the
# cost the core/plugin split exists to remove. A lean consumer names the
# kinds it actually configures, each from its own module:
#
#     Sekreto.new(chain, plugins: [Sekreto.Plugins.Hashicorp.hashicorp()])
#
# `all/0` is a FUNCTION, not a constant, and that is not a limitation of
# elixir but the mechanism: the BEAM loads a module when something first
# calls into it, so naming `Sekreto.Plugins` loads this module alone and
# the ten behind it arrive only when `all/0` runs. Python's plugins
# package has to arrange the same laziness by hand, with a module
# `__getattr__`; here it is what the runtime already does.
#
# Nothing in `src/` calls this. See docs/design/plugin-providers.md.

defmodule Sekreto.Plugins do
  @moduledoc """
  The full set of shipped plugin definitions.

  `all/0` answers all ten, in the order every port lists them. Reaching
  it loads every plugin module; an app that configures two kinds passes
  those two.
  """

  alias Sekreto.Plugins.Aws
  alias Sekreto.Plugins.Azuresecrets
  alias Sekreto.Plugins.Boru
  alias Sekreto.Plugins.Doppler
  alias Sekreto.Plugins.Gcpsecrets
  alias Sekreto.Plugins.Hashicorp
  alias Sekreto.Plugins.Infisical
  alias Sekreto.Plugins.Onepassword
  alias Sekreto.Plugins.Secretspec

  @doc """
  Every plugin kind this library ships: ten definitions from nine
  modules, since the two aws stores share a signer and travel together.
  """
  def all do
    [
      Hashicorp.hashicorp(),
      Boru.boru(),
      Aws.awssecrets(),
      Aws.awsparams(),
      Gcpsecrets.gcpsecrets(),
      Azuresecrets.azuresecrets(),
      Onepassword.onepassword(),
      Doppler.doppler(),
      Infisical.infisical(),
      Secretspec.secretspec()
    ]
  end
end
