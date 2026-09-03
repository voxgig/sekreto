# THE FULL SET - every plugin this library ships, in one import.
#
# It exists for the callers that genuinely want all ten kinds: the CLI,
# the conformance suite, an app whose chain is decided at run time.
#
#     from voxgig_sekreto.plugins import ALL
#     Sekreto({'plugins': ALL, 'providers': [...]})
#
# IT IS ALSO THE THING TO AVOID IF YOU CARE WHAT GETS IMPORTED. Reaching
# one plugin through this package imports every other - AWS request
# signing and seven HTTP vault clients included. A lean consumer imports
# the kinds it actually configures, each from its own module:
#
#     from voxgig_sekreto.plugins.hashicorp import hashicorp
#
# See docs/design/plugin-providers.md.

from .hashicorp import hashicorp, HashicorpProvider
from .boru import boru, BoruProvider
from .aws import awssecrets, awsparams, AwssecretsProvider, AwsparamsProvider, sigv4
from .gcpsecrets import gcpsecrets, GcpsecretsProvider
from .azuresecrets import azuresecrets, AzuresecretsProvider
from .onepassword import onepassword, OnepasswordProvider
from .doppler import doppler, DopplerProvider
from .infisical import infisical, InfisicalProvider
from .secretspec import secretspec, SecretspecProvider
from .httpjson import fetchjson

ALL = [
    hashicorp, boru, awssecrets, awsparams, gcpsecrets, azuresecrets,
    onepassword, doppler, infisical, secretspec,
]

__all__ = [
    'ALL',
    'hashicorp', 'boru', 'awssecrets', 'awsparams', 'gcpsecrets', 'azuresecrets',
    'onepassword', 'doppler', 'infisical', 'secretspec',
    'HashicorpProvider', 'BoruProvider', 'AwssecretsProvider', 'AwsparamsProvider',
    'GcpsecretsProvider', 'AzuresecretsProvider', 'OnepasswordProvider',
    'DopplerProvider', 'InfisicalProvider', 'SecretspecProvider',
    'sigv4', 'fetchjson',
]
