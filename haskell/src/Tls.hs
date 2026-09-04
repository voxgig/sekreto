-- | The Haskell half of the transport binding: FFI declarations, and a
-- connection that reads and writes bytes.
--
-- GHC's boot libraries have no networking at all - not even a socket - so
-- both the socket and the TLS come from C. `src/tls.c` is the only file in
-- the port that names OpenSSL or a socket; this file is the only one that
-- names `src/tls.c`. Everything above works in terms of 'Conn'.
--
-- The audit surface is `-lssl -lcrypto`: the distribution's OpenSSL, and
-- nothing else. The shim is compiled from source by the port's own
-- Makefile, so no package index is involved.

{-# LANGUAGE ForeignFunctionInterface #-}

module Tls
  ( Conn (..),
    cabundlevar,
    dial,
    havetls,
  )
where

import qualified Data.ByteString as B
import Bytes (utf8encode)
import Foreign.C.String (CString, peekCAString)
import Foreign.C.Types (CChar, CInt (..))
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Ptr (Ptr, nullPtr)
import System.Environment (lookupEnv)

-- | The environment variable naming extra trust roots, as a PEM bundle.
-- One name across every port, so a private CA is configured the same way
-- wherever sekreto runs.
cabundlevar :: String
cabundlevar = "SEKRETO_CA_BUNDLE"

-- | How long any single round-trip may take. Ports carry the same bound.
timeoutms :: Int
timeoutms = 10000

-- | An open connection, plaintext or TLS. A read of zero bytes is the end
-- of the stream.
data Conn = Conn
  { connsend :: B.ByteString -> IO (Either String ()),
    connrecv :: Int -> IO (Either String B.ByteString),
    connclose :: IO ()
  }

foreign import ccall safe "sekreto_connect"
  c_connect :: CString -> CString -> CInt -> Ptr CChar -> CInt -> IO CInt

foreign import ccall unsafe "sekreto_close"
  c_close :: CInt -> IO ()

foreign import ccall safe "sekreto_send"
  c_send :: CInt -> Ptr CChar -> CInt -> IO CInt

foreign import ccall safe "sekreto_recv"
  c_recv :: CInt -> Ptr CChar -> CInt -> IO CInt

foreign import ccall unsafe "sekreto_why"
  c_why :: IO CString

foreign import ccall safe "sekreto_tls_connect"
  c_tlsconnect :: CInt -> CString -> CString -> Ptr CChar -> CInt -> IO (Ptr ())

foreign import ccall safe "sekreto_tls_send"
  c_tlssend :: Ptr () -> Ptr CChar -> CInt -> IO CInt

foreign import ccall safe "sekreto_tls_recv"
  c_tlsrecv :: Ptr () -> Ptr CChar -> CInt -> IO CInt

foreign import ccall unsafe "sekreto_tls_free"
  c_tlsfree :: Ptr () -> IO ()

foreign import ccall unsafe "sekreto_tls_why"
  c_tlswhy :: IO CString

foreign import ccall unsafe "sekreto_have_tls"
  c_havetls :: IO CInt

-- | Does this build have a TLS backend? A build without one must raise on
-- every https address rather than quietly reach nowhere.
havetls :: IO Bool
havetls = (1 ==) <$> c_havetls

-- | A Haskell string as a NUL-terminated C string, UTF-8 encoded.
-- `withCString` would go through the process locale, which is C under the
-- wiped environment the integration suite runs the CLI in.
withtext :: String -> (CString -> IO a) -> IO a
withtext text = B.useAsCString (utf8encode text)

-- | Connect to host:port, and hand the socket to OpenSSL when the address
-- is https. The connect is bounded across every address the name resolves
-- to, not per address.
dial :: String -> Int -> Bool -> IO (Either String Conn)
dial host port usetls =
  withtext host $ \chost ->
    withtext (show port) $ \cport ->
      allocaBytes errlen $ \err -> do
        fd <- c_connect chost cport (fromIntegral timeoutms) err (fromIntegral errlen)

        if 0 > fd
          then Left <$> peekCAString err
          else
            if usetls
              then starttls fd host
              else pure (Right (plainconn fd))

errlen :: Int
errlen = 256

plainconn :: CInt -> Conn
plainconn fd =
  Conn
    { connsend = \payload ->
        B.useAsCStringLen payload $ \(buf, len) -> do
          wrote <- c_send fd buf (fromIntegral len)
          if 0 > wrote then Left <$> lasterror c_why else pure (Right ()),
      connrecv = \want ->
        allocaBytes want $ \buf -> do
          got <- c_recv fd buf (fromIntegral want)
          if 0 > got
            then Left <$> lasterror c_why
            else Right <$> B.packCStringLen (buf, fromIntegral got),
      connclose = c_close fd
    }

-- | Complete a TLS handshake over an already-connected socket, verifying
-- the chain and the host name. The socket is closed on failure, since the
-- caller never sees it.
--
-- The trust bundle is read here rather than in C, so that the environment
-- stays Haskell's business: an empty value means unset, and a path that
-- cannot be read adds no roots and raises nothing.
starttls :: CInt -> String -> IO (Either String Conn)
starttls fd host = do
  bundle <- maybe "" id <$> lookupEnv cabundlevar

  withtext host $ \chost ->
    withtext bundle $ \cbundle ->
      allocaBytes errlen $ \err -> do
        handle <- c_tlsconnect fd chost cbundle err (fromIntegral errlen)

        if nullPtr == handle
          then do
            why <- peekCAString err
            c_close fd
            pure (Left why)
          else pure (Right (tlsconn handle fd))

tlsconn :: Ptr () -> CInt -> Conn
tlsconn handle fd =
  Conn
    { connsend = \payload ->
        B.useAsCStringLen payload $ \(buf, len) -> do
          wrote <- c_tlssend handle buf (fromIntegral len)
          if 0 > wrote then Left <$> lasterror c_tlswhy else pure (Right ()),
      connrecv = \want ->
        allocaBytes want $ \buf -> do
          got <- c_tlsrecv handle buf (fromIntegral want)
          if 0 > got
            then Left <$> lasterror c_tlswhy
            else Right <$> B.packCStringLen (buf, fromIntegral got),
      -- SSL_set_fd does not take ownership of the descriptor, so the
      -- socket is closed here as well as the connection freed.
      connclose = c_tlsfree handle >> c_close fd
    }

lasterror :: IO CString -> IO String
lasterror source = do
  text <- source
  if nullPtr == text then pure "transport failure" else peekCAString text
