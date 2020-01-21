-- array
-- auto-update?
-- makeIV

{-# LANGUAGE OverloadedStrings #-}

module Crypto.Token where

import Crypto.Cipher.AES (AES256)
import Crypto.Cipher.Types (AuthTag(..), AEADMode(..))
import qualified Crypto.Cipher.Types as C
import Crypto.Error (throwCryptoError)
import Crypto.Random (getRandomBytes)
import Data.ByteArray (ByteArray, Bytes)
import qualified Data.ByteArray as BA
import qualified Data.IORef as I
import Data.Int (Int64)
import Foreign.Storable

data Secret = Secret {
    secretIV      :: Bytes
  , secretKey     :: Bytes
  , secretCounter :: I.IORef Int64
  }

generateSecret :: IO Secret
generateSecret = Secret <$> genIV
                        <*> genKey
                        <*> I.newIORef 0

genKey :: IO Bytes
genKey = getRandomBytes keyLength

genIV :: IO Bytes
genIV = getRandomBytes ivLength

----------------------------------------------------------------

ivLength :: Int
ivLength = 8

keyLength :: Int
keyLength = 32

counterLength :: Int
counterLength = 8

----------------------------------------------------------------

encryptToken :: (Storable a, ByteArray ba)
             => Secret -> a -> IO ba
encryptToken secret x = do
    n <- I.atomicModifyIORef' (secretCounter secret) (\i -> (i+1, i))
    plain <- BA.create (sizeOf x) $ \ptr -> poke ptr x
    let nonce = undefined (secretIV secret) n
    return $ aes256gcmEncrypt plain (secretKey secret) nonce

decryptToken :: (Storable a, ByteArray ba)
             => Secret -> ba -> IO (Maybe a)
decryptToken secret ciphertag = do
    let (seqnum,cipher) = BA.splitAt counterLength ciphertag
        nonce = undefined (secretIV secret) seqnum
    let mplain = aes256gcmDecrypt cipher (secretKey secret) nonce
    case mplain of
      Nothing    -> return Nothing
      Just plain -> Just <$> BA.withByteArray plain peek

----------------------------------------------------------------

constantAdditionalData :: Bytes
constantAdditionalData = BA.empty

aes256gcmEncrypt :: ByteArray ba
                 => ba -> Bytes -> Bytes -> ba
aes256gcmEncrypt plain key nonce = cipher `BA.append` BA.convert tag
  where
    conn = throwCryptoError (C.cipherInit key) :: AES256
    aeadIni = throwCryptoError $ C.aeadInit AEAD_GCM conn nonce
    (AuthTag tag, cipher) = C.aeadSimpleEncrypt aeadIni constantAdditionalData plain 16

aes256gcmDecrypt :: ByteArray ba
                 => ba -> Bytes -> Bytes -> Maybe ba
aes256gcmDecrypt ciphertag key nonce = plain
  where
    conn = throwCryptoError $ C.cipherInit key :: AES256
    aeadIni = throwCryptoError $ C.aeadInit AEAD_GCM conn nonce
    (cipher, tag) = BA.splitAt (BA.length ciphertag - 16) ciphertag
    authtag = AuthTag $ BA.convert tag
    plain = C.aeadSimpleDecrypt aeadIni constantAdditionalData cipher authtag
