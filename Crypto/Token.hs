{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Encrypted tokens/tickets to keep state in the client side.
module Crypto.Token (
  -- * Configuration
    Config(..)
  , defaultConfig
  -- * Token manager
  , TokenManager
  , spawnTokenManager
  , killTokenManager
  -- * Encryption and decryption
  , encryptToken
  , decryptToken
  ) where

import Control.Concurrent
import Crypto.Cipher.AES (AES256)
import Crypto.Cipher.Types (AuthTag(..), AEADMode(..))
import qualified Crypto.Cipher.Types as C
import Crypto.Error (throwCryptoError)
import Crypto.Random (getRandomBytes)
import Data.Array.IO
import Data.Bits (xor)
import Data.ByteArray (ByteArray, Bytes)
import qualified Data.ByteArray as BA
import qualified Data.IORef as I
import Data.Int (Int64)
import Data.Word (Word16, Word64)
import Foreign.Ptr
import Foreign.Storable

----------------------------------------------------------------

-- | Configuration for token manager.
data Config = Config {
  -- | The interval to generate a new secret and remove the oldest one in minutes.
    interval   :: Int
  -- | Maximum size of secret entries. Minimum is 256 and maximum is 32767.
  , maxEntries :: Int
  }

-- | Default configuration to update secrets in 30 minutes and keep them for 10 days.
defaultConfig :: Config
defaultConfig = Config {
    interval = 30
  , maxEntries = 480
  }

----------------------------------------------------------------

-- fixme: mask
-- | The abstract data type for token manager.
data TokenManager = TokenManager {
    secrets :: IOArray Int Secret
  , currentIndex :: I.IORef Int
  , headerMask :: Header
  , threadId :: ThreadId
  }

-- | Spawning a token manager.
spawnTokenManager :: Config -> IO TokenManager
spawnTokenManager Config{..} = do
    emp <- emptySecret
    let lim = (max 256 (min maxEntries 32767)) - 1
    arr <- newArray (0, lim) emp
    update arr 0
    ref <- I.newIORef 0
    tid <- forkIO $ loop arr ref
    msk <- newHeaderMask
    return $ TokenManager arr ref msk tid
  where
    update :: IOArray Int Secret -> Int -> IO ()
    update arr idx = do
        ent <- generateSecret
        writeArray arr idx ent
    loop arr ref = do
        threadDelay (interval * 60 * 1000000)
        idx0 <- I.readIORef ref
        (_, n) <- getBounds arr
        let idx = (idx0 + 1) `mod` (n + 1)
        update arr idx
        I.writeIORef ref idx
        loop arr ref

-- | Killing a token manager.
killTokenManager :: TokenManager -> IO ()
killTokenManager TokenManager{..} = killThread threadId

----------------------------------------------------------------

getSecret :: TokenManager -> Int -> IO Secret
getSecret TokenManager{..} idx0 = do
    (_, n) <- getBounds secrets
    let idx = idx0 `mod` (n + 1)
    readArray secrets idx

----------------------------------------------------------------

data Secret = Secret {
    secretIV      :: Bytes
  , secretKey     :: Bytes
  , secretCounter :: I.IORef Int64
  }

emptySecret :: IO Secret
emptySecret = Secret BA.empty BA.empty <$> I.newIORef 0

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

indexLength :: Int
indexLength = 2

counterLength :: Int
counterLength = 8

tagLength :: Int
tagLength = 16

----------------------------------------------------------------

data Header = Header {
    headerIndex   :: Word16
  , headerCounter :: Word64
  }

instance Storable Header where
    sizeOf _    = indexLength + counterLength
    alignment _ = indexLength -- fixme
    peek p = do
        i <- peek $ castPtr p
        c <- peek (castPtr p `plusPtr` indexLength)
        return $ Header i c
    poke p (Header i c) = do
        poke (castPtr p) i
        poke (castPtr p `plusPtr` indexLength) c

newHeaderMask :: IO Header
newHeaderMask = do
    bin <- getRandomBytes (indexLength + counterLength) :: IO Bytes
    BA.withByteArray bin peek

----------------------------------------------------------------

xorHeader :: Header -> Header -> Header
xorHeader x y = Header {
    headerIndex = headerIndex x `xor` headerIndex y
  , headerCounter = headerCounter x `xor` headerCounter y
  }

addHeader :: ByteArray ba => TokenManager -> Int -> Int64 -> ba -> IO ba
addHeader TokenManager{..} idx counter cipher = do
    let hdr = Header (fromIntegral idx) (fromIntegral counter)
        mskhdr = headerMask `xorHeader` hdr
    hdrbin <- BA.create (sizeOf mskhdr) $ \ptr -> poke ptr mskhdr
    return (hdrbin `BA.append` cipher)

delHeader :: ByteArray ba => TokenManager -> ba -> IO (Int, Int64, ba)
delHeader TokenManager{..} token = do
    let (hdrbin, cipher) = BA.splitAt (indexLength + counterLength) token
    mskhdr <- BA.withByteArray hdrbin peek
    let hdr = headerMask `xorHeader` mskhdr
        idx = fromIntegral $ headerIndex hdr
        counter = fromIntegral $ headerCounter hdr
    return (idx, counter, cipher)

-- | Encrypting a target value to get a token.
encryptToken :: (Storable a, ByteArray ba)
             => TokenManager -> a -> IO ba
encryptToken mgr x = do
    idx <- I.readIORef $ currentIndex mgr
    secret <- getSecret mgr idx
    (counter, cipher) <- encrypt secret x
    addHeader mgr idx counter cipher

encrypt :: (Storable a, ByteArray ba)
        => Secret -> a -> IO (Int64, ba)
encrypt secret x = do
    counter <- I.atomicModifyIORef' (secretCounter secret) (\i -> (i+1, i))
    plain <- BA.create (sizeOf x) $ \ptr -> poke ptr x
    nonce <- makeNounce counter $ secretIV secret
    let cipher = aes256gcmEncrypt plain (secretKey secret) nonce
    return (counter, cipher)

-- | Decrypting a token to get a target value.
decryptToken :: (Storable a, ByteArray ba)
             => TokenManager -> ba -> IO (Maybe a)
decryptToken mgr token = do
    (idx, counter, cipher) <- delHeader mgr token
    secret <- getSecret mgr idx
    decrypt secret counter cipher

decrypt :: (Storable a, ByteArray ba)
        => Secret -> Int64 -> ba -> IO (Maybe a)
decrypt secret counter cipher = do
    nonce <- makeNounce counter $ secretIV secret
    let mplain = aes256gcmDecrypt cipher (secretKey secret) nonce
    case mplain of
      Nothing    -> return Nothing
      Just plain -> Just <$> BA.withByteArray plain peek

makeNounce :: forall ba . ByteArray ba => Int64 -> ba -> IO ba
makeNounce counter iv = do
    cv <- BA.create 8 $ \ptr -> poke ptr counter
    return $ iv `BA.xor` (cv :: ba)

----------------------------------------------------------------

constantAdditionalData :: Bytes
constantAdditionalData = BA.empty

aes256gcmEncrypt :: ByteArray ba
                 => ba -> Bytes -> Bytes -> ba
aes256gcmEncrypt plain key nonce = cipher `BA.append` BA.convert tag
  where
    conn = throwCryptoError (C.cipherInit key) :: AES256
    aeadIni = throwCryptoError $ C.aeadInit AEAD_GCM conn nonce
    (AuthTag tag, cipher) = C.aeadSimpleEncrypt aeadIni constantAdditionalData plain tagLength

aes256gcmDecrypt :: ByteArray ba
                 => ba -> Bytes -> Bytes -> Maybe ba
aes256gcmDecrypt ciphertag key nonce = plain
  where
    conn = throwCryptoError $ C.cipherInit key :: AES256
    aeadIni = throwCryptoError $ C.aeadInit AEAD_GCM conn nonce
    (cipher, tag) = BA.splitAt (BA.length ciphertag - tagLength) ciphertag
    authtag = AuthTag $ BA.convert tag
    plain = C.aeadSimpleDecrypt aeadIni constantAdditionalData cipher authtag
