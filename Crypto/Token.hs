{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Encrypted tokens/tickets to keep state in the client side.
--   For security reasons, 'Storable' data types MUST be fixed-size
--   when stored (i.e. serialized into the memory).
module Crypto.Token (
    -- * Configuration
    Config (..),
    defaultConfig,

    -- * Token manager
    TokenManager,
    spawnTokenManager,
    killTokenManager,

    -- * Encryption and decryption
    encryptToken,
    decryptToken,
) where

import Control.AutoUpdate
import Crypto.Cipher.AES (AES256)
import Crypto.Cipher.Types (AEADMode (..), AuthTag (..))
import qualified Crypto.Cipher.Types as C
import Crypto.Error (maybeCryptoError, throwCryptoError)
import Crypto.Random (getRandomBytes)
import Data.Array.IO
import Data.Bits (xor)
import Data.ByteArray (ByteArray, Bytes)
import qualified Data.ByteArray as BA
import qualified Data.IORef as I
import Data.Word (Word16, Word64)
import Foreign.Ptr
import Foreign.Storable

----------------------------------------------------------------

type Index = Word16
type Counter = Word64

-- | Configuration for token manager.
data Config = Config
    { interval :: Int
    -- ^ The interval to generate a new secret and remove the oldest one in minutes.
    , maxEntries :: Int
    -- ^ Maximum size of secret entries. Minimum is 256 and maximum is 32767.
    }
    deriving (Eq, Show)

-- | Default configuration to update secrets in 30 minutes and keep them for 10 days.
--
-- >>> defaultConfig
-- Config {interval = 30, maxEntries = 480}
defaultConfig :: Config
defaultConfig =
    Config
        { interval = 30
        , maxEntries = 480
        }

----------------------------------------------------------------

-- fixme: mask

-- | The abstract data type for token manager.
data TokenManager = TokenManager
    { headerMask :: Header
    , getEncryptSecret :: IO (Secret, Index)
    , getDecryptSecret :: Index -> IO Secret
    }

-- | Spawning a token manager based on auto-update.
--   This thread will sleep if 'getEncryptSecret' is not used.
spawnTokenManager :: Config -> IO TokenManager
spawnTokenManager Config{..} = do
    emp <- emptySecret
    let lim = fromIntegral (max 256 (min maxEntries 32767)) - 1
    arr <- newArray (0, lim) emp
    ent <- generateSecret
    writeArray arr 0 ent
    ref <- I.newIORef 0
    getEncSec <-
        mkAutoUpdate
            defaultUpdateSettings
                { updateAction = update arr ref
                , updateFreq = interval * 1000000
                }
    msk <- newHeaderMask
    return $ TokenManager msk getEncSec (readSecret arr)
  where
    update :: IOArray Index Secret -> I.IORef Index -> IO (Secret, Index)
    update arr ref = do
        idx0 <- I.readIORef ref
        (_, n) <- getBounds arr
        let idx = (idx0 + 1) `mod` (n + 1)
        sec <- generateSecret
        writeArray arr idx sec
        I.writeIORef ref idx
        return (sec, idx)

-- | Killing a token manager.
--   Deprecated and no effecrt currently
killTokenManager :: TokenManager -> IO ()
killTokenManager _ = return ()

----------------------------------------------------------------

readSecret :: IOArray Index Secret -> Index -> IO Secret
readSecret secrets idx0 = do
    (_, n) <- getBounds secrets
    let idx = idx0 `mod` (n + 1)
    readArray secrets idx

----------------------------------------------------------------

data Secret = Secret
    { secretIV :: Bytes
    , secretKey :: Bytes
    , secretCounter :: I.IORef Counter
    }

emptySecret :: IO Secret
emptySecret = Secret BA.empty BA.empty <$> I.newIORef 0

generateSecret :: IO Secret
generateSecret =
    Secret
        <$> genIV
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

data Header = Header
    { headerIndex :: Index
    , headerCounter :: Counter
    }

instance Storable Header where
    sizeOf _ = indexLength + counterLength
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
xorHeader x y =
    Header
        { headerIndex = headerIndex x `xor` headerIndex y
        , headerCounter = headerCounter x `xor` headerCounter y
        }

addHeader :: ByteArray ba => TokenManager -> Index -> Counter -> ba -> IO ba
addHeader TokenManager{..} idx counter cipher = do
    let hdr = Header idx counter
        mskhdr = headerMask `xorHeader` hdr
    hdrbin <- BA.create (sizeOf mskhdr) $ \ptr -> poke ptr mskhdr
    return (hdrbin `BA.append` cipher)

delHeader
    :: ByteArray ba => TokenManager -> ba -> IO (Maybe (Index, Counter, ba))
delHeader TokenManager{..} token
    | BA.length token < minlen = return Nothing
    | otherwise = do
        let (hdrbin, cipher) = BA.splitAt minlen token
        mskhdr <- BA.withByteArray hdrbin peek
        let hdr = headerMask `xorHeader` mskhdr
            idx = headerIndex hdr
            counter = headerCounter hdr
        return $ Just (idx, counter, cipher)
  where
    minlen = indexLength + counterLength

-- | Encrypting a target value to get a token.
encryptToken
    :: (Storable a, ByteArray ba)
    => TokenManager
    -> a
    -> IO ba
encryptToken mgr x = do
    (secret, idx) <- getEncryptSecret mgr
    (counter, cipher) <- encrypt secret x
    addHeader mgr idx counter cipher

encrypt
    :: (Storable a, ByteArray ba)
    => Secret
    -> a
    -> IO (Counter, ba)
encrypt secret x = do
    counter <- I.atomicModifyIORef' (secretCounter secret) (\i -> (i + 1, i))
    plain <- BA.create (sizeOf x) $ \ptr -> poke ptr x
    nonce <- makeNonce counter $ secretIV secret
    let cipher = aes256gcmEncrypt plain (secretKey secret) nonce
    return (counter, cipher)

-- | Decrypting a token to get a target value.
decryptToken
    :: (Storable a, ByteArray ba)
    => TokenManager
    -> ba
    -> IO (Maybe a)
decryptToken mgr token = do
    mx <- delHeader mgr token
    case mx of
        Nothing -> return Nothing
        Just (idx, counter, cipher) -> do
            secret <- getDecryptSecret mgr idx
            decrypt secret counter cipher

decrypt
    :: forall a ba
     . (Storable a, ByteArray ba)
    => Secret
    -> Counter
    -> ba
    -> IO (Maybe a)
decrypt secret counter cipher = do
    nonce <- makeNonce counter $ secretIV secret
    let mplain = aes256gcmDecrypt cipher (secretKey secret) nonce
        expect = sizeOf (undefined :: a)
    case mplain of
        Just plain
            | BA.length plain == expect -> Just <$> BA.withByteArray plain peek
        _ -> return Nothing

makeNonce :: forall ba. ByteArray ba => Counter -> ba -> IO ba
makeNonce counter iv = do
    cv <- BA.create ivLength $ \ptr -> poke ptr counter
    return $ iv `BA.xor` (cv :: ba)

----------------------------------------------------------------

constantAdditionalData :: Bytes
constantAdditionalData = BA.empty

aes256gcmEncrypt
    :: ByteArray ba
    => ba
    -> Bytes
    -> Bytes
    -> ba
aes256gcmEncrypt plain key nonce = cipher `BA.append` BA.convert tag
  where
    conn = throwCryptoError (C.cipherInit key) :: AES256
    aeadIni = throwCryptoError $ C.aeadInit AEAD_GCM conn nonce
    (AuthTag tag, cipher) = C.aeadSimpleEncrypt aeadIni constantAdditionalData plain tagLength

aes256gcmDecrypt
    :: ByteArray ba
    => ba
    -> Bytes
    -> Bytes
    -> Maybe ba
aes256gcmDecrypt ctexttag key nonce = do
    aes <- maybeCryptoError $ C.cipherInit key :: Maybe AES256
    aead <- maybeCryptoError $ C.aeadInit AEAD_GCM aes nonce
    let (ctext, tag) = BA.splitAt (BA.length ctexttag - tagLength) ctexttag
        authtag = AuthTag $ BA.convert tag
    C.aeadSimpleDecrypt aead constantAdditionalData ctext authtag
