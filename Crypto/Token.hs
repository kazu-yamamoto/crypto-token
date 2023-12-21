{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Encrypted tokens/tickets to keep state in the client side.
--   For security reasons, 'Storable' data types MUST be fixed-size
--   when stored (i.e. serialized into the memory).
module Crypto.Token (
    -- * Configuration
    Config,
    interval,
    tokenLifetime,
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
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BS
import qualified Data.IORef as I
import Data.Word
import Foreign.Ptr
import Foreign.Storable
import Network.ByteOrder

----------------------------------------------------------------

type Index = Word16
type Counter = Word64

-- | Configuration for token manager.
data Config = Config
    { interval :: Int
    -- ^ The interval to generate a new secret and remove the oldest one in seconds.
    , tokenLifetime :: Int
    -- ^ The token lifetime, that is, tokens can be decrypted in this period.
    }
    deriving (Eq, Show)

-- | Default configuration to update secrets in 30 minutes (1,800 seconds) and token liefetime is 1 day (86,400 seconds)
--
-- >>> defaultConfig
-- Config {interval = 1800, maxEntries = 86400}
defaultConfig :: Config
defaultConfig =
    Config
        { interval = 1800
        , tokenLifetime = 86400
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
--   This thread will sleep if not used and wake up again if used.
spawnTokenManager :: Config -> IO TokenManager
spawnTokenManager Config{..} = do
    emp <- emptySecret
    let lim = fromIntegral (tokenLifetime `div` interval)
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
--   Deprecated and no effecrt currently.
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
    { secretIV :: ByteString
    , secretKey :: ByteString
    , secretCounter :: I.IORef Counter
    }

emptySecret :: IO Secret
emptySecret = Secret BS.empty BS.empty <$> I.newIORef 0

generateSecret :: IO Secret
generateSecret =
    Secret
        <$> genIV
        <*> genKey
        <*> I.newIORef 0

genKey :: IO ByteString
genKey = getRandomBytes keyLength

genIV :: IO ByteString
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

encodeHeader :: Header -> IO ByteString
encodeHeader Header{..} = withWriteBuffer (indexLength + counterLength) $ \wbuf -> do
    write16 wbuf headerIndex
    write64 wbuf headerCounter

decodeHeader :: ByteString -> IO Header
decodeHeader bs = withReadBuffer bs $ \rbuf ->
    Header <$> read16 rbuf <*> read64 rbuf

newHeaderMask :: IO Header
newHeaderMask = do
    bin <- getRandomBytes (indexLength + counterLength) :: IO ByteString
    decodeHeader bin

----------------------------------------------------------------

xorHeader :: Header -> Header -> Header
xorHeader x y =
    Header
        { headerIndex = headerIndex x `xor` headerIndex y
        , headerCounter = headerCounter x `xor` headerCounter y
        }

addHeader :: TokenManager -> Index -> Counter -> ByteString -> IO ByteString
addHeader TokenManager{..} idx counter cipher = do
    let hdr = Header idx counter
        mskhdr = headerMask `xorHeader` hdr
    hdrbin <- encodeHeader mskhdr
    return (hdrbin `BS.append` cipher)

delHeader
    :: TokenManager -> ByteString -> IO (Maybe (Index, Counter, ByteString))
delHeader TokenManager{..} token
    | BS.length token < minlen = return Nothing
    | otherwise = do
        let (hdrbin, cipher) = BS.splitAt minlen token
        mskhdr <- decodeHeader hdrbin
        let hdr = headerMask `xorHeader` mskhdr
            idx = headerIndex hdr
            counter = headerCounter hdr
        return $ Just (idx, counter, cipher)
  where
    minlen = indexLength + counterLength

-- | Encrypting a target value to get a token.
encryptToken
    :: TokenManager
    -> ByteString
    -> IO ByteString
encryptToken mgr x = do
    (secret, idx) <- getEncryptSecret mgr
    (counter, cipher) <- encrypt secret x
    addHeader mgr idx counter cipher

encrypt
    :: Secret
    -> ByteString
    -> IO (Counter, ByteString)
encrypt secret plain = do
    counter <- I.atomicModifyIORef' (secretCounter secret) (\i -> (i + 1, i))
    nonce <- makeNonce counter $ secretIV secret
    let cipher = aes256gcmEncrypt plain (secretKey secret) nonce
    return (counter, cipher)

-- | Decrypting a token to get a target value.
decryptToken
    :: TokenManager
    -> ByteString
    -> IO (Maybe ByteString)
decryptToken mgr token = do
    mx <- delHeader mgr token
    case mx of
        Nothing -> return Nothing
        Just (idx, counter, cipher) -> do
            secret <- getDecryptSecret mgr idx
            decrypt secret counter cipher

decrypt
    :: Secret
    -> Counter
    -> ByteString
    -> IO (Maybe ByteString)
decrypt secret counter cipher = do
    nonce <- makeNonce counter $ secretIV secret
    return $ aes256gcmDecrypt cipher (secretKey secret) nonce

makeNonce :: Counter -> ByteString -> IO ByteString
makeNonce counter iv = do
    cv <- BS.create ivLength $ \ptr -> poke (castPtr ptr) counter
    return $ iv `BA.xor` cv

----------------------------------------------------------------

constantAdditionalData :: ByteString
constantAdditionalData = BS.empty

aes256gcmEncrypt
    :: ByteString
    -> ByteString
    -> ByteString
    -> ByteString
aes256gcmEncrypt plain key nonce = cipher `BS.append` (BA.convert tag)
  where
    conn = throwCryptoError (C.cipherInit key) :: AES256
    aeadIni = throwCryptoError $ C.aeadInit AEAD_GCM conn nonce
    (AuthTag tag, cipher) = C.aeadSimpleEncrypt aeadIni constantAdditionalData plain tagLength

aes256gcmDecrypt
    :: ByteString
    -> ByteString
    -> ByteString
    -> Maybe ByteString
aes256gcmDecrypt ctexttag key nonce = do
    aes <- maybeCryptoError $ C.cipherInit key :: Maybe AES256
    aead <- maybeCryptoError $ C.aeadInit AEAD_GCM aes nonce
    let (ctext, tag) = BS.splitAt (BS.length ctexttag - tagLength) ctexttag
        authtag = AuthTag $ BA.convert tag
    C.aeadSimpleDecrypt aead constantAdditionalData ctext authtag
