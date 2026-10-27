{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Encrypted tokens/tickets to keep state in the client side.
module Crypto.Token (
    -- * Configuration
    Config,
    defaultConfig,
    interval,
    tokenLifetime,
    threadName,

    -- * Token manager
    TokenManager,
    spawnTokenManager,
    killTokenManager,

    -- * Encryption and decryption
    encryptToken,
    decryptToken,
) where

import Control.Concurrent
import qualified Control.Exception as E
import Control.Monad (when)
import Crypto.Cipher.AES (AES256)
import Crypto.Cipher.Types (AEADMode (..), AuthTag (..))
import qualified Crypto.Cipher.Types as C
import Crypto.Error (maybeCryptoError, throwCryptoError)
import Crypto.Random (getRandomBytes)
import Data.Array.IO
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import qualified Data.IORef as I
import Data.Word
import GHC.Clock (getMonotonicTimeNSec)
import GHC.Conc.Sync (labelThread)
import Network.ByteOrder

----------------------------------------------------------------

type Index = Word16
type Counter = Word64

-- | Configuration for token manager.
data Config = Config
    { interval :: Int
    -- ^ The interval to generate a new secret and remove the oldest one in seconds.
    , tokenLifetime :: Int
    -- ^ The token lifetime in seconds, that is, tokens can be decrypted in this period.
    --   It is cut short if it spans more than 65535 intervals.
    , threadName :: String
    }
    deriving (Eq, Show)

-- | Default configuration to update secrets in 30 minutes (1,800 seconds) and token lifetime is 2 hours (7,200 seconds)
--
-- >>> defaultConfig
-- Config {interval = 1800, tokenLifetime = 7200, threadName = "Crypto token manager"}
defaultConfig :: Config
defaultConfig =
    Config
        { interval = 1800
        , tokenLifetime = 7200
        , threadName = "Crypto token manager"
        }

----------------------------------------------------------------

-- | The abstract data type for token manager.
data TokenManager = TokenManager
    { headerKey :: AES256
    , getEncryptSecret :: IO (Secret, Index)
    , getDecryptSecret :: Index -> IO Secret
    , threadId :: ThreadId
    , lifetimeNSec :: Word64
    }

-- | Spawning a token manager.
--   This throws an 'IOError' if 'interval' is not positive.
spawnTokenManager :: Config -> IO TokenManager
spawnTokenManager Config{..} = do
    when (interval <= 0) $
        E.throwIO $
            userError "Crypto.Token: interval must be positive"
    -- the secret a token was made with must outlive the token itself,
    -- and an index travels as Word16, so there are at most 65536 slots
    let lifetime = max 0 tokenLifetime
        slots = min 65536 $ (lifetime + interval - 1) `div` interval + 1
    emp <- emptySecret
    arr <- newArray (0, slots - 1) emp
    ent <- generateSecret
    writeArray arr 0 ent
    ref <- I.newIORef 0
    tid <- forkIO $ loop arr ref
    labelThread tid threadName
    hkey <- newHeaderKey
    return $
        TokenManager hkey (readCurrentSecret arr ref) (readSecret arr) tid $
            fromIntegral lifetime * 1000000000
  where
    loop arr ref = do
        delaySeconds interval
        -- a failed rotation is retried at the next interval
        update arr ref `E.catch` ignoreSync
        loop arr ref
    ignoreSync :: E.SomeException -> IO ()
    ignoreSync e = case E.fromException e of
        Just (E.SomeAsyncException _) -> E.throwIO e
        Nothing -> return ()
    update :: IOArray Int Secret -> I.IORef Int -> IO ()
    update arr ref = do
        idx0 <- I.readIORef ref
        n <- rangeSize <$> getBounds arr
        let idx = (idx0 + 1) `mod` n
        sec <- generateSecret
        writeArray arr idx sec
        I.writeIORef ref idx

-- threadDelay's microseconds overflow a 32-bit Int after 35 minutes.
delaySeconds :: Int -> IO ()
delaySeconds n
    | n <= 0 = return ()
    | otherwise = do
        let m = min n 1000
        threadDelay (m * 1000000)
        delaySeconds (n - m)

-- | Killing a token manager.
killTokenManager :: TokenManager -> IO ()
killTokenManager TokenManager{..} = killThread threadId

----------------------------------------------------------------

readSecret :: IOArray Int Secret -> Index -> IO Secret
readSecret secrets idx0 = do
    n <- rangeSize <$> getBounds secrets
    readArray secrets $ fromIntegral idx0 `mod` n

readCurrentSecret :: IOArray Int Secret -> I.IORef Int -> IO (Secret, Index)
readCurrentSecret arr ref = do
    idx <- I.readIORef ref
    sec <- readArray arr idx
    return (sec, fromIntegral idx)

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

-- 96 bits, the nonce length GCM is designed for
ivLength :: Int
ivLength = 12

keyLength :: Int
keyLength = 32

indexLength :: Int
indexLength = 2

counterLength :: Int
counterLength = 8

tagLength :: Int
tagLength = 16

-- one AES block: index, counter and zero padding
headerLength :: Int
headerLength = 16

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

newHeaderKey :: IO AES256
newHeaderKey = do
    key <- getRandomBytes keyLength :: IO ByteString
    return $ throwCryptoError $ C.cipherInit key

----------------------------------------------------------------

-- The header is encrypted so that tokens do not reveal how they relate.
addHeader :: TokenManager -> Index -> Counter -> ByteString -> IO ByteString
addHeader TokenManager{..} idx counter cipher = do
    hdrbin <- encodeHeader $ Header idx counter
    let padding = BS.replicate (headerLength - BS.length hdrbin) 0
        blk = C.ecbEncrypt headerKey (hdrbin `BS.append` padding)
    return (blk `BS.append` cipher)

delHeader
    :: TokenManager -> ByteString -> IO (Maybe (Index, Counter, ByteString))
delHeader TokenManager{..} token
    | BS.length token < headerLength = return Nothing
    | otherwise = do
        let (blk, cipher) = BS.splitAt headerLength token
            (hdrbin, padding) =
                BS.splitAt (indexLength + counterLength) $ C.ecbDecrypt headerKey blk
        if BS.any (/= 0) padding
            then return Nothing
            else do
                Header{..} <- decodeHeader hdrbin
                return $ Just (headerIndex, headerCounter, cipher)

-- | Encrypting a target value to get a token.
encryptToken
    :: TokenManager
    -> ByteString
    -> IO ByteString
encryptToken mgr x = do
    (secret, idx) <- getEncryptSecret mgr
    now <- getMonotonicTimeNSec
    (counter, cipher) <- encrypt secret (bytestring64 now `BS.append` x)
    addHeader mgr idx counter cipher

encrypt
    :: Secret
    -> ByteString
    -> IO (Counter, ByteString)
encrypt secret plain = do
    counter <- I.atomicModifyIORef' (secretCounter secret) (\i -> (i + 1, i))
    let nonce = makeNonce counter $ secretIV secret
        cipher = aes256gcmEncrypt plain (secretKey secret) nonce
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
            mplain <- decrypt secret counter cipher
            now <- getMonotonicTimeNSec
            return $ mplain >>= checkLifetime now
  where
    checkLifetime now plain
        | BS.length plain < 8 = Nothing
        | issued <= now && now - issued <= lifetimeNSec mgr = Just x
        | otherwise = Nothing
      where
        (hdr, x) = BS.splitAt 8 plain
        issued = word64 hdr

decrypt
    :: Secret
    -> Counter
    -> ByteString
    -> IO (Maybe ByteString)
decrypt secret counter cipher = do
    let nonce = makeNonce counter $ secretIV secret
    return $ aes256gcmDecrypt cipher (secretKey secret) nonce

makeNonce :: Counter -> ByteString -> ByteString
makeNonce counter iv = iv `BA.xor` cv
  where
    cv = BS.replicate (ivLength - counterLength) 0 `BS.append` bytestring64 counter

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
