{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module TokenSpec where

import Control.Concurrent
import qualified Control.Exception as E
import Crypto.Token
import Test.Hspec

----------------------------------------------------------------

spec :: Spec
spec = do
    describe "crypto token" $ do
        it "encrypt & decrypt ByteString" $ do
            mgr <- spawnTokenManager $ defaultConfig{interval = 1, tokenLifetime = 3}
            tf <- encryptToken mgr "Foo"
            threadDelay 1100000
            decryptToken mgr tf `shouldReturn` Just "Foo"
            tb <- encryptToken mgr "Bar"
            threadDelay 1100000
            decryptToken mgr tf `shouldReturn` Just "Foo"
            decryptToken mgr tb `shouldReturn` Just "Bar"
            threadDelay 1100000
            decryptToken mgr tf `shouldReturn` Nothing
            decryptToken mgr tb `shouldReturn` Just "Bar"
            threadDelay 1100000
            decryptToken mgr tf `shouldReturn` Nothing
            decryptToken mgr tb `shouldReturn` Nothing

    describe "configuration" $ do
        it "survives a lifetime shorter than the interval" $
            roundTrip defaultConfig{interval = 10, tokenLifetime = 1}
        it "survives more intervals than an index can name" $
            roundTrip defaultConfig{interval = 1, tokenLifetime = 100000}
        it "refuses a non-positive interval" $
            spawnTokenManager defaultConfig{interval = 0}
                `shouldThrow` (\(_ :: E.IOException) -> True)

roundTrip :: Config -> IO ()
roundTrip conf =
    E.bracket (spawnTokenManager conf) killTokenManager $ \mgr -> do
        t <- encryptToken mgr "Foo"
        decryptToken mgr t `shouldReturn` Just "Foo"
