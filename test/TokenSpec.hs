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
        it "encrypt & decrypt ByteString" $
            roundTrip defaultConfig
        it "lives as long as its lifetime, across rotations" $ do
            mgr <- spawnTokenManager $ defaultConfig{interval = 1, tokenLifetime = 2}
            threadDelay 900000
            -- made just before a rotation
            tf <- encryptToken mgr "Foo"
            threadDelay 1200000
            decryptToken mgr tf `shouldReturn` Just "Foo"
            tb <- encryptToken mgr "Bar"
            threadDelay 1300000
            decryptToken mgr tf `shouldReturn` Nothing
            decryptToken mgr tb `shouldReturn` Just "Bar"
            killTokenManager mgr

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
