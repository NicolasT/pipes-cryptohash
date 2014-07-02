{-# LANGUAGE GADTs #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Main (main) where

import Test.Tasty.HUnit
import qualified Test.Tasty as Tasty
import qualified Test.Tasty.SmallCheck as SC
import qualified Test.Tasty.QuickCheck as QC

import Test.SmallCheck.Series (Serial(..))

import Test.QuickCheck (Arbitrary(..), elements)

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Char8 as BS8

import Control.Monad.State (State, runState)
import Control.Monad.Identity (Identity (runIdentity))

import qualified Crypto.Hash as H

import Pipes
import qualified Pipes.Prelude as P
import Pipes.CryptoHash


instance Monad m => Serial m ByteString where
    series = fmap BS8.pack series

instance Monad m => Serial m LBS.ByteString where
    series = fmap LBS.fromChunks series

instance Arbitrary ByteString where
    arbitrary = fmap BS.pack arbitrary
    shrink = fmap BS.pack . shrink . BS.unpack

instance Arbitrary LBS.ByteString where
    arbitrary = fmap LBS.fromChunks arbitrary
    shrink = fmap LBS.fromChunks . shrink . LBS.toChunks


data HashAlgorithm where
    HashAlgorithm :: (Show a, H.HashAlgorithm a) => a -> HashAlgorithm

deriving instance Show HashAlgorithm

instance Arbitrary HashAlgorithm where
    arbitrary = elements [ HashAlgorithm H.MD2
                         , HashAlgorithm H.MD4
                         , HashAlgorithm H.MD5
                         , HashAlgorithm H.SHA1
                         , HashAlgorithm H.SHA224
                         , HashAlgorithm H.SHA256
                         , HashAlgorithm H.SHA384
                         , HashAlgorithm H.SHA512
                         , HashAlgorithm H.RIPEMD160
                         , HashAlgorithm H.Whirlpool
                         , HashAlgorithm H.Tiger
                         , HashAlgorithm H.SHA3_224
                         , HashAlgorithm H.SHA3_256
                         , HashAlgorithm H.SHA3_384
                         , HashAlgorithm H.SHA3_512
                         , HashAlgorithm H.Skein256_224
                         , HashAlgorithm H.Skein256_256
                         , HashAlgorithm H.Skein512_224
                         , HashAlgorithm H.Skein512_256
                         , HashAlgorithm H.Skein512_384
                         , HashAlgorithm H.Skein512_512
                         ]


main :: IO ()
main = Tasty.defaultMain tests

tests :: Tasty.TestTree
tests = Tasty.testGroup "Tests" [properties, unitTests]

properties :: Tasty.TestTree
properties = Tasty.testGroup "Properties" [scProps, qcProps]


runHash :: Monad m
        => (Producer b m () -> Producer b Identity ((), d))
        -> [b]
        -> d
runHash h l = snd $ runIdentity $ runEffect $ h (each l) >-> P.drain

runHashPipe :: H.HashAlgorithm a
            => Pipe b b (State (H.Context a)) ()
            -> H.Context a
            -> [b]
            -> H.Digest a
runHashPipe h c l = H.hashFinalize . snd $ flip runState c
                                         $ runEffect
                                         $ each l >-> h >-> P.drain


validate :: H.HashAlgorithm a => a -> [ByteString] -> H.Digest a
validate _ = H.hashlazy . LBS.fromChunks

validate' :: H.HashAlgorithm a => a -> [LBS.ByteString] -> H.Digest a
validate' _ = H.hashlazy . LBS.concat


scProps :: Tasty.TestTree
scProps = Tasty.testGroup "SmallCheck"
    [ SC.testProperty "hash" $
        \l -> runHash hash l == validate H.SHA1 l
    , SC.testProperty "hashLazy" $
        \l -> runHash hashLazy l == validate' H.SHA256 l
    , SC.testProperty "hashPipeAlg" $
        \l -> runHashPipe (hashPipeAlg H.SHA1) (H.hashInitAlg H.SHA1) l == validate H.SHA1 l
    ]

qcProps :: Tasty.TestTree
qcProps = Tasty.testGroup "QuickCheck"
    [ QC.testProperty "hash" $
        \(HashAlgorithm a) l -> runHash hash l == validate a l
    , QC.testProperty "hashLazy" $
        \(HashAlgorithm a) l -> runHash hashLazy l == validate' a l
    , QC.testProperty "hashPipeAlg" $
        \(HashAlgorithm a) l -> runHashPipe (hashPipeAlg a) (H.hashInitAlg a) l == validate a l
    ]

unitTests :: Tasty.TestTree
unitTests = Tasty.testGroup "Unit Tests"
    [ testCase "hash: SHA1 \"abcdef\"" $
        H.digestToHexByteString
            (runHash hash ["ab", "cd", "ef"] :: H.Digest H.SHA1)
            @?= expected
    , testCase "hashLazyContext: SHA1 \"abcdef\"" $
        H.digestToHexByteString
            (H.hashFinalize $ runHash (hashLazyContext (H.hashInitAlg H.SHA1))
                            $ fmap LBS.fromChunks [["ab", "c"], ["d"], ["e", "f"]])
            @?= expected
    , testCase "hashPipe: SHA1 \"abcdef\"" $
        H.digestToHexByteString
            (runHashPipe hashPipe (H.hashInitAlg H.SHA1) ["ab", "cd", "e", "f"])
            @?= expected
    ]
  where
    expected = "1f8ac10f23c5b5bc1167bda84b833e5c057a77d2"
