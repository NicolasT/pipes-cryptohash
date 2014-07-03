{-# LANGUAGE BangPatterns #-}

{-|
Module      : Crypto.Hash.Fold
Description : Folds based on the @foldl@ package calculating digests over
              'BS.ByteString's using the @cryptohash@ package
Copyright   : (c) Nicolas Trangez, 2014
License     : BSD3
Maintainer  : ikke@nicolast.be
Stability   : experimental

This module provides 'Fold's calculating hashes using the 'Crypto.Hash'
functions.
-}

module Crypto.Hash.Fold (
    -- * 'Fold's over containers of strict 'BS.ByteString's
      hash
    , hashAlg
    , hashContext
    -- * 'Fold's over containers of lazy 'LBS.ByteString's
    , hashLazy
    , hashLazyAlg
    , hashLazyContext
    ) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS

import Crypto.Hash (Context, Digest, HashAlgorithm, hashFinalize, hashInit, hashUpdate)

import Control.Foldl (Fold(Fold))

-- | Strict version of 'hashUpdate'
hashUpdate' :: HashAlgorithm a => Context a -> BS.ByteString -> Context a
hashUpdate' !ctx = hashUpdate ctx

-- | 'Fold' updating a given initial 'Context' with the input 'BS.ByteString's
hashContext :: HashAlgorithm a
            => Context a  -- ^ Initial 'Context'
            -> Fold BS.ByteString (Context a)
hashContext ctx0 = Fold hashUpdate' ctx0 id
{-# INLINE hashContext #-}

-- | 'Fold' calculating a hash of the input 'BS.ByteString's
hash :: HashAlgorithm a => Fold BS.ByteString (Digest a)
hash = hashFinalize `fmap` hashContext hashInit
{-# INLINE hash #-}

-- | Like 'hash', but takes a specific 'HashAlgorithm'
--
-- This allows for passing a value instead of adding explicit
-- type-signatures to select a hash method.
hashAlg :: HashAlgorithm a => a -> Fold BS.ByteString (Digest a)
hashAlg _ = hash
{-# INLINE hashAlg #-}


-- | 'Fold' updating a given initial 'Context' with the input
-- lazy 'LBS.ByteString's
hashLazyContext :: HashAlgorithm a => Context a -> Fold LBS.ByteString (Context a)
hashLazyContext ctx0 = Fold (LBS.foldlChunks hashUpdate') ctx0 id
{-# INLINE hashLazyContext #-}

-- | 'Fold' calculating a hash of the input lazy 'LBS.ByteString's
hashLazy :: HashAlgorithm a => Fold LBS.ByteString (Digest a)
hashLazy = hashFinalize `fmap` hashLazyContext hashInit
{-# INLINE hashLazy #-}

-- | Like 'hashLazy', but takes a specific 'HashAlgorithm'
--
-- This allows for passing a value instead of adding explicit
-- type-signatures to select a hash method.
hashLazyAlg :: HashAlgorithm a => a -> Fold LBS.ByteString (Digest a)
hashLazyAlg _ = hashLazy
{-# INLINE hashLazyAlg #-}
