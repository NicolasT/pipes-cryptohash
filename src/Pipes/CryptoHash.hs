{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE FlexibleContexts #-}

{-|
Module      : Pipes.CryptoHash
Description : Utilities to calculate hash digests of 'BS.ByteString' streams
Copyright   : (c) Nicolas Trangez, 2014
License     : BSD3
Maintainer  : ikke@nicolast.be
Stability   : experimental

This module provides several helpers to calculate hashes of byte-streams using
the "Crypto.Hash" interface, where the streams are 'Pipe's of 'BS.ByteString's
or lazy 'LBS.ByteString's.

There are 2 interfaces: one wraps 'Producer's, creating a new 'Producer' to
which all elements from the original 'Producer' are passed along, whilst a hash
is calculated on-the-go and returned when the stream ends, tupled with the
result of the original stream.

The second interface provides regular 'Pipe's which can be put inside a
pipeline, and requires a 'MonadState' layer in the underlying monad stack to
store & return the hashing 'Context'.
-}

module Pipes.CryptoHash (
    -- * Wrappers for 'Producer's
    -- ** Strict 'BS.ByteString' 'Producer's
      hash
    , hashAlg
    , hashContext
    -- ** Lazy 'LBS.ByteString' 'Producer's
    , hashLazy
    , hashLazyAlg
    , hashLazyContext

    -- * 'Pipe' interface
    -- ** Strict 'BS.ByteString' streams
    , hashPipe
    , hashPipeAlg
    -- ** Lazy 'LBS.ByteString' streams
    , hashPipeLazy
    , hashPipeLazyAlg
    ) where

import Pipes
import qualified Pipes.Prelude as PP

import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS

import Control.Monad.State.Class (MonadState, get, put)

import Control.Foldl (purely)

import Crypto.Hash (Context, Digest, HashAlgorithm, hashUpdate)

import qualified Crypto.Hash.Fold as F

catWithFold :: Monad m
            => (x -> a -> x)
            -> x
            -> (x -> b)
            -> Producer a m r
            -> Producer a m (r, b)
catWithFold f a0 m = loop a0
  where
    -- Note: it's really important to be strict in @ctx@, otherwise a huge
    -- thunk is accumulated. If you don't believe me, run the demo twice on
    -- a big file with "+RTS -s", once with the bang and once without, and
    -- compare `maximum residency` and `total memory in use`.
    loop !a p =
        lift (next p) >>=
        either
            (\r -> return (r, m a))
            (\(b, p') -> yield b >> loop (f a b) p')
{-# INLINE catWithFold #-}


-- | Like 'hash', but allows to pass in an existing 'Context', and retrieve
-- it afterwards.
--
-- This can be useful when the hash of a concatenation of multiple streams
-- needs to be calculated, without being able to actually combine the streams
-- into a single 'Producer' for some reason.
hashContext :: (HashAlgorithm a, Monad m)
            => Context a  -- ^ Initial 'Context'
            -> Producer BS.ByteString m r  -- ^ Source 'Producer'
            -> Producer BS.ByteString m (r, Context a)
hashContext = purely catWithFold . F.hashContext
{-# INLINE hashContext #-}

-- | Create a 'BS.ByteString' 'Producer' wrapping a 'BS.ByteString' 'Producer'
-- which calculates a 'Digest' on the go. This 'Digest' will be tupled with
-- the result of the original 'Producer' when the stream ends.
hash :: (HashAlgorithm a, Monad m)
     => Producer BS.ByteString m r  -- ^ Source 'Producer'
     -> Producer BS.ByteString m (r, Digest a)
hash = purely catWithFold F.hash
{-# INLINEABLE hash #-}

-- | Like 'hash', but takes a specific 'HashAlgorithm'
--
-- This allows for passing a value instead of adding explicit
-- type-signatures to select a hash method.
hashAlg :: (HashAlgorithm a, Monad m)
        => a  -- ^ Algorithm to use
        -> Producer BS.ByteString m r  -- ^ Source 'Producer'
        -> Producer BS.ByteString m (r, Digest a)
hashAlg = purely catWithFold . F.hashAlg
{-# INLINEABLE hashAlg #-}


-- | Like 'hashContext', but for lazy 'LBS.ByteString's
hashLazyContext :: (HashAlgorithm a, Monad m)
                => Context a  -- ^ Initial 'Context'
                -> Producer LBS.ByteString m r  -- ^ Source 'Producer'
                -> Producer LBS.ByteString m (r, Context a)
hashLazyContext = purely catWithFold . F.hashLazyContext
{-# INLINEABLE hashLazyContext #-}

-- | Like 'hash', but for lazy 'LBS.ByteString's
hashLazy :: (HashAlgorithm a, Monad m)
         => Producer LBS.ByteString m r  -- ^ Source 'Producer'
         -> Producer LBS.ByteString m (r, Digest a)
hashLazy = purely catWithFold F.hashLazy
{-# INLINEABLE hashLazy #-}

-- | Like 'hashAlg', but for lazy 'LBS.ByteString's
hashLazyAlg :: (HashAlgorithm a, Monad m)
            => a  -- ^ Algorithm to use
            -> Producer LBS.ByteString m r  -- ^ Source 'Producer'
            -> Producer LBS.ByteString m (r, Digest a)
hashLazyAlg = purely catWithFold . F.hashLazyAlg
{-# INLINEABLE hashLazyAlg #-}


hashPipeInternal :: MonadState s m
                 => (s -> a -> s)
                 -> Pipe a a m r
hashPipeInternal f = PP.chain (modify' . flip f)
  where
    -- See strictness note in 'catWithFold'
    modify' f' = get >>= (put $!) . f'
{-# INLINE hashPipeInternal #-}

-- | Update a 'Context' stored in an underlying 'MonadState' with every
-- 'BS.ByteString' passing by.
hashPipe :: (HashAlgorithm a, MonadState (Context a) m)
         => Pipe BS.ByteString BS.ByteString m r
hashPipe = hashPipeInternal hashUpdate
{-# INLINEABLE hashPipe #-}

-- | Like 'hashPipe', but takes a specific 'HashAlgorithm'
--
-- This allows for passing a value instead of adding explicit
-- type-signatures to select a hash method.
hashPipeAlg :: (HashAlgorithm a, MonadState (Context a) m)
            => a  -- ^ Algorithm to use
            -> Pipe BS.ByteString BS.ByteString m r
hashPipeAlg _ = hashPipe
{-# INLINEABLE hashPipeAlg #-}

-- | Like 'hashPipe', but for lazy 'LBS.ByteString's
hashPipeLazy :: (HashAlgorithm a, MonadState (Context a) m)
             => Pipe LBS.ByteString LBS.ByteString m r
hashPipeLazy = hashPipeInternal (LBS.foldlChunks hashUpdate)
{-# INLINEABLE hashPipeLazy #-}

-- | Like 'hashPipeAlg', but for lazy 'LBS.ByteString's
hashPipeLazyAlg :: (HashAlgorithm a, MonadState (Context a) m)
                => a  -- ^ Algorithm to use
                -> Pipe LBS.ByteString LBS.ByteString m r
hashPipeLazyAlg _ = hashPipeLazy
{-# INLINEABLE hashPipeLazyAlg #-}
