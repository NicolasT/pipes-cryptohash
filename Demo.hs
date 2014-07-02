module Main (main) where

import qualified Data.ByteString.Char8 as BS8

import Crypto.Hash (SHA1(SHA1), digestToHexByteString)

import Pipes
import Pipes.Prelude (drain)
import Pipes.ByteString (stdin)

import Pipes.CryptoHash (hashAlg)

main :: IO ()
main = do
    ((), d) <- runEffect $ hashAlg algo stdin >-> drain
    putStrLn $ show algo ++ ": " ++ BS8.unpack (digestToHexByteString d)
  where
    algo = SHA1
