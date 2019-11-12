{-# language BangPatterns #-}
{-# language TypeApplications #-}

module Fortios.Hash
  ( duohash
  , quadrohash
  ) where

import Data.Bytes.Types (Bytes(Bytes))
import Data.Primitive (indexByteArray)
import Data.Word (Word8)

duohash :: Int -> Int -> Int -> Bytes -> Word
duohash !acc !x1 !x2 (Bytes !arr !off !len) = case len of
  0 -> fromIntegral @Int @Word acc
  _ ->
    let accNew = acc
          + x1 * fromIntegral (indexByteArray arr off :: Word8)
          + x2 * fromIntegral (indexByteArray arr (off + 1) :: Word8)
     in duohash accNew x1 x2 (Bytes arr (off + 2) (len - 2)) 
  
quadrohash :: Int -> Int -> Int -> Int -> Int -> Bytes -> Word
quadrohash !acc !x1 !x2 !x3 !x4 (Bytes !arr !off !len) = case len of
  0 -> fromIntegral @Int @Word acc
  _ ->
    let accNew = acc
          + x1 * fromIntegral (indexByteArray arr off :: Word8)
          + x2 * fromIntegral (indexByteArray arr (off + 1) :: Word8)
          + x3 * fromIntegral (indexByteArray arr (off + 2) :: Word8)
          + x4 * fromIntegral (indexByteArray arr (off + 3) :: Word8)
     in quadrohash accNew x1 x2 x3 x4 (Bytes arr (off + 4) (len - 4)) 
