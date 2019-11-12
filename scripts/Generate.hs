{-# language BangPatterns #-}
{-# language LambdaCase #-}
{-# language TypeApplications #-}
{-# language ScopedTypeVariables #-}

module Main where

import Data.Int (Int32)
import Data.Word (Word8,Word16)
import Data.Char (ord)
import Data.Map (Map)
import System.Random (randomIO)
import Control.Monad (replicateM)
import System.IO (stdin)

import qualified Data.Map.Strict as Map
import qualified Data.List as L
import qualified Data.Text as T
import qualified Data.Text.IO as T
import qualified System.IO as IO

allKeywords :: [String]
allKeywords =
  [ "action"
  , "app"
  , "appcat"
  , "cat"
  , "catdesc"
  , "countweb"
  , "craction"
  , "crlevel"
  , "crscore"
  , "date"
  , "devid"
  , "devname"
  , "direction"
  , "dstcountry"
  , "dstintf"
  , "dstip"
  , "dstport"
  , "duration"
  , "eventtype"
  , "hostname"
  , "lanin"
  , "lanout"
  , "level"
  , "logid"
  , "method"
  , "msg"
  , "policyid"
  , "policytype"
  , "poluuid"
  , "profile"
  , "proto"
  , "rcvdbyte"
  , "rcvdpkt"
  , "reqtype"
  , "sentbyte"
  , "sentpkt"
  , "service"
  , "sessionid"
  , "srccountry"
  , "srcintf"
  , "srcip"
  , "srcport"
  , "subtype"
  , "time"
  , "trandisp"
  , "transip"
  , "transport"
  , "type"
  , "url"
  , "user"
  , "utmaction"
  , "vd"
  , "wanin"
  , "wanout"
  ]

data Algorithm = AlgoTwo !Int !Int | AlgoFour !Int !Int !Int !Int
  deriving (Show)

type Result = Map Int (Algorithm, Int, Map Word String)

keywordsOfLength :: Int -> [String]
keywordsOfLength !n =
  filter (\k -> length k == n) allKeywords

groupedKeywords :: [[String]]
groupedKeywords = map keywordsOfLength [0..20]

main :: IO ()
main = do
  let go !acc !_ [] = pure acc
      go !acc !len (keywords : xs) = do
        r <- attemptTableSize keywords len
        go (acc <> r) (len + 1) xs
  res <- go mempty 0 groupedKeywords
  Map.foldMapWithKey (\k v -> putStrLn (show k ++ ": " ++ show v)) res
  IO.withFile "src/Fortios/Generated.hs" IO.WriteMode $ \h -> do
    IO.hPutStrLn h "{-# language PatternSynonyms #-}"
    IO.hPutStr h "module Fortios.Generated\n  ("
    IO.hPutStrLn h (drop 3 (makePatternExports res))
    IO.hPutStrLn h (exportHashFuncs res)
    IO.hPutStrLn h "  ) where\n"
    IO.hPutStrLn h "import Fortios.Hash (duohash,quadrohash)"
    IO.hPutStrLn h "import Data.Bytes.Types (Bytes(Bytes))\n"
    IO.hPutStrLn h "import Data.Primitive (ByteArray)\n"
    IO.hPutStrLn h (makePatterns res)
    IO.hPutStrLn h (makeHashFuncs res)

takeDividingTwo :: [a] -> [a]
takeDividingTwo (x : y : zs) = x : y : takeDividingTwo zs
takeDividingTwo (_ : []) = []
takeDividingTwo [] = []

takeDividingFour :: [a] -> [a]
takeDividingFour (w: x : y : z : zs) = w : x : y : z : takeDividingFour zs
takeDividingFour (_ : _ : _ : []) = []
takeDividingFour (_ : _ : []) = []
takeDividingFour (_ : []) = []
takeDividingFour [] = []

attemptTableSize :: [String] -> Int -> IO Result
attemptTableSize keywords !len = if length keywords > 0  
  then do
    putStrLn ("Mod " ++ show sz ++ " hashes for strings of length " ++ show len ++ ":\n" ++ show keywords)
    attemptMultiplierSizeTwo keywords sz >>= \case
      Just res -> pure (Map.singleton len res)
      Nothing -> attemptMultiplierSizeFour keywords sz >>= \case
        Just res -> pure (Map.singleton len res)
        Nothing -> fail "hautnoehnutah"
  else pure Map.empty
  where
  sz = nextPowerOfTwo (length keywords + 1)

attemptMultiplierSizeTwo :: [String] -> Int
  -> IO (Maybe (Algorithm, Int, Map Word String))
attemptMultiplierSizeTwo keywords !sz =
  let go !i !cutoff = if i >= (0 :: Int)
        then do
          ms0 :: [Word16] <- replicateM 2 randomIO
          -- putStrLn ("Attempt mutipliers: " ++ show ms0)
          let ms1@[m0,m1] = map (fromIntegral @Word16 @Int) ms0
          let ms = streamFromList ms1
          let rs = L.nub (map (hashStringWith sz ms . takeDividingTwo) keywords)
          if L.length rs == L.length keywords && maximum rs <= fromIntegral @Int @Word cutoff
            then do
              putStrLn "Found a match"
              putStrLn ("Multipliers: " ++ show ms1)
              putStrLn ("Hashes: " ++ show rs)
              putStrLn ("Table Size: " ++ show sz)
              let algo = AlgoTwo m0 m1
              let xs = map (\x -> (hashStringWith sz ms (takeDividingTwo x), x)) keywords
              pure (Just (algo,sz,Map.fromList xs))
            else go (i - 1) cutoff
        else if cutoff < sz
          then go 80000 (cutoff + 1)
          else pure Nothing
   in go 80000 (length keywords)

attemptMultiplierSizeFour :: [String] -> Int
  -> IO (Maybe (Algorithm, Int, Map Word String))
attemptMultiplierSizeFour keywords !sz =
  let go !i !cutoff = if i >= (0 :: Int)
        then do
          ms0 :: [Word16] <- replicateM 4 randomIO
          let ms1@[m0,m1,m2,m3] = map (fromIntegral @Word16 @Int) ms0
          let ms = streamFromList ms1
          let rs = L.nub (map (hashStringWith sz ms . takeDividingFour) keywords)
          if L.length rs == L.length keywords && maximum rs <= fromIntegral @Int @Word cutoff
            then do
              putStrLn "Found a match"
              putStrLn ("Multipliers: " ++ show ms1)
              putStrLn ("Hashes: " ++ show rs)
              putStrLn ("Table Size: " ++ show sz)
              let algo = AlgoFour m0 m1 m2 m3
              let xs = map (\x -> (hashStringWith sz ms (takeDividingFour x), x)) keywords
              pure (Just (algo,sz,Map.fromList xs))
            else go (i - 1) cutoff
        else if cutoff < sz
          then go 80000 (cutoff + 1)
          else pure Nothing
   in go 800000 (length keywords)
       
  
streamFromList :: [Int] -> IntStream
streamFromList xs = go xs where
  go [] = go xs
  go (y : ys) = IntStream y (go ys)

data IntStream = IntStream !Int IntStream

hashStringWith :: Int -> IntStream -> String -> Word
hashStringWith !tblSz = go 0 where
  go !acc _ [] = mod (fromIntegral @Int @Word acc) (fromIntegral @Int @Word tblSz)
  go !acc (IntStream m ms) (c : cs) = go (acc + ord c * m) ms cs
  
nextPowerOfTwo :: Int -> Int
nextPowerOfTwo !n = go 1 where
  go !x = if x >= n
    then x
    else go (x * 2)

makePatternExports :: Map Int (Algorithm, Int, Map Word String) -> String
makePatternExports = concat . L.sort . foldMap
  (\(_,_,m) -> Map.foldMapWithKey
    ( \theHash str -> ["  , pattern H_" ++ str ++ "\n"]
    ) m
  )

makePatterns :: Map Int (Algorithm, Int, Map Word String) -> String
makePatterns = concat . L.sort . foldMap
  (\(_,_,m) -> Map.foldMapWithKey
    ( \theHash str ->
      [ "pattern H_" ++ str ++ " :: Word\n"
      , "pattern H_" ++ str ++ " = " ++ show theHash ++ "\n\n"
      ]
    ) m
  )

makeHashFuncs :: Map Int (Algorithm, Int, Map Word String) -> String
makeHashFuncs = Map.foldMapWithKey
  (\len (algo,n,_) -> concat
    [ "hashString" ++ show len ++ " :: ByteArray -> Int -> Word\n"
    , "hashString" ++ show len ++ " arr off = "
    , case algo of
        AlgoTwo x1 x2 ->
          "rem (duohash 0 " ++ show x1 ++ " " ++ show x2 ++ 
          " (Bytes arr off " ++ show (2 * div len 2) ++ ")) " ++
          show n ++ "\n\n"
        AlgoFour x1 x2 x3 x4 ->
          "rem (quadrohash 0 " ++ show x1 ++ " " ++ show x2 ++ " " ++
          show x3 ++ " " ++ show x4 ++ 
          " (Bytes arr off " ++ show (4 * div len 4) ++ ")) " ++
          show n ++ "\n\n"
    ]
  )

exportHashFuncs :: Map Int (Algorithm, Int, Map Word String) -> String
exportHashFuncs = Map.foldMapWithKey
  (\len _ -> "  , hashString" ++ show len ++ "\n"
  )
