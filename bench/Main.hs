import Gauge (bench,whnf,defaultMain)

import qualified Sample as S
import qualified Fortios.Syslog as FGT

main :: IO ()
main = defaultMain
  [ bench "Traffic-Local-A" (whnf FGT.decode S.traffic_local_A)
  , bench "Traffic-Forward-A" (whnf FGT.decode S.traffic_forward_A)
  ]
