{-# LANGUAGE DoAndIfThenElse #-}
import Control.Monad (forever,forM,guard,void)
import Control.Concurrent (forkIO)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Char8 as C
import Data.Binary.Get (getWord32host,runGet)
import Data.Char (isAscii)
import Data.Functor ((<$>))
import Data.Maybe (catMaybes)
import Debug.Trace (traceShow)
import Network.DNS
import Network.Multicast (addMembership)
import Network.Socket hiding (recv,sendTo)
import Network.Socket.ByteString(recv,sendTo)
import System.Environment (getArgs)
import System.Exit (exitFailure)

-- | The port used for MDNS requests/respones
mdnsPort :: PortNumber
mdnsPort = 5353

-- | The multicast IP address used for MDNS responses
mdnsIp :: HostAddress
mdnsIp = runGet getWord32host $ BL.pack [224,0,0,251]

-- | The SockAddr used for MDNS response
mdnsAddr :: SockAddr
mdnsAddr = SockAddrInet mdnsPort mdnsIp

-- | The maximum size of UDP DNS message defined in RFC-1035
maxDNSMsgSize :: Int
maxDNSMsgSize = 512

-- | Convert a String with only ascii characters to Domain
toDomain :: String -> Domain
toDomain = C.pack

-- | Convert strict ByteString to lazy ByteString
bsFromStrict :: B.ByteString -> BL.ByteString
bsFromStrict = BL.pack . B.unpack

-- | Convert lazy ByteString to strict ByteString
bsFromLazy :: BL.ByteString -> B.ByteString
bsFromLazy = B.concat . BL.toChunks

-- | Create a MDNS response
responseMDNS :: DNSFormat        -- ^ The original MDNS request
             -> [ResourceRecord] -- ^ The answers to response
             -> DNSFormat        -- ^ The result MDNS response
responseMDNS req answers = DNSFormat h [] answers [] []
  where
    h = DNSHeader { identifier = identifier (header req)
                  , flags = (flags $ header req) {qOrR = QR_Response}
                  , qdCount = 0
                  , anCount = length answers
                  , nsCount = 0
                  , arCount = 0
                  }

-- | Query DNS for a list of qustions
lookupDNS :: Resolver            -- ^ The resolver to lookup with
          -> [Question]          -- ^ The list of questions to look up
          -> IO [ResourceRecord] -- ^ The answers
lookupDNS resolver questions = concat <$> forM questions lookup'
  where
    lookup' :: Question -> IO [ResourceRecord]
    -- returns [] if no results found
    lookup' q = maybe [] answer <$> lookupRaw resolver (qname q) (qtype q)

-- | Proxy MDNS queries for domains ending with the given suffixes.
proxyForSuffixes :: [Domain] -> IO ()
proxyForSuffixes suffixes = withSocketsDo $ do
    seed <- makeResolvSeed defaultResolvConf
    sock <- socket AF_INET Datagram defaultProtocol
    -- We should work properly when other MDNS server(e.g. avahi-daemon) is
    -- running, so we need to set ReuseAddr socket option.
    setSocketOption sock ReuseAddr 1
    bind sock serverAddr
    mdnsIpStr <- inet_ntoa mdnsIp
    addMembership sock mdnsIpStr
    forever $ tryReceivingMsg sock seed
  where
    serverAddr = SockAddrInet mdnsPort 0
    tryReceivingMsg sock seed = do
        bytes <- recv sock maxDNSMsgSize
        case decode (bsFromStrict bytes) of
            Left err -> putStrLn $ "received a invalid message:" ++ err
            Right msg' -> processMsg sock seed msg'
    processMsg sock seed msg =  proxyIt
      where
        proxyIt
            | notRequest || null questionToUs = return ()
            | otherwise =  do
                  putStrLn $ "will handle:" ++ show questionToUs
                  void $ forkIO $ withResolver seed $ \resolver -> do
                      answers <- lookupDNS resolver questionToUs
                      let rsp = responseMDNS msg answers
                      void $ sendTo sock (msgToByteString rsp) mdnsAddr
        questionToUs = [ q | q <- question msg
                           , qtype q == A
                           , any (`C.isSuffixOf` qname q) suffixes]
        notRequest = not $ qOrR (flags $ header msg) == QR_Query
        -- encode the response and then convert it to strict ByteString from a
        -- lazy one.
        msgToByteString = bsFromLazy . encode

main = do
    suffixes <- getArgs
    if all (all isAscii) suffixes
    then proxyForSuffixes $ map (toDomain . fixSuffix) suffixes
    else putStrLn "Only supports domain names in ascii!!" >> exitFailure
  where
    -- names in DNS questions should end in "."
    fixSuffix suffix
        | last suffix == '.' = suffix
        | otherwise = suffix ++ "."
