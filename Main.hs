import Control.Monad (forever,forM,guard,void)
import Control.Concurrent (forkIO)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Char8 as C
import Data.Binary.Get (getWord32host,runGet)
import Data.Functor ((<$>))
import Data.Maybe (catMaybes)
import Debug.Trace (traceShow)
import Network.DNS
import Network.Socket hiding (sendTo)
import Network.Socket.ByteString(sendTo)
import System.Environment (getArgs)

-- | The port used for MDNS requests/respones
mdnsPort :: PortNumber
mdnsPort = 5353

-- | The multicast IP address used for MDNS responses
mdnsIp :: HostAddress
mdnsIp = runGet getWord32host $ BL.pack [224,0,0,251]

-- | The SockAddr used for MDNS response
mdnsAddr :: SockAddr
mdnsAddr = SockAddrInet mdnsPort mdnsIp

toDomain :: String -> Domain
toDomain = C.pack

-- | Extract domains with given suffixes in the questions of a DNS request
extractDomainsWithSuffixes :: [Domain]  -- ^ The suffixes of domains we are interested in
                           -> DNSFormat -- ^ The DNS message
                           -> [Domain]  -- ^ The domains with suffixes we are interested in
extractDomainsWithSuffixes suffixes msg =
    if qOrR (flags (header msg)) == QR_Query
    then domains
    else []
  where
    domains = do
        q <- question msg
        guard $ qtype q == A
        guard $ any (`C.isSuffixOf` qname q) suffixes
        return $ qname q

-- | Query domains with DNS server and response through MDNS
queryDomains :: Socket    -- ^ The socket used to response MDNS
             -> Resolver  -- ^ The resolver we could use to lookup domains with
             -> [Domain]  -- ^ The domains we want to look up
             -> DNSFormat -- ^ The origial MDNS request
             -> IO ()
queryDomains sock resolver domains req = do
    dnsRsps <- catMaybes <$> forM domains (\name -> lookupRaw resolver name A)
    let answer' = concat $ map answer dnsRsps
        flags' = (flags $ header req) { qOrR = QR_Response }
        header' = (header req) {flags = flags',qdCount = 0,anCount = length answer'}
        mdnsRsp = req {header = header',question = [],answer = answer'}
        rspBytes = B.concat $ BL.toChunks $ encode mdnsRsp
    void $ sendTo sock rspBytes mdnsAddr

-- | Proxy MDNS queries for domains ending with the given suffixes.
proxyForSuffixes :: [Domain] -> IO ()
proxyForSuffixes suffixes = withSocketsDo $ do
    seed <- makeResolvSeed defaultResolvConf
    sock <- socket AF_INET Datagram defaultProtocol
    setSocketOption sock ReuseAddr 1
    bind sock addr
    forever $ receive sock >>= processMsg sock seed
  where
    addr = SockAddrInet mdnsPort (fromInteger 0)
    processMsg sock seed msg = print ("received:" ++ show msg) >> case extractDomainsWithSuffixes suffixes msg of
        [] -> return ()
        domains -> void $ forkIO $ withResolver seed $ \resolver ->
            queryDomains sock resolver domains msg

main = do
    suffixes <- getArgs
    proxyForSuffixes $ map (toDomain . fixSuffix) suffixes
  where
    -- names in DNS questions should end in "."
    fixSuffix suffix
        | last suffix == '.' = suffix
        | otherwise = suffix ++ "."
