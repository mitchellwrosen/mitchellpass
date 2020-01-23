{-# language BlockArguments #-}
{-# language DeriveAnyClass #-}
{-# language DerivingStrategies #-}
{-# language GeneralizedNewtypeDeriving #-}
{-# language LambdaCase #-}
{-# language OverloadedStrings #-}
{-# language ScopedTypeVariables #-}

module Main where

import Control.Exception (Exception, throwIO)
import Control.Category ((>>>))
import Data.Coerce (coerce)
import Data.Foldable
import Data.Function ((&))
import Data.HashMap.Strict (HashMap)
import Data.Maybe
import Data.Text (Text)
import System.Environment (getEnv)
import qualified Crypto.PubKey.RSA as RSA
import qualified Data.ASN1.BinaryEncoding as ASN1
import qualified Data.ASN1.Encoding as ASN1
import qualified Data.ASN1.Error as ASN1
import qualified Data.ASN1.Types as ASN1
import qualified Data.Aeson as Aeson
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Base64 as ByteString
import qualified Data.HashMap.Strict as HashMap
import qualified Data.Text.Encoding as Text
import qualified Data.X509 as X509


main :: IO ()
main = do
  home <- getEnv "HOME"
  config <-
    Aeson.eitherDecodeFileStrict ( home ++ "/.ipfs/config" ) >>=
      fatal FatalError'ParseIpfsConfig
  privKeyBytes <-
    config
      & ipfsConfigIdentity
      & ipfsConfigIdentityPrivKey
      & Text.encodeUtf8
      & ByteString.decodeBase64
      & fatal FatalError'Base64DecodePrivateKey
  privKeyAsn <-
    privKeyBytes
      & ByteString.drop 5 -- it's a small protobuf; drop enum (4) and len (1)
      & ASN1.decodeASN1' ASN1.DER
      & fatal FatalError'ASN1DecodePrivateKey
  privKey <-
    privKeyAsn
      & ASN1.fromASN1
      & \case
          Right ( X509.PrivKeyRSA key, [] ) -> pure key
          Right what -> fatal ( Left >>> FatalError'RSADecodePrivateKey ) ( Left what )
          Left what -> fatal ( Right >>> FatalError'RSADecodePrivateKey ) ( Left what )
  print privKey

data FatalError
  = FatalError'ParseIpfsConfig String
  | FatalError'Base64DecodePrivateKey Text
  | FatalError'ASN1DecodePrivateKey ASN1.ASN1Error
  | FatalError'RSADecodePrivateKey ( Either ( X509.PrivKey, [ ASN1.ASN1 ] ) String )
  deriving stock ( Show )
  deriving anyclass ( Exception )

fatal :: ( e -> FatalError ) -> Either e a -> IO a
fatal f =
  either ( f >>> throwIO ) pure

newtype IpfsConfig
  = IpfsConfig ( HashMap Text Aeson.Value )
  deriving newtype ( Aeson.FromJSON )

newtype IpfsConfigIdentity
  = IpfsConfigIdentity ( HashMap Text Aeson.Value )
  deriving newtype ( Aeson.FromJSON )

ipfsConfigIdentity :: IpfsConfig -> IpfsConfigIdentity
ipfsConfigIdentity config =
  fromJust do
    Aeson.Object identity <- HashMap.lookup "Identity" ( coerce config )
    pure ( coerce identity )

ipfsConfigIdentityPeerId :: IpfsConfigIdentity -> Text
ipfsConfigIdentityPeerId identity =
  fromJust do
    Aeson.String peerId <- HashMap.lookup "PeerID" ( coerce identity )
    pure peerId

ipfsConfigIdentityPrivKey :: IpfsConfigIdentity -> Text
ipfsConfigIdentityPrivKey identity =
  fromJust do
    Aeson.String peerId <- HashMap.lookup "PrivKey" ( coerce identity )
    pure peerId
