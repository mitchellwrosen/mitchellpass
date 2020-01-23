{-# language BlockArguments #-}
{-# language DeriveAnyClass #-}
{-# language DerivingStrategies #-}
{-# language GeneralizedNewtypeDeriving #-}
{-# language LambdaCase #-}
{-# language OverloadedStrings #-}
{-# language ScopedTypeVariables #-}
{-# language TypeApplications #-}

module Main where

import Control.Exception (Exception, throwIO)
import Control.Category ((>>>))
import Control.Monad
import Data.ByteString (ByteString)
import Data.Coerce (coerce)
import Data.Foldable
import Data.Function ((&))
import Data.HashMap.Strict (HashMap)
import Data.Maybe
import Data.Text (Text)
import System.Environment (getArgs, getEnv)
import System.Exit (exitSuccess)
import System.IO (hIsTerminalDevice, stdout)
import qualified Crypto.Cipher.ChaChaPoly1305 as ChaCha
import qualified Crypto.Error
import qualified Crypto.Hash.Algorithms as Hash
import qualified Crypto.KDF.HKDF as HKDF
import qualified Crypto.PubKey.RSA as RSA
import qualified Data.ASN1.BinaryEncoding as ASN1
import qualified Data.ASN1.Encoding as ASN1
import qualified Data.ASN1.Error as ASN1
import qualified Data.ASN1.Types as ASN1
import qualified Data.Aeson as Aeson
import qualified Data.ByteArray as ByteArray
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Base64 as ByteString
import qualified Data.HashMap.Strict as HashMap
import qualified Data.Text.Encoding as Text
import qualified Data.Text.IO as Text
import qualified Data.X509 as X509


main :: IO ()
main = do
  input <- ByteString.getContents
  when ( ByteString.null input ) exitSuccess

  home <- getEnv "HOME"
  config <-
    Aeson.eitherDecodeFileStrict ( home ++ "/.ipfs/config" ) >>=
      fatal FatalError'ParseIpfsConfig
  privKeyProto <-
    config
      & ipfsConfigIdentity
      & ipfsConfigIdentityPrivKey
      & Text.encodeUtf8
      & ByteString.decodeBase64
      & fatal FatalError'Base64DecodePrivateKey
  -- it's a small protobuf; drop enum (4) and len (1)
  let privKeyBytes = ByteString.drop 5 privKeyProto
  privKeyAsn <-
    privKeyBytes
      & ASN1.decodeASN1' ASN1.DER
      & fatal FatalError'ASN1DecodePrivateKey
  privKey <-
    privKeyAsn
      & ASN1.fromASN1
      & \case
          Right ( X509.PrivKeyRSA key, [] ) -> pure key
          Right what -> fatal ( Left >>> FatalError'RSADecodePrivateKey ) ( Left what )
          Left what -> fatal ( Right >>> FatalError'RSADecodePrivateKey ) ( Left what )
  let prk = HKDF.extractSkip @_ @Hash.Blake2b_256 privKeyBytes
  let derivedKey = HKDF.expand @_ @_ @ByteString prk ByteString.empty 32

  let Crypto.Error.CryptoPassed nonce = ChaCha.nonce12 ( ByteString.replicate 12 0 )
  let Crypto.Error.CryptoPassed state0 = ChaCha.initialize derivedKey nonce

  getArgs >>= \case
    [ "-d" ] -> do
      input' <-
        ByteString.decodeBase64 input
          & fatal FatalError'Base64DecodeCiphertext
      let ( actualAuth, input'' ) = ByteString.splitAt 16 input'
      let ( output, state1 ) = ChaCha.decrypt input'' state0
      let expectedAuth = ChaCha.finalize state1
      when ( actualAuth /= ByteArray.convert expectedAuth ) do
        throwIO FatalError'ChaChaAuthFailure
      case Text.decodeUtf8' output of
        Left _ ->
          hIsTerminalDevice stdout >>= \case
            False -> ByteString.putStr output
            True -> throwIO FatalError'CantPrintBinaryDataToTerminal
        Right output ->
          Text.putStrLn output

    _ -> do
      let ( output, state1 ) = ChaCha.encrypt input state0

      ( ByteArray.convert ( ChaCha.finalize state1 ) <> output )
        & ByteString.encodeBase64
        & Text.putStrLn

data FatalError
  = FatalError'ASN1DecodePrivateKey ASN1.ASN1Error
  | FatalError'Base64DecodeCiphertext Text
  | FatalError'Base64DecodePrivateKey Text
  | FatalError'CantPrintBinaryDataToTerminal
  | FatalError'ChaChaAuthFailure
  | FatalError'ParseIpfsConfig String
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
