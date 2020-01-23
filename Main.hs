{-# language BlockArguments #-}
{-# language DerivingStrategies #-}
{-# language GeneralizedNewtypeDeriving #-}
{-# language OverloadedStrings #-}
{-# language ScopedTypeVariables #-}

module Main where

import Data.Coerce (coerce)
import Data.Function ((&))
import Data.HashMap.Strict (HashMap)
import Data.Maybe
import Data.Text (Text)
import System.Environment (getEnv)
import qualified Data.Aeson as Aeson
import qualified Data.HashMap.Strict as HashMap


main :: IO ()
main = do
  home <- getEnv "HOME"
  config <-
    Aeson.eitherDecodeFileStrict ( home ++ "/.ipfs/config" ) >>=
      either fail pure
  print ( config & ipfsConfigIdentity & ipfsConfigIdentityPeerId )
  pure ()


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
