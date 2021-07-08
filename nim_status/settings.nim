import # nim libs
  std/[json, options, strutils, strformat]

import # vendor libs
  json_serialization, sqlcipher, web3/conversions as web3_conversions 

import # nim-status libs
  ./conversions, ./settings/types

export types, options

proc createSettings*(db: DbConn, s: Settings, nodecfg: JsonNode) = # TODO: replace JsonNode by a proper NodeConfig object?
  var setting: Settings
  let query = fmt"""INSERT INTO {setting.tableName} (
                      {setting.userAddress.columnName},
                      {setting.currency.columnName},
                      {setting.currentNetwork.columnName},
                      {setting.dappsAddress.columnName},
                      {setting.eip1581Address.columnName},
                      {setting.installationId.columnName},
                      {setting.keyUid.columnName},
                      {setting.keycardInstanceUid.columnName},
                      {setting.keycardPairedOn.columnName},
                      {setting.keycardPairing.columnName},
                      {setting.latestDerivedPath.columnName},
                      {setting.mnemonic.columnName},
                      {setting.name.columnName},
                      {setting.networks.columnName},
                      {setting.nodeConfig.columnName},
                      {setting.photoPath.columnName},
                      {setting.previewPrivacy.columnName},
                      {setting.publicKey.columnName},
                      {setting.signingPhrase.columnName},
                      {setting.walletRootAddress.columnName},
                      synthetic_id)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'id')"""

  db.exec(query,
            s.userAddress,
            s.currency,
            s.currentNetwork,
            s.dappsAddress,
            s.eip1581Address,
            s.installationID,
            s.keyUID,
            s.keycardInstanceUID,
            s.keycardPairedOn,
            s.keycardPairing,
            s.latestDerivedPath,
            s.mnemonic,
            s.name,
            s.networks,
            nodecfg,
            s.photoPath,
            s.previewPrivacy,
            s.publicKey,
            s.signingPhrase,
            s.walletRootAddress)

proc saveSetting*(db: DbConn, setting: string, value: auto) =
  var settings: Settings
  db.exec(fmt"""UPDATE {settings.tableName} SET {setting} = ? WHERE synthetic_id = 'id'""", value)

proc getNodeConfig*(db: DbConn): JsonNode =
  var settings: Settings
  let query = fmt"""SELECT {settings.nodeConfig.columnName} FROM {settings.tableName} WHERE synthetic_id = 'id'"""
  let nodeConfig = db.value(JsonNode, query)
  if not nodeConfig.isSome:
    raise newException(ValueError, "No record found for node config")
  nodeConfig.get

proc getSettings*(db: DbConn): Settings =
  let query = fmt"""SELECT * FROM {result.tableName} WHERE synthetic_id = 'id'"""

  let settings = db.one(Settings, query)
  if not settings.isSome:
    raise newException(ValueError, "No record found for settings")
  settings.get
