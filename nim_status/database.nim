import # std libs
  std/[os, unicode]

import # vendor libs
  nimcrypto/keccak, results, sqlcipher

import # nim-status libs
  ./migration,
  ./migrations/sql_scripts_accounts as acc_migration,
  ./migrations/sql_scripts_app as app_migration

export sqlcipher

proc initializeDB*(path:string): DbConn =
  createDir path.parentDir()
  var runMigrations = false
  if not path.fileExists():
    runMigrations = true
  result = openDatabase(path)
  if runMigrations:
    let definition = acc_migration.newMigrationDefinition()
    if not result.migrate(definition).isOk:
      raise newException(SqliteError, "Failure executing migrations")

proc hash(password: string): string =
  "0x" & toUpper($keccak_256.digest(password))

proc initializeDB*(path, password: string): DbConn =
  createDir path.parentDir()
  var runMigrations = false
  if not path.fileExists():
    runMigrations = true
  result = openDatabase(path)
  result.key(password.hash)
  result.exec("PRAGMA cipher_page_size = 1024")
  result.exec("PRAGMA kdf_iter = 3200")
  result.exec("PRAGMA cipher_hmac_algorithm = HMAC_SHA1")
  result.exec("PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA1")
  result.exec("PRAGMA foreign_keys = ON")
  result.exec("PRAGMA journal_mode = WAL")
  if runMigrations:
    let definition = app_migration.newMigrationDefinition()
    if not result.migrate(definition).isOk:
      raise newException(SqliteError, "Failure executing migrations")
