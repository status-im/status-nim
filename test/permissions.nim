import # nim libs
  options, os, unittest

import # vendor libs
  chronos, json_serialization, sqlcipher

import # nim-status libs
  ../nim_status/[database, permissions],
  ./test_helpers

procSuite "permissions":
  asyncTest "permissions":
    let password = "qwerty"
    let path = currentSourcePath.parentDir() & "/build/my.db"
    removeFile(path)
    let db = initializeDB(path, password)

    let dappPerm1: DappPermissions = DappPermissions(
      name: "Dapp1",
      permissions: @["perm1a"]
    )
    let dappPerm2: DappPermissions = DappPermissions(
      name: "Dapp2",
      permissions: @["perm2a", "perm2b"]
    )
    let dappPerm3: DappPermissions = DappPermissions(
      name: "Dapp3",
      permissions: @[]
    )

    db.addPermissions(dappPerm1)
    db.addPermissions(dappPerm2)
    db.addPermissions(dappPerm3)

    var dappPerms = db.getPermissions()

    check:
      dappPerms == @[dappPerm1, dappPerm2, dappPerm3]
      # ensure serialized result is the same as status-go's RPC response
      Json.encode(dappPerms) == """[{"dapp":"Dapp1","permissions":["perm1a"]},{"dapp":"Dapp2","permissions":["perm2a","perm2b"]},{"dapp":"Dapp3","permissions":[]}]"""

    db.deletePermission(dappPerm2.name)
    dappPerms = db.getPermissions()

    check:
      dappPerms == @[dappPerm1, dappPerm3]

    db.close()
    removeFile(path)
