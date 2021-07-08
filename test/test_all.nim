import
  # `test/account.nim` is presently disabled because it relies on
  # `test/test_utils.nim`, which relies on `nim_status/go/shim.nim`, which has
  # been removed from this repo
  # ./account,

  ./account/generator/generator,
  ./accounts,
  ./bip32,
  ./callrpc,
  ./chats,
  ./client,
  ./contacts,
  ./db_smoke,

  # `test/login_and_logout.nim` is presently disabled because
  # `nim_status/accounts.nim` uses a global mutable variable for `web3_conn`
  # (which can't be referenced within a chronos async function, e.g. an
  # `asyncTest`); it should instead be a property of an init'd Status object
  # (or something along those lines)
  # ./login_and_logout,

  ./mailservers,
  ./messages,
  ./mnemonic,
  ./multiaccount,
  ./migrations,
  ./pendingtxs,
  ./permissions,
  ./settings,
  ./tokens,
  ./tx_history,
  ./waku_smoke
