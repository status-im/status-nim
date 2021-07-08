import # nim libs
  json, options, os, unittest

import # vendor libs
  chronos, json_serialization, sqlcipher, web3/conversions as web3_conversions

import # nim-status libs
  ../nim_status/[database, pendingtxs],
  ./test_helpers

procSuite "pendingtxs":
  asyncTest "pendingtxs":
    let password = "qwerty"
    let path = currentSourcePath.parentDir() & "/build/my.db"
    removeFile(path)
    let db = initializeDB(path, password)

    let tx = PendingTx(
      networkId: 1,
      transactionHash: "0x1234",
      blkNumber: 0,
      fromAddress: "0xabc",
      toAddress: "0xdef",
      txType: "default_type",
      data: "data_json"
    )

    # savePendingTx
    db.savePendingTx(tx)

    # getPendingOutboundTxsByAddress
    var txs = db.getPendingOutboundTxsByAddress(1, "0xabc")

    check:
      len(txs) == 1 and
        txs[0].transactionHash == "0x1234" and
        txs[0].fromAddress == "0xabc" and
        txs[0].toAddress == "0xdef" and
        txs[0].txType == "default_type" and
        txs[0].data == "data_json"

    # deletePendingTx
    db.deletePendingTx("0x1234")

    txs = db.getPendingTxs(1)

    check:
      len(txs) == 0

    db.close()
    removeFile(path)
