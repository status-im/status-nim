import # nim-status libs
  ../../../nim_status/accounts/public_accounts

import # chat libs
  ./common

export common

logScope:
  topics = "chat client"

type
  ClientEvent* = ref object of Event

  AddWalletAccountResult* = ref object of ClientEvent
    account*: PublicAccount
    error*: string
    timestamp*: int64

  CreateAccountResult* = ref object of ClientEvent
    account*: PublicAccount
    error*: string
    timestamp*: int64

  ImportMnemonicResult* = ref object of ClientEvent
    error*: string
    account*: PublicAccount
    timestamp*: int64

  ListAccountsResult* = ref object of ClientEvent
    accounts*: seq[PublicAccount]
    timestamp*: int64

  LoginResult* = ref object of ClientEvent
    account*: PublicAccount
    error*: string
    loggedin*: bool

  LogoutResult* = ref object of ClientEvent
    error*: string
    loggedin*: bool

  NetworkStatus* = ref object of ClientEvent
    online*: bool

  UserMessage* = ref object of ClientEvent
    message*: string
    timestamp*: int64
    username*: string

const clientEvents* = [
  "AddWalletAccountResult",
  "CreateAccountResult",
  "ImportMnemonicResult",
  "ListAccountsResult",
  "LoginResult",
  "LogoutResult",
  "NetworkStatus",
  "UserMessage"
]

proc listenToStatus(self: ChatClient) {.async.} =
  let worker = self.taskRunner.workers["status"].worker
  while self.running and self.taskRunner.running.load():
    let event = await worker.chanRecvFromWorker.recv()
    asyncSpawn self.events.send(event)

proc listen*(self: ChatClient) {.async.} =
  asyncSpawn self.listenToStatus()
