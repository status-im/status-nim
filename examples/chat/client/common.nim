import # std libs
  std/times

import # chat libs
  ../config, ../task_runner

import # nim-status libs
  ../../../nim_status/accounts

export accounts, config, task_runner, times

logScope:
  topics = "chat client"

type
  Event* = ref object of RootObj

  EventChannel* = AsyncChannel[ThreadSafeString]

  # TODO: alphabetise ChatClient above HelpText -- didn't want to interfere
  # with ongoing work
  ChatClient* = ref object
    account*: PublicAccount
    chatConfig*: ChatConfig
    events*: EventChannel
    loggedin*: bool
    online*: bool
    running*: bool
    taskRunner*: TaskRunner

const status* = "status"

proc newEventChannel*(): EventChannel =
  newAsyncChannel[ThreadSafeString](-1)
