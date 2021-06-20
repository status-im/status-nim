import # chat libs
  ./client/tasks

export tasks

logScope:
  topics = "chat client"

# This module's purpose is to provide wrappers for task invocation to e.g. send
# a message via nim-status/waku running in a separate thread; starting the
# client also initiates listening for events coming from nim-status/waku.

# `type ChatClient` is defined in ./common to avoid circular dependency

proc new*(T: type ChatClient, chatConfig: ChatConfig): T =
  let statusArg = StatusArg(chatConfig: chatConfig)
  var taskRunner = TaskRunner.new()
  taskRunner.createWorker(thread, status, statusContext, statusArg)

  T(chatConfig: chatConfig, events: newEventChannel(), running: false,
    taskRunner: taskRunner)

proc start*(self: ChatClient) {.async.} =
  debug "client starting"

  self.events.open()
  await self.taskRunner.start()

  # set `self.running = true` before any `asyncSpawn` so client logic can check
  # `self.running` to know whether to run / continue running / stop running
  self.running = true
  debug "client started"

  asyncSpawn self.listen()

proc stop*(self: ChatClient) {.async.} =
  debug "client stopping"

  self.running = false
  await self.taskRunner.stop()
  self.events.close()

  debug "client stopped"

proc login*(self: ChatClient, username: string) {.async.} =
  asyncSpawn startWakuChat2(self.taskRunner, status, username)

proc logout*(self: ChatClient) {.async.} =
  asyncSpawn stopWakuChat2(self.taskRunner, status)

proc sendMessage*(self: ChatClient, message: string) {.async.} =
  asyncSpawn publishWakuChat2(self.taskRunner, status, message)
