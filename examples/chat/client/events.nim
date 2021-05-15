import # chat libs
  ./common

export common

logScope:
  topics = "chat"

type
  ClientEvent* = ref object of Event
  UserMessage* = ref object of ClientEvent
    username*: string
    message*: string

const clientEvents*: seq[string] = @[
  "UserMessage"
]

proc listenToStatus(self: ChatClient) {.async.} =
  let worker = self.taskRunner.workers["status"].worker
  while self.running and self.taskRunner.running.load():
    let event = await worker.chanRecvFromWorker.recv()
    asyncSpawn self.events.send(event)

proc listen*(self: ChatClient) {.async.} =
  asyncSpawn self.listenToStatus()