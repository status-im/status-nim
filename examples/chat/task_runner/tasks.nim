import # vendor libs
  chronicles, chronos, json_serialization, json_serialization/std/options

import ./serialization

export chronicles, json_serialization, options, serialization

logScope:
  topics = "task_runner"

type
  ContextArg* = ref object of RootObj

  Context* = proc(arg: ContextArg): Future[void] {.gcsafe, nimcall, raises: [Defect].}

  Task* = proc(taskArgEncoded: string): Future[void] {.gcsafe, nimcall, raises: [Defect].}

  TaskKind* = enum no_rts, rts # rts := "return to sender"

  TaskArg* = ref object of RootObj
    chanSendToHost*: ByteAddress # pointer to channel for sending to host
    task*: ByteAddress # pointer to task proc
    taskName*: string
    workerRunning*: ByteAddress # pointer to taskRunner's .running Atomic[bool]

# there should eventually be the ability to reliably stop individual workers,
# i.e. each worker would have it's own `.running` Atomic[bool] (maybe
# reconsider the naming, e.g. "workerStopped" vs. "workerRunning" to be
# consistent with "taskStopped", or switch the latter to
# "taskRunning"). Currently, a TaskRunner instance's `.running` Atomic[bool]
# serves as a "master switch" for all the workers, so it's not completely
# inaccurate for the field on TaskArg to be named `workerRunning`

const emptyContext*: Context =
  proc(arg: ContextArg) {.async, gcsafe, nimcall.} = discard

proc decode*[T](arg: string): T =
  Json.decode(arg, T, allowUnknownFields = true)

proc encode*[T](arg: T): string =
  arg.toJson(typeAnnotations = true)
