import # std libs
  std/[strformat, strutils]

import # nim-status libs
  ../../../nim_status/[accounts, alias]

import # chat libs
  ./parser

export parser

logScope:
  topics = "chat tui"

# `action` and `command` (see ./commands) procs are `{.async.}` for the
# convenience of e.g. interaction with channels and tasks. However, they should
# be self-contained with respect to their effects (with allowance for
# `await`-ing or `waitFor`-ing invocation of another `{.async.}` proc or
# blocking until return of a synchronous proc), i.e. other than invoking tasks
# (to do work on other threads) or sending to a channel (using `asyncSpawn`),
# they *should not* spawn independent asynchronous routines to cause side
# effects in the main thread that would happen *after* the current
# action/command has returned. They should also return as soon as possible and
# should be considered to effectively "block the main thread" while they are
# executing. The time budget for an action, from start to finish and including
# the execution time of procs it may call, is 16 milliseconds so as to maintain
# at least 60 FPS in the TUI.

const
  KEY_MOUSE = "KEY_MOUSE"
  KEY_RESIZE = "KEY_RESIZE"

proc dispatch*(self: ChatTUI, command: string) {.gcsafe, nimcall.} =
  let (commandType, args, isCommand) = parse(command)

  if isCommand: commandCases()
  else:
    # should print an error/explanation to the screen as well
    error "TUI received malformed or unknown command", command

# InputKey ---------------------------------------------------------------------

proc action*(self: ChatTUI, event: InputKey) {.async, gcsafe, nimcall.} =
  # if TUI is not ready for input then ignore it
  if self.inputReady:
    # handle mouse events and special keys e.g. arrow keys, ESCAPE, RETURN, etc.
    let
      key = event.key
      name = event.name

    case name:
      of ESCAPE:
        discard

      of KEY_MOUSE:
        var me: MEvent
        getmouse(addr me)
        discard

      of KEY_RESIZE:
        self.resizeScreen()

      of RETURN:
        let command = self.currentInput

        if command.strip(trailing = false) != "" and
           not aliased[DEFAULT_COMMAND].contains(command.strip()[1..^1]):
          self.currentInput = ""
          trace "TUI reset current input", currentInput=self.currentInput

          self.clearInput()
          self.dispatch(command)

      else:
        discard

# InputReady -------------------------------------------------------------------

proc action*(self: ChatTUI, event: InputReady) {.async, gcsafe, nimcall.} =
  let
    ready = event.ready

  if ready:
    self.inputReady = true
    self.drawScreen()
    self.outputReady = true

# InputString ------------------------------------------------------------------

proc action*(self: ChatTUI, event: InputString) {.async, gcsafe, nimcall.} =
  # if TUI is not ready for input then ignore it
  if self.inputReady:
    let input = event.str
    self.currentInput = self.currentInput & input
    trace "TUI updated current input", currentInput=self.currentInput

    self.printInput(input)

# CreateAccountResult ----------------------------------------------------------

proc action*(self: ChatTUI, event: CreateAccountResult) {.async, gcsafe,
  nimcall.} =

  # if TUI is not ready for output then ignore it
  if self.outputReady:
    let
      account = event.account
      timestamp = event.timestamp

      name = account.name
      keyUid = account.keyUid
      abbrev = keyUid[0..5] & "..." & keyUid[^4..^1]

    self.printResult("Created account:", timestamp)
    self.printResult(fmt"{2.indent()}{name} ({abbrev})", timestamp)

# ImportMnemonicResult -----------------------------------------------------------

proc action*(self: ChatTUI, event: ImportMnemonicResult) {.async, gcsafe, nimcall.} =
  # if TUI is not ready for output then ignore it
  if self.outputReady:
    let
      multiAcc = event.multiAcc
      timestamp = event.timestamp

      account = multiAcc.accounts[2]
      name = account.publicKey.generateAlias()
      keyUid = account.keyUid
      abbrev = keyUid[0..5] & "..." & keyUid[^4..^1]

    # TODO need proper JSON serialization for this
    trace "TUI importing account" , multiAcc=multiAcc.encode

    self.printResult("Imported account:", timestamp)
    self.printResult(fmt"{2.indent()}{name} ({abbrev})", timestamp)

# ListAccountsResult -----------------------------------------------------------

proc action*(self: ChatTUI, event: ListAccountsResult) {.async, gcsafe,
  nimcall.} =

  # if TUI is not ready for output then ignore it
  if self.outputReady:
    let
      accounts = event.accounts
      timestamp = event.timestamp

    trace "TUI showing accounts from nim-status", accounts=(%accounts)

    if accounts.len > 0:
      var i = 1
      self.printResult("Existing accounts:", timestamp)
      for account in accounts:
        let
          name = account.name
          keyUid = account.keyUid
          abbrev = keyUid[0..5] & "..." & keyUid[^4..^1]

        self.printResult(fmt"{2.indent()}{i}. {name} ({abbrev})",
          timestamp)
        i = i + 1
    else:
      self.printResult(
        "No accounts. Create an account using `/create <password>`.",
        timestamp)

# LoginResult ------------------------------------------------------------------

proc action*(self: ChatTUI, event: LoginResult) {.async, gcsafe, nimcall.} =
  let
    error = event.error
    loggedin = event.loggedin

  if error != "":
    self.wprintFormatError(epochTime().int64, fmt"{error}")
  else:
    self.client.account = event.account
    self.printResult("Login successful.", epochTime().int64)
    if not self.client.online:
      asyncSpawn self.client.connect(self.client.account.name)

  self.client.loggedin = loggedin
  trace "TUI updated client state", loggedin

# LogoutResult -----------------------------------------------------------------

proc action*(self: ChatTUI, event: LogoutResult) {.async, gcsafe, nimcall.} =
  let
    error = event.error
    loggedin = event.loggedin

  if error != "":
    self.wprintFormatError(epochTime().int64, fmt"{error}")
  else:
    self.client.account = PublicAccount()
    self.printResult("Logout successful.", epochTime().int64)
    if self.client.online:
      asyncSpawn self.client.disconnect()

  self.client.loggedin = loggedin
  trace "TUI updated client state", loggedin

# NetworkStatus ----------------------------------------------------------------

proc action*(self: ChatTUI, event: NetworkStatus) {.async, gcsafe, nimcall.} =
  let online = event.online

  self.client.online = online
  trace "TUI updated client state", online

# UserMessage ------------------------------------------------------------------

proc action*(self: ChatTUI, event: UserMessage) {.async, gcsafe, nimcall.} =
  # if TUI is not ready for output then ignore it
  if self.outputReady:
    let
      message = event.message
      timestamp = event.timestamp
      username = event.username

    debug "TUI received user message", message, timestamp, username
    self.printMessage(message, timestamp, username)
