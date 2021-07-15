import # std libs
  std/[os, strutils, times]

import # nim-status libs
  ../../nim_status/[client, database],# ../../nim_status/accounts/public_accounts,
  ../../nim_status/extkeys/[paths, types]

import # chat libs
  ./events, ./waku_chat2

export events

logScope:
  topics = "chat client"

type
  StatusArg* = ref object of ContextArg
    chatConfig*: ChatConfig

  StatusState* = enum loggedout, loggingin, loggedin, loggingout

var
  conf {.threadvar.}: ChatConfig
  connected {.threadvar.}: bool
  contentTopic {.threadvar.}: ContentTopic
  contextArg {.threadvar.}: StatusArg
  nick {.threadvar.}: string
  subscribed {.threadvar.}: bool
  status {.threadvar.}: StatusObject
  statusState {.threadvar.}: StatusState
  wakuNode {.threadvar.}: WakuNode
  wakuState {.threadvar.}: WakuState

when PayloadV1:
  var
    symKey {.threadvar.}: SymKey
    symKeyGenerated {.threadvar.}: bool

proc resetContext() {.gcsafe, nimcall.} =
  connected = false
  nick = ""
  subscribed = false
  wakuNode = nil
  wakuState = WakuState.stopped

const statusContext*: Context = proc(arg: ContextArg) {.async, gcsafe, nimcall,
  raises: [Defect].} =

  # set threadvar values that are never reset, i.e. persist across dis/connect
  contextArg = cast[StatusArg](arg)
  conf = contextArg.chatConfig
  contentTopic = conf.contentTopic

  status = StatusObject.new(conf.dataDir)
  # threadvar `statusState` is currently out of scope re: "resetting the
  # context"; the relevant code/logic can be reconsidered in the future, was
  # originally implemented in context of `startWakuChat2` and `stopWakuChat2`
  statusState = StatusState.loggedout

  # threadvar `symKeyGenerated` is a special case because it depends on
  # compile-time `PayloadV1` value and because the value of its counterpart
  # `symKey` only needs to be set once, i.e. it also persists across
  # dis/connect; but note that `symKey` itself is set for the first time in
  # task `startWakuChat2` as an optimization for TUI startup time
  when PayloadV1: symKeyGenerated = false

  # re/set threadvars that don't persist across dis/connect
  resetContext()

proc new(T: type UserMessage, wakuMessage: WakuMessage): T =
  var
    message: string
    timestamp: int64
    username: string

  let protoResult = Chat2Message.init(wakuMessage.payload)

  if protoResult.isOk:
    let chat2Message = protoResult[]
    message = string.fromBytes(chat2Message.payload)
    timestamp = chat2Message.timestamp
    username = chat2Message.nick
  else:
     # could happen if one/more clients on the same network/topic are able to
     # communicate but are using incompatible encodings for some reason
     message = string.fromBytes(wakuMessage.payload)
     timestamp = getTime().toUnix
     username = "[unknown]"

  T(message: message, timestamp: timestamp, username: username)

proc addWalletAccount*(name: string,
  password: string) {.task(kind=no_rts, stoppable=false).} =

  let timestamp = getTime().toUnix

  if statusState != StatusState.loggedin:
    let
      eventNotLoggedIn = AddWalletAccountResult(error: "Not logged in, " &
        "cannot create a new wallet account. Please login with /login first.",
        timestamp: timestamp)
      eventNotLoggedInEnc = eventNotLoggedIn.encode
      task = taskArg.taskName

    trace "task sent event to host", event=eventNotLoggedInEnc, task
    asyncSpawn chanSendToHost.send(eventNotLoggedInEnc.safe)
    return

  let
    dir = status.dataDir / "keystore"
    # Hardcode bip39Passphrase to empty string. Can be enabled in UI later if
    # needed.
    publicAccountResult = status.addWalletAccount(name, password, dir) 

  if publicAccountResult.isErr:
    let
      event = AddWalletAccountResult(error: "Error creating wallet account, " &
        "error: " & publicAccountResult.error, timestamp: timestamp)
      eventEnc = event.encode
      task = taskArg.taskName
    trace "task sent event with error to host", event=eventEnc, task
    asyncSpawn chanSendToHost.send(eventEnc.safe)
    return

  let
    account = publicAccountResult.get
    event = AddWalletAccountResult(account: account, timestamp: timestamp)
    eventEnc = event.encode
    task = taskArg.taskName

  trace "task sent event to host", event=eventEnc, task
  asyncSpawn chanSendToHost.send(eventEnc.safe)

proc createAccount*(password: string) {.task(kind=no_rts, stoppable=false).} =
  let timestamp = getTime().toUnix

  if statusState != StatusState.loggedout:
    let
      eventNotLoggedOut = AddWalletAccountResult(error: "You must be logged " &
        "out to create a new account. Please logout with /logout first.",
        timestamp: timestamp)
      eventNotLoggedOutEnc = eventNotLoggedOut.encode
      task = taskArg.taskName

    trace "task sent event to host", event=eventNotLoggedOutEnc, task
    asyncSpawn chanSendToHost.send(eventNotLoggedOutEnc.safe)
    return

  let
    paths = @[PATH_WALLET_ROOT, PATH_EIP_1581, PATH_WHISPER, PATH_DEFAULT_WALLET]
    dir = status.dataDir / "keystore"
    # Hardcode bip39Passphrase to empty string. Can be enabled in UI later if
    # needed.
    publicAccountResult = status.createAccount(12, 1, "", password,
      paths, dir) 

  if publicAccountResult.isErr:
    let
      event = CreateAccountResult(error: "Error creating account, error: " &
        publicAccountResult.error, timestamp: timestamp)
      eventEnc = event.encode
      task = taskArg.taskName
    trace "task sent event with error to host", event=eventEnc, task
    asyncSpawn chanSendToHost.send(eventEnc.safe)
    return

  let
    account = publicAccountResult.get
    event = CreateAccountResult(account: account, timestamp: timestamp)
    eventEnc = event.encode
    task = taskArg.taskName

  trace "task sent event to host", event=eventEnc, task
  asyncSpawn chanSendToHost.send(eventEnc.safe)

proc importMnemonic*(mnemonic: string, bip39Passphrase: string,
  password: string) {.task(kind=no_rts, stoppable=false).} =

  let
    timestamp = getTime().toUnix
    paths = @[PATH_WALLET_ROOT, PATH_EIP_1581, PATH_WHISPER, PATH_DEFAULT_WALLET]
    dir = status.dataDir / "keystore"
    importedResult = status.importMnemonic(Mnemonic mnemonic, bip39Passphrase,
      password, paths, dir)

  if importedResult.isErr:
    let
      event = events.ImportMnemonicResult(error: "Error importing mnemonic: " &
        importedResult.error, timestamp: timestamp)
      eventEnc = event.encode
      task = taskArg.taskName
    trace "task sent event with error to host", event=eventEnc, task
    asyncSpawn chanSendToHost.send(eventEnc.safe)

  let
    account = importedResult.get
    event = ImportMnemonicResult(account: account, timestamp: timestamp)
    eventEnc = event.encode
    task = taskArg.taskName

  trace "task sent event to host", event=eventEnc, task
  asyncSpawn chanSendToHost.send(eventEnc.safe)

proc listAccounts*() {.task(kind=no_rts, stoppable=false).} =
  let
    accounts = status.getPublicAccounts()
    event = ListAccountsResult(accounts: accounts, timestamp: getTime().toUnix)
    eventEnc = event.encode
    task = taskArg.taskName

  trace "task sent event to host", event=eventEnc, task
  asyncSpawn chanSendToHost.send(eventEnc.safe)

proc login*(account: int,
  password: string) {.task(kind=no_rts, stoppable=false).} =

  let task = taskArg.taskName

  if statusState != StatusState.loggedout: return
  statusState = StatusState.loggingin

  let allAccounts = status.getPublicAccounts()

  var
    event: events.LoginResult
    eventEnc: string
    numberedAccount: PublicAccount
    keyUid: string

  if account < 1 or account > allAccounts.len:
    statusState = StatusState.loggedout

    event = events.LoginResult(
      error: "bad account number. List accounts using `/list`.",
      loggedin: false)

    eventEnc = event.encode

  else:
    numberedAccount = allAccounts[account - 1]
    keyUid = numberedAccount.keyUid

    try:
      let loginResult = status.login(keyUid, password)
      if loginResult.isErr:
        statusState = StatusState.loggedout
        event = events.LoginResult(error: loginResult.error, loggedin: false)
        eventEnc = event.encode

        trace "task sent event to host", event=eventEnc, task
        asyncSpawn chanSendToHost.send(eventEnc.safe)
        return

      statusState = StatusState.loggedin

      event = events.LoginResult(account: loginResult.get, error: "",
        loggedin: true)
      eventEnc = event.encode

    except SqliteError as e:
      error "task encountered a database error", error=e.msg, task

      statusState = StatusState.loggedout

      event = events.LoginResult(
        error: "login failed with database error, maybe wrong password?",
        loggedin: false)

      eventEnc = event.encode

  trace "task sent event to host", event=eventEnc, task
  asyncSpawn chanSendToHost.send(eventEnc.safe)

proc logout*() {.task(kind=no_rts, stoppable=false).} =
  let task = taskArg.taskName

  if statusState != StatusState.loggedin: return
  statusState = StatusState.loggingout

  var
    event: events.LogoutResult
    eventEnc: string

  try:
    let logoutResult = status.logout()
    if logoutResult.isErr:
      statusState = StatusState.loggedin
      event = events.LogoutResult(error: logoutResult.error, loggedin: true)
      eventEnc = event.encode

      trace "task sent event to host", event=eventEnc, task
      asyncSpawn chanSendToHost.send(eventEnc.safe)
      return

    statusState = StatusState.loggedout

    event = events.LogoutResult(error: "", loggedin: false)
    eventEnc = event.encode

  except SqliteError as e:
    error "task encountered a database error", error=e.msg, task

    statusState = StatusState.loggedin

    event = events.LogoutResult(error: "logout failed with database error.",
      loggedin: true)

    eventEnc = event.encode

  trace "task sent event to host", event=eventEnc, task
  asyncSpawn chanSendToHost.send(eventEnc.safe)

proc startWakuChat2*(username: string) {.task(kind=no_rts, stoppable=false).} =
  let task = taskArg.taskName

  if wakuState != WakuState.stopped: return
  wakuState = WakuState.starting

  nick = username

  when PayloadV1:
    # generate `symKey` here instead of `statusContext` to decrease startup
    # time of `TaskRunner` instance and therefore time to first paint of TUI
    if not symKeyGenerated:
      symKey = generateSymKey(contentTopic)
      symKeyGenerated = true

  let (extIp, extTcpPort, extUdpPort) = setupNat(conf.nat, clientId,
    Port(uint16(conf.tcpPort) + conf.portsShift),
    Port(uint16(conf.udpPort) + conf.portsShift))

  var nodekey: waku_chat2.crypto.PrivateKey

  if $conf.nodekey == "":
    nodekey = waku_chat2.crypto.PrivateKey.random(Secp256k1,
      waku_chat2.keys.newRng()[]).tryGet()
  else:
    nodekey = waku_chat2.crypto.PrivateKey(scheme: Secp256k1,
      skkey: SkPrivateKey.init(
        waku_chat2.utils.fromHex($conf.nodekey)).tryGet())

  wakuNode = WakuNode.init(nodekey, ValidIpAddress.init($conf.listenAddress),
    Port(uint16(conf.tcpPort) + conf.portsShift), extIp, extTcpPort)

  await wakuNode.start()

  wakuNode.mountRelay(conf.topics.split(" "),
    rlnRelayEnabled = conf.rlnRelay,
    relayMessages = conf.relay)

  wakuNode.mountLibp2pPing()

  let
    fleet = conf.fleet
    staticnodes = conf.staticnodes

  if staticnodes.len > 0:
    info "Connecting to static peers", nodes=staticnodes
    await wakuNode.connectToNodes(staticnodes)

  elif fleet != WakuFleet.none:
    info "Static peers not configured, choosing one at random", fleet
    let node = await selectRandomNode($fleet)

    info "Connecting to peer", node
    await wakuNode.connectToNodes(@[node])

  connected = true

  if conf.swap: wakuNode.mountSwap()

  if conf.relay:
    proc handler(topic: waku_chat2.Topic, data: seq[byte]) {.async, gcsafe.} =
      let decoded = WakuMessage.init(data)

      if decoded.isOk():
        let message = decoded.get()
        trace "decoded WakuMessage", message

        let
          event = UserMessage.new(message)
          eventEnc = event.encode

        trace "task sent event to host", event=eventEnc, task
        asyncSpawn chanSendToHost.send(eventEnc.safe)

      else:
        let error = decoded.error
        error "received invalid WakuMessage", error

    wakuNode.subscribe(DefaultTopic, handler)

    subscribed = true

  if conf.keepAlive: wakuNode.startKeepalive()

  wakuState = WakuState.started

  let
    event = NetworkStatus(online: true)
    eventEnc = event.encode

  trace "task sent event to host", event=eventEnc, task
  asyncSpawn chanSendToHost.send(eventEnc.safe)

proc stopWakuChat2*() {.task(kind=no_rts, stoppable=false).} =
  let task = taskArg.taskName

  if wakuState != WakuState.started: return
  wakuState = WakuState.stopping

  await wakuNode.stop()
  resetContext()

  let
    event = NetworkStatus(online: false)
    eventEnc = event.encode

  trace "task sent event to host", event=eventEnc, task
  asyncSpawn chanSendToHost.send(eventEnc.safe)

proc publishWakuChat2*(message: string) {.task(kind=no_rts, stoppable=false).} =
  if wakuState != WakuState.started or not connected: return

  let
    chat2pb = Chat2Message.init(nick, message).encode()
    wakuMessage = WakuMessage(payload: chat2pb.buffer,
      contentTopic: contentTopic, version: 0)

  asyncSpawn wakuNode.publish(DefaultTopic, wakuMessage)
