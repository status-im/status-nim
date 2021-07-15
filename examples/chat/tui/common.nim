import # chat libs
  ../client, ./ncurses_helpers

export client, ncurses_helpers

logScope:
  topics = "chat tui"

type
  ChatTUI* = ref object
    chatConfig*: ChatConfig
    chatWin*: PWindow
    chatWinBox*: PWindow
    client*: ChatClient
    currentInput*: string
    events*: EventChannel
    infoLine*: PWindow
    infoLineBottom*: PWindow
    inputReady*: bool
    inputWin*: PWindow
    inputWinBox*: PWindow
    locale*: string
    mainWin*: PWindow
    mouse*: bool
    outputReady*: bool
    running*: bool
    taskRunner*: TaskRunner

  TUIEvent* = ref object of Event

  InputKey* = ref object of TUIEvent
    key*: int
    name*: string

  InputReady* = ref object of TUIEvent
    ready*: bool

  InputString* = ref object of TUIEvent
    str*: string

  # all fields on types that derive from Command should be of type `string`
  Command* = ref object of RootObj

  AddWalletAccount* = ref object of Command
    name*: string
    password*: string

  Connect* = ref object of Command

  CommandParameter* = ref object of RootObj
    name*: string
    description*: string

  CreateAccount* = ref object of Command
    password*: string

  Disconnect* = ref object of Command

  Help* = ref object of Command
    command*: string

  HelpText* = ref object of RootObj
    command*: string
    parameters*: seq[CommandParameter]
    aliases*: seq[string]
    description*: string

  ImportMnemonic* = ref object of Command
    mnemonic*: string
    passphrase*: string
    password*: string

  ListAccounts* = ref object of Command

  Login* = ref object of Command
    account*: string
    password*: string

  Logout* = ref object of Command

  Quit* = ref object of Command

  SendMessage* = ref object of Command
    message*: string

const
  TUIEvents* = [
    "InputKey",
    "InputReady",
    "InputString"
  ]

  DEFAULT_COMMAND* = ""

  commands* = {
    DEFAULT_COMMAND: "SendMessage",
    "addaccount": "AddWalletAccount",
    "connect": "Connect",
    "createaccount": "CreateAccount",
    "disconnect": "Disconnect",
    "help": "Help",
    "importmnemonic": "ImportMnemonic",
    "listaccounts": "ListAccounts",
    "login": "Login",
    "logout": "Logout",
    "quit": "Quit"
  }.toTable

  aliases* = {
    "?": "help",
    "add": "addaccount",
    "create": "createaccount",
    "import": "importmnemonic",
    "list": "listaccounts",
    "send": DEFAULT_COMMAND
  }.toTable

  aliased* = {
    DEFAULT_COMMAND: @["send"],
    "addaccount": @["add"],
    "createaccount": @["create"],
    "importmnemonic": @["import"],
    "help": @["?"],
    "listaccounts": @["list"]
  }.toTable

proc stop*(self: ChatTUI) {.async.} =
  debug "TUI stopping"

  var stopping: seq[Future[void]] = @[]
  stopping.add self.client.stop()
  stopping.add self.taskRunner.stop()
  await allFutures(stopping)
  self.events.close()

  # calling `endwin` here isn't working as expected, i.e. if the terminal is
  # resized while the chat program is running then the terminal's state is
  # often "corrupted" when the chat program exits; calling `endwin` before
  # program exit is supposed to prevent it from being corrupted
  endwin()
  trace "TUI restored the terminal"

  debug "TUI stopped"
  # set `self.running = true` as the the last step to facilitate clean program
  # exit (see ../chat)
  self.running = false
