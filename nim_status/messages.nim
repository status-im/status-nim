import # nim libs
  json, options, sequtils, strutils, strformat

import # vendor libs
  sqlcipher, json_serialization, json_serialization/[reader, writer, lexer]

import # nim-status libs
  conversions

type
  MessageType* {.pure.} = enum
    Id = "id",
    WhisperTimestamp = "whisperTimestamp ",
    Source = "source",
    Destination = "destination",
    Text = "text",
    ContentType = "contentType",
    Username = "username",
    Timestamp = "timestamp",
    ChatId = "chatId",
    LocalChatId = "localChatId",
    Hide = "hide",
    ResponseTo = "responseTo",
    MessageType = "messageType",
    ClockValue = "clockValue",
    Seen = "seen",
    OutgoingStatus = "outgoingStatus",
    ParsedText = "parsedText",
    RawPayload = "rawPayload",
    StickerPack = "stickerPack",
    StickerHash = "stickerHash",
    CommandId = "commandId",
    CommandValue = "commandValue",
    CommandAddress = "commandAddress",
    CommandFrom = "commandFrom",
    CommandContract = "commandContract",
    CommandTransactionHash = "commandTransactionHash",
    CommandSignature = "commandSignature",
    CommandState = "commandState",
    AudioPayload = "audioPayload",
    AudioType = "audioType",
    AudioDurationMs = "audioDurationMs",
    AudioBase64 = "audioBase64",
    ReplaceMessage = "replaceMessage",
    Rtl = "rtl",
    LineCount = "lineCount",
    Links = "links",
    Mentions = "mentions",
    ImagePayload = "imagePayload",
    ImageType = "imageType",
    ImageBase64 = "imageBase64"

  MessageCol* {.pure.} = enum
    Id = "id",
    WhisperTimestamp = "whisper_timestamp",
    Source = "source",
    Destination = "destination",
    Text = "text",
    ContentType = "content_type",
    Username = "username",
    Timestamp = "timestamp",
    ChatId = "chat_id",
    LocalChatId = "local_chat_id",
    Hide = "hide",
    ResponseTo = "response_to",
    MessageType = "message_type",
    ClockValue = "clock_value",
    Seen = "seen",
    OutgoingStatus = "outgoing_status",
    ParsedText = "parsed_text",
    RawPayload = "raw_payload",
    StickerPack = "sticker_pack",
    StickerHash = "sticker_hash",
    CommandId = "command_id",
    CommandValue = "command_value",
    CommandAddress = "command_address",
    CommandFrom = "command_from",
    CommandContract = "command_contract",
    CommandTransactionHash = "command_transaction_hash",
    CommandSignature = "command_signature",
    CommandState = "command_state",
    AudioPayload = "audio_payload",
    AudioType = "audio_type",
    AudioDurationMs = "audio_duration_ms",
    AudioBase64 = "audio_base64",
    ReplaceMessage = "replace_message",
    Rtl = "rtl",
    LineCount = "line_count",
    Links = "links",
    Mentions = "mentions",
    ImagePayload = "image_payload",
    ImageType = "image_type",
    ImageBase64 = "image_base64" 

  Message* = object
    id* {.serializedFieldName($MessageType.Id), dbColumnName($MessageCol.Id).}: string
    whisperTimestamp* {.serializedFieldName($MessageType.WhisperTimestamp), dbColumnName($MessageCol.WhisperTimestamp).}: int
    source* {.serializedFieldName($MessageType.Source), dbColumnName($MessageCol.Source).}: string
    destination* {.serializedFieldName($MessageType.Destination), dbColumnName($MessageCol.Destination).}: seq[byte]
    text* {.serializedFieldName($MessageType.Text), dbColumnName($MessageCol.Text).}: string
    contentType* {.serializedFieldName($MessageType.ContentType), dbColumnName($MessageCol.ContentType).}: int
    username* {.serializedFieldName($MessageType.Username), dbColumnName($MessageCol.Username).}: string
    timestamp* {.serializedFieldName($MessageType.Timestamp), dbColumnName($MessageCol.Timestamp).}: int
    chatId* {.serializedFieldName($MessageType.ChatId), dbColumnName($MessageCol.ChatId).}: string
    localChatId* {.serializedFieldName($MessageType.LocalChatId), dbColumnName($MessageCol.LocalChatId).}: string
    hide* {.serializedFieldName($MessageType.Hide), dbColumnName($MessageCol.Hide).}: bool
    responseTo* {.serializedFieldName($MessageType.ResponseTo), dbColumnName($MessageCol.ResponseTo).}: string
    messageType* {.serializedFieldName($MessageType.MessageType), dbColumnName($MessageCol.MessageType).}: int
    clockValue* {.serializedFieldName($MessageType.ClockValue), dbColumnName($MessageCol.ClockValue).}: int
    seen* {.serializedFieldName($MessageType.Seen), dbColumnName($MessageCol.Seen).}: bool
    outgoingStatus* {.serializedFieldName($MessageType.OutgoingStatus), dbColumnName($MessageCol.OutgoingStatus).}: string
    parsedText* {.serializedFieldName($MessageType.ParsedText), dbColumnName($MessageCol.ParsedText).}: seq[byte]
    rawPayload* {.serializedFieldName($MessageType.RawPayload), dbColumnName($MessageCol.RawPayload).}: seq[byte]
    stickerPack* {.serializedFieldName($MessageType.StickerPack), dbColumnName($MessageCol.StickerPack).}: int
    stickerHash* {.serializedFieldName($MessageType.StickerHash), dbColumnName($MessageCol.StickerHash).}: string
    commandId* {.serializedFieldName($MessageType.CommandId), dbColumnName($MessageCol.CommandId).}: string
    commandValue* {.serializedFieldName($MessageType.CommandValue), dbColumnName($MessageCol.CommandValue).}: string
    commandAddress* {.serializedFieldName($MessageType.CommandAddress), dbColumnName($MessageCol.CommandAddress).}: string
    commandFrom* {.serializedFieldName($MessageType.CommandFrom), dbColumnName($MessageCol.CommandFrom).}: string
    commandContract* {.serializedFieldName($MessageType.CommandContract), dbColumnName($MessageCol.CommandContract).}: string
    commandTransactionHash* {.serializedFieldName($MessageType.CommandTransactionHash), dbColumnName($MessageCol.CommandTransactionHash).}: string
    commandSignature* {.serializedFieldName($MessageType.CommandSignature), dbColumnName($MessageCol.CommandSignature).}: seq[byte]
    commandState* {.serializedFieldName($MessageType.CommandState), dbColumnName($MessageCol.CommandState).}: int
    audioPayload* {.serializedFieldName($MessageType.AudioPayload), dbColumnName($MessageCol.AudioPayload).}: seq[byte]
    audioType* {.serializedFieldName($MessageType.AudioType), dbColumnName($MessageCol.AudioType).}: int
    audioDurationMs* {.serializedFieldName($MessageType.AudioDurationMs), dbColumnName($MessageCol.AudioDurationMs).}: int
    audioBase64* {.serializedFieldName($MessageType.AudioBase64), dbColumnName($MessageCol.AudioBase64).}: string
    replaceMessage* {.serializedFieldName($MessageType.ReplaceMessage), dbColumnName($MessageCol.ReplaceMessage).}: string
    rtl* {.serializedFieldName($MessageType.Rtl), dbColumnName($MessageCol.Rtl).}: bool
    lineCount* {.serializedFieldName($MessageType.LineCount), dbColumnName($MessageCol.LineCount).}: int
    links* {.serializedFieldName($MessageType.Links), dbColumnName($MessageCol.Links).}: string
    mentions* {.serializedFieldName($MessageType.Mentions), dbColumnName($MessageCol.Mentions).}: string
    imagePayload* {.serializedFieldName($MessageType.ImagePayload), dbColumnName($MessageCol.ImagePayload).}: seq[byte]
    imageType* {.serializedFieldName($MessageType.ImageType), dbColumnName($MessageCol.ImageType).}: string
    imageBase64* {.serializedFieldName($MessageType.ImageBase64), dbColumnName($MessageCol.ImageBase64).}: string


proc getMessageById*(db: DbConn, id: string): Option[Message] = 
  let query = """SELECT * from user_messages where id = ?"""

  result = db.one(Message, query, id)

proc saveMessage*(db: DbConn, message: Message) = 
  let query = fmt"""INSERT INTO user_messages(
    {$MessageCol.Id},
    {$MessageCol.WhisperTimestamp},
    {$MessageCol.Source},
    {$MessageCol.Destination},
    {$MessageCol.Text},
    {$MessageCol.ContentType},
    {$MessageCol.Username},
    {$MessageCol.Timestamp},
    {$MessageCol.ChatId},
    {$MessageCol.LocalChatId},
    {$MessageCol.Hide},
    {$MessageCol.ResponseTo},
    {$MessageCol.MessageType},
    {$MessageCol.ClockValue},
    {$MessageCol.Seen},
    {$MessageCol.OutgoingStatus},
    {$MessageCol.ParsedText},
    {$MessageCol.RawPayload},
    {$MessageCol.StickerPack},
    {$MessageCol.StickerHash},
    {$MessageCol.CommandId},
    {$MessageCol.CommandValue},
    {$MessageCol.CommandAddress},
    {$MessageCol.CommandFrom},
    {$MessageCol.CommandContract},
    {$MessageCol.CommandTransactionHash},
    {$MessageCol.CommandSignature},
    {$MessageCol.CommandState},
    {$MessageCol.AudioPayload},
    {$MessageCol.AudioType},
    {$MessageCol.AudioDurationMs},
    {$MessageCol.AudioBase64},
    {$MessageCol.ReplaceMessage},
    {$MessageCol.Rtl},
    {$MessageCol.LineCount},
    {$MessageCol.Links},
    {$MessageCol.Mentions},
    {$MessageCol.ImagePayload},
    {$MessageCol.ImageType},
    {$MessageCol.ImageBase64})
    VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) 
  """
  db.exec(query, 
    message.id,
    message.whisperTimestamp,
    message.source,
    message.destination,
    message.text,
    message.contentType,
    message.username,
    message.timestamp,
    message.chatId,
    message.localChatId,
    message.hide,
    message.responseTo,
    message.messageType,
    message.clockValue,
    message.seen,
    message.outgoingStatus,
    message.parsedText,
    message.rawPayload,
    message.stickerPack,
    message.stickerHash,
    message.commandId,
    message.commandValue,
    message.commandAddress,
    message.commandFrom,
    message.commandContract,
    message.commandTransactionHash,
    message.commandSignature,
    message.commandState,
    message.audioPayload,
    message.audioType,
    message.audioDurationMs,
    message.audioBase64,
    message.replaceMessage,
    message.rtl,
    message.lineCount,
    message.links,
    message.mentions,
    message.imagePayload,
    message.imageType,
    message.imageBase64)

proc deleteMessage*(db: DbConn, message: Message) =
  let query = fmt"""
    DELETE FROM user_messages where id = ?"""

  db.exec(query, message.id)

proc markAllRead*(db: DbConn, chatId: string) = 
  let query = fmt"""
     UPDATE user_messages SET seen = 1 WHERE local_chat_id = ? AND seen != 1"""
  db.exec(query, chatId)

  let chatQuery = fmt"""
    UPDATE chats SET unviewed_message_count = 0 WHERE id = ?"""

  db.exec(chatQuery, chatId)

proc markMessagesSeen*(db: DbConn, chatId: string, messageIds: seq[string]) = 
  let quotedIds = sequtils.map(messageIds, proc(s:string):string = "'" & s & "'")
  let inVector = strutils.join(quotedIds, ",")
  let query = fmt"UPDATE user_messages SET seen = 1 WHERE id IN (" & inVector & ")"

  db.exec(query)

  let chatQuery = fmt"""
    UPDATE chats SET unviewed_message_count =
		  (SELECT COUNT(1)
		   FROM user_messages
		   WHERE local_chat_id = ? AND seen = 0)
		WHERE id = ?"""

  db.exec(chatQuery, chatId, chatId)
