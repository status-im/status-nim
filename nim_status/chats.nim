import # nim libs
  json, options, strformat, marshal
import # vendor libs
  sqlcipher, json_serialization, json_serialization/[reader, writer, lexer],
  stew/byteutils

import messages, contacts

type
  ChatType* {.pure.} = enum
    Id = "id",
    Name = "name",
    Color = "color",
    ChatType = "chatType",
    Active = "active",
    Timestamp = "timestamp",
    DeletedAtClockValue = "deletedAtClockValue",
    PublicKey = "publicKey",
    UnviewedMessageCount = "unviewedMessageCount",
    LastClockValue = "lastClockValue",
    LastMessage = "lastMessage",
    Members = "members",
    MembershipUpdates = "membershipUpdates"
    Profile = "profile",
    InvitationAdmin = "invitationAdmin",
    Muted = "muted"

  ChatCol* {.pure.} = enum
    Id = "id",
    Name = "name",
    Color = "color",
    ChatType = "type",
    Active = "active",
    Timestamp = "timestamp",
    DeletedAtClockValue = "deleted_at_clock_value",
    PublicKey = "public_key",
    UnviewedMessageCount = "unviewed_message_count",
    LastClockValue = "last_clock_value",
    LastMessage = "last_message",
    Members = "members",
    MembershipUpdates = "membership_updates"
    Profile = "profile",
    InvitationAdmin = "invitation_admin",
    Muted = "muted"


  Chat* = object
    id* {.serializedFieldName($ChatType.Id), dbColumnName($ChatCol.Id).}: string
    name* {.serializedFieldName($ChatType.Name), dbColumnName($ChatCol.Name).}: string
    color* {.serializedFieldName($ChatType.Color), dbColumnName($ChatCol.Color).}: string
    chatType* {.serializedFieldName($ChatType.ChatType), dbColumnName($ChatCol.ChatType).}: int
    active* {.serializedFieldName($ChatType.Active), dbColumnName($ChatCol.Active).}: bool
    timestamp* {.serializedFieldName($ChatType.Timestamp), dbColumnName($ChatCol.Timestamp).}: int
    deletedAtClockValue* {.serializedFieldName($ChatType.DeletedAtClockValue), dbColumnName($ChatCol.DeletedAtClockValue).}: int
    publicKey* {.serializedFieldName($ChatType.PublicKey), dbColumnName($ChatCol.PublicKey).}: seq[byte]
    unviewedMessageCount* {.serializedFieldName($ChatType.UnviewedMessageCount), dbColumnName($ChatCol.UnviewedMessageCount).}: int
    lastClockValue* {.serializedFieldName($ChatType.LastClockValue), dbColumnName($ChatCol.LastClockValue).}: int
    lastMessage* {.serializedFieldName($ChatType.LastMessage), dbColumnName($ChatCol.LastMessage).}: Option[seq[byte]]
    members* {.serializedFieldName($ChatType.Members), dbColumnName($ChatCol.Members).}: seq[byte]
    membershipUpdates* {.serializedFieldName($ChatType.MembershipUpdates), dbColumnName($ChatCol.MembershipUpdates).}: seq[byte]
    profile* {.serializedFieldName($ChatType.Profile), dbColumnName($ChatCol.Profile).}: string
    invitationAdmin* {.serializedFieldName($ChatType.InvitationAdmin), dbColumnName($ChatCol.InvitationAdmin).}: string
    muted* {.serializedFieldName($ChatType.Muted), dbColumnName($ChatCol.Muted).}: bool

proc getChats*(db: DbConn): seq[Chat] =
  let query = """SELECT * from chats"""

  result = db.all(Chat, query)

proc getChatById*(db: DbConn, id: string): Option[Chat] =
  let query = """SELECT * from chats where id = ?"""

  result = db.one(Chat, query, id)

proc saveChat*(db: DbConn, chat: Chat) =
  let query = fmt"""INSERT INTO chats(
    {$ChatCol.Id},
    {$ChatCol.Name},
    {$ChatCol.Color},
    {$ChatCol.ChatType},
    {$ChatCol.Active},
    {$ChatCol.Timestamp},
    {$ChatCol.DeletedAtClockValue},
    {$ChatCol.PublicKey},
    {$ChatCol.UnviewedMessageCount},
    {$ChatCol.LastClockValue},
    {$ChatCol.LastMessage},
    {$ChatCol.Members},
    {$ChatCol.MembershipUpdates},
    {$ChatCol.Profile},
    {$ChatCol.InvitationAdmin},
    {$ChatCol.Muted})
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
  """
  db.exec(query,
    chat.id,
    chat.name,
    chat.color,
    chat.chatType,
    chat.active,
    chat.timestamp,
    chat.deletedAtClockValue,
    chat.publicKey,
    chat.unviewedMessageCount,
    chat.lastClockValue,
    chat.lastMessage,
    chat.members,
    chat.membershipUpdates,
    chat.profile,
    chat.invitationAdmin,
    chat.muted)

proc muteChat*(db: DbConn, chatId: string) =
  let query = fmt"""UPDATE chats SET muted = 1 WHERE id = ?"""

  db.exec(query, chatId)

proc unmuteChat*(db: DbConn, chatId: string) =
  let query = fmt"""UPDATE chats SET muted = 0 WHERE id = ?"""

  db.exec(query, chatId)

proc deleteChat*(db: DbConn, chat: Chat) =
  let query = fmt"""DELETE FROM chats where id = ?"""

  db.exec(query, chat.id)

# BlockContact updates a contact, deletes all the messages and 1-to-1 chat, updates the unread messages count and returns a map with the new count
proc blockContact*(db: DbConn, contact: Contact): seq[Chat] =
  var chats:seq[Chat] = @[]
  # Delete messages
  var query = fmt"""DELETE
     FROM user_messages
     WHERE source = ?"""

  db.exec(query, contact.id)

  # Update contact
  saveContact(db, contact)

  # Delete one-to-one chat
  query = fmt"""DELETE FROM chats WHERE id = ?"""

  db.exec(query, contact.id)

  # Recalculate denormalized fields
  query = fmt"""UPDATE chats
    SET unviewed_message_count = (SELECT COUNT(1)
                                  FROM user_messages WHERE seen = 0
                                  AND local_chat_id = chats.id)"""
  db.exec(query)

  # return the updated chats
  chats = getChats(db)
  for chat in chats:
    query = fmt"""SELECT * FROM user_messages WHERE local_chat_id = ? ORDER BY clock_value DESC LIMIT 1"""
    var c = chat
    let lastMessages = db.one(Message, query, c.id)
    if lastMessages.isNone:
      # Reset LastMessage
      query = fmt"""UPDATE chats SET last_message = NULL WHERE id = ?"""
      db.exec(query, c.id)
      c.lastMessage = none(seq[byte])
    else:
      let lastMessage = lastMessages.get
      let encodedMessage = $$lastMessage
      query = fmt"""UPDATE chats SET last_message = ? WHERE id = ?"""
      db.exec(query, encodedMessage, c.id)
      c.lastMessage = some(encodedMessage.toBytes())

  chats
