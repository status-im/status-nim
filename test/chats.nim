import # nim libs
  json, options, os, unittest

import # vendor libs
  chronos, json_serialization, sqlcipher, stew/byteutils,
  web3/conversions as web3_conversions

import # nim-status libs
  ../nim_status/[chats, contacts, conversions, database, messages],
  ./test_helpers

procSuite "chats":
  asyncTest "chats":
    let password = "qwerty"
    let path = currentSourcePath.parentDir() & "/build/my.db"
    removeFile(path)
    let db = initializeDB(path, password)

    var chat = Chat(
      id: "ContactId",
      name: "chat-name",
      color: "blue",
      chatType: 1,
      active: true,
      timestamp: 25,
      deletedAtClockValue: 15,
      publicKey: "public-key".toBytes(),
      unviewedMessageCount: 3,
      lastClockValue: 18,
      lastMessage: some("lastMessage".toBytes()),
      members: "members".toBytes(),
      membershipUpdates: "membershipUpdates".toBytes(),
      profile: "profile",
      invitationAdmin: "invitationAdmin",
      muted: false,
    )

    # saveChat
    db.saveChat(chat)

    # getChats
    chat.id = "ContactId1"
    db.saveChat(chat)
    var dbChats = db.getChats()

    check:
      len(dbChats) == 2

    # getChatById
    var dbChat = db.getChatById("ContactId").get()

    check:
      dbChat.active == true and
        dbChat.publicKey == "public-key".toBytes() and
        dbChat.unviewedMessageCount == 3

    # [mute/unmute]Chat
    db.muteChat("ContactId")
    dbChat = db.getChatById("ContactId").get()

    check:
      dbChat.muted == true

    db.unmuteChat("ContactId")
    dbChat = db.getChatById("ContactId").get()

    check:
      dbChat.muted == false

    # blockContact
    let contact = Contact(
      id: "ContactId",
      address: some("0xdeadbeefdeadbeefdeadbeefdeadbeef11111111".parseAddress),
      name: some("TheUsername1"),
      ensVerified: true,
      ensVerifiedAt: 11111,
      lastENSClockValue: 111,
      ensVerificationRetries: 1,
      alias: some("Teenage Mutant NinjaTurtle"),
      identicon: "ABCDEF",
      photo: some("ABC"),
      lastUpdated: 11111,
      systemTags: @["tag11","tag12","tag13"],
      deviceInfo: @[ContactDeviceInfo(installationId: "ABC1", timestamp: 11, fcmToken: "ABC1")],
      tributeToTalk: some("ABC1"),
      localNickname: some("ABC1")
    )
    db.saveContact(contact)

    var msg = Message(
      id: "msg1",
      whisperTimestamp: 0,
      source: "ContactId",
      destination: "default_destination".toBytes(),
      text: "text",
      contentType: 0,
      username: "user1",
      timestamp: 25,
      chatId: "chat-id",
      localChatId: "ContactId",
      hide: false,
      responseTo: "user1",
      messageType: 0,
      clockValue: 0,
      seen: false,
      outgoingStatus: "Delivered",
      parsedText: "parsed".toBytes(),
      rawPayload: "raw".toBytes(),
      stickerPack: 0,
      stickerHash: "hash",
      commandId: "command1",
      commandValue: "commandValue",
      commandAddress: "commandAddress",
      commandFrom: "commandFrom",
      commandContract: "commandContract",
      commandTransactionHash: "commandTransactionHash",
      commandSignature: "commandSignature".toBytes(),
      commandState: 3,
      audioPayload: "audioPayload".toBytes(),
      audioType: 0,
      audioDurationMs: 10,
      audioBase64: "sdf",
      replaceMessage: "message_replacement",
      rtl: false,
      lineCount: 5,
      links: "links",
      mentions: "mentions",
      imagePayload: "blob".toBytes(),
      imageType: "type",
      imageBase64: "sdfsdfsdf"
    )
    db.saveMessage(msg)
    msg.id = "msg2"
    msg.source = "ContactId1"
    msg.localChatId = "ContactId1"
    db.saveMessage(msg)

    let chatsAfterBlocking = db.blockContact(contact)

    check:
      # Assert that blockContact deleted entry from user_messages
      db.getMessageById("msg1").isNone()
      # Assert that blockContact deleted entry from chats
      db.getChatById("ContactId").isNone()
      # Assert there is 1 unviewed message from ContactId1
      len(chatsAfterBlocking) == 1

    let chatEntry = chatsAfterBlocking[0]
    echo "chatEntry"
    echo chatEntry

    check:
      chatEntry.unviewedMessageCount == 1

    # deleteChat
    db.deleteChat(chat)
    dbChats = db.getChats()

    check:
      # Chat with id=ContactId was deleted by blockContact
      len(dbChats) == 0

    db.close()
    removeFile(path)
