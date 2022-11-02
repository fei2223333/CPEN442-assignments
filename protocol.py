#!/usr/bin/env python3

from message import Message,AuthMessage,RkeyMessage,TextMessage
from crypto import CryptoProvider
import pdb

class Protocol:
    _MAGIC = "LPVPN"
    _VERSION = 0x01
    # Initializer (Called from app.py)
    def __init__(self,output,statechange):
        self._output = output
        self._statechange = statechange
        self._crypt = CryptoProvider(self._statechange.GetKey)


    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    def GetHandshakeInitiationMessage(self,key: str) -> bytes:
        self._crypt.reset()
        nonce = self._crypt.nonce()
        prime = self._crypt.prime()
        codec = Message.GetCodec(self._MAGIC,self._VERSION)
        message = AuthMessage(codec,Message.Type.AUTH,
                          AuthMessage.Command.INIT,[nonce],None,prime)
        message.hmac = codec.HMAC(self._crypt,message)
        return message


    # Checking if a received message is part of your protocol (called from app.py)
    def _IsMessagePartOfProtocol(self, message: bytes) -> bool:
        if len(message)>5:
            return self._MAGIC.encode()==message[:5]
        return False


    # Processing protocol message
    def _ProcessReceivedProtocolMessage(self, message: bytes):
        codec = Message.GetCodec(self._MAGIC,self._VERSION)
        message = codec.Decode(message)
        if Message.Type.AUTH == message.message_type:
            self._ProcessAuthMsg(message)
        elif Message.Type.RKEY == message.message_type:
            self._ProcessRkeyMsg(message)
        elif Message.Type.TEXT == message.message_type:
            self._ProcessTextMsg(message)
        else:
            raise Exception("PROTOCOL: Unknown message type")
        nextMsg = message.GetNext(self._crypt)
        if nextMsg is not None:
            self._output.SendMessage(nextMsg)

    def _ProcessAuthMsg(self,message: Message):
        if not message.codec.CHECK_HMAC(self._crypt,message):
            raise Exception("PROTOCOL: AUTH HMAC mismatch")
        if AuthMessage.Command.INIT == message.message_command:
                self._crypt.reset()
        else:
            if not self._crypt.checknonce(message.nonces[0]):
                raise Exception("PROTOCOL: AUTH nonce mismatch")
            delay = True if AuthMessage.Command.HELO == message.message_command else False
            self._crypt.setremote(message.additional_data,delay)
            self._output.YieldLog("PROTOL: Secure channel established")
            self._statechange.Success()

    def _ProcessRkeyMsg(self,message: Message):
        self._crypt.setremote(message.additional_data)

    def _ProcessTextMsg(self,message: Message):
        text = message.additional_data.decode()
        self._output.YieldMessage(text)

    def EncapsulateTextMessage(self, payload: str) -> TextMessage:
        data = payload.encode()
        codec = Message.GetCodec(self._MAGIC,self._VERSION)
        return TextMessage(codec,Message.Type.TEXT,TextMessage.Command.RESV,[],None,data)

    def CommitMessage(self, message: bytes) -> bytes:
        if self._crypt.established is None:
            self._crypt.established = True
        elif self._crypt.established:
            message = self._crypt.encrypt(message)
        return message

    def _CheckRekeyTimer(self):
        pass

    def _ProcessProtocolMessageWithAudit(self,message: bytes):
        try:
            self._ProcessReceivedProtocolMessage(message)
        except Exception as e:
            self._output.YieldLog("PROTOL: Secure channel establishment failed")
            self._output.YieldLog(e)
            self._statechange.Fail()

    def AcceptMessage(self, message: bytes):
        if self._crypt.established:
            try:
                message = self._crypt.decrypt(message)
            except Exception as e:
                self._output.YieldLog("PROTOCOL: failed to decrypt and verify message, probably tampered")
                self._statechange.Reset()
                self._output.YieldLog("PROTOCOL: ATTENTION! SecureConnection TERMINATED")
                self._crypt.reset()
        if not self._IsMessagePartOfProtocol(message):
            self._output.YieldLog("PROTOCOL: unknown message, discarded")
        self._ProcessProtocolMessageWithAudit(message)
        self._CheckRekeyTimer()
