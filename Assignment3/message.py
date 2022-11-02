#!/usr/bin/env python3

import pdb
from enum import Enum

class Message:
    class Codec:
        def __init__(self,magic: str, version: int):
            self.magic = magic.encode()
            self.ver = version.to_bytes(1,byteorder="big")
        def Encode(self,message)->bytes:
            return self.magic+self.ver+message.encode()
        def Decode(self,data: bytes):
            if len(data)<12:
                raise Exception("Codec: Invalid message")
            if data[:5]!=self.magic:
                raise Exception("Codec: Invalid magic number")
            if data[5:6]!=self.ver:
                raise Exception("Codec: Protocol version mismatch")
            return self._decode(data)
        def HMAC(self,crypt, message) -> bytes:
            return crypt.hmac(self._itemize(message))
        def CHECK_HMAC(self,crypt, message) -> bool:
            items = self._itemize(message)
            signature = message.hmac
            return crypt.checkhmac(items,signature)
        def _decode(self,data: bytes):
            if Message.Type.AUTH.value==data[6]:
                return AuthMessage.decode(self,data)
            if Message.Type.RKEY.value==data[6]:
                return RkeyMessage.decode(self,data)
            if Message.Type.TEXT.value==data[6]:
                return TextMessage.decode(self,data)
            raise Exception("Codec: Unknown message type")
        def _itemize(self,message) -> list:
            return [self.magic,self.ver,
                    message.message_type.toByte(),
                    message.message_command.toByte(),
                    message.additional_data]+message.nonces


    class Type(Enum):
        AUTH = 1
        RKEY = 2
        TEXT = 3

        def toByte(self):
            return self.value.to_bytes(1,byteorder="big")

    def __init__(self,codec,mtype,mcmd,nonces,hmac,data):
        self.codec = codec
        self.message_type = mtype
        self.message_command = mcmd
        self.nonces = nonces
        self.hmac = hmac
        self.additional_data = data

    def encode(self) -> bytes:
        header = self.message_type.toByte()+self.message_command.toByte()
        pointer = 12+len(self.nonces)*4+32
        length = len(self.additional_data)
        header = header + pointer.to_bytes(2,byteorder="big")
        header = header + length.to_bytes(2,byteorder="big")
        for nonce in self.nonces:
            if isinstance(nonce,int):
                nonce = nonce.to_bytes(4,byteorder="big")
            header = header + nonce
        header = header + (self.hmac if self.hmac is not None else b'\x00'*32)
        return header+self.additional_data

    @staticmethod
    def GetCodec(magic: bytes, version: bytes):
        return Message.Codec(magic,version)

class AuthMessage(Message):
    class Command(Enum):
        INIT = 1
        HELO = 2
        CKEY = 3

        def toByte(self):
            return self.value.to_bytes(1,byteorder="big")

    def GetNext(self,crypt):
        if AuthMessage.Command.INIT == self.message_command:
            return self._handle_init(crypt)
        if AuthMessage.Command.HELO == self.message_command:
            return self._handle_helo(crypt)
        if AuthMessage.Command.CKEY == self.message_command:
            return None
        raise Exception("AuthMessage.GetNext: Invalid command")

    def _handle_init(self,crypt):
        crypt.setup(self.additional_data)
        nonce = crypt.nonce()
        dh_y = crypt.pubkey()
        nonces = self.nonces+[nonce]
        message = Message(self.codec,Message.Type.AUTH,AuthMessage.Command.HELO,nonces,None,dh_y)
        message.hmac = self.codec.HMAC(crypt,message)
        return message
    def _handle_helo(self,crypt):
        dh_y = crypt.pubkey()
        nonces = self.nonces[-1:]
        message = Message(self.codec,Message.Type.AUTH,AuthMessage.Command.CKEY,nonces,None,dh_y)
        message.hmac = self.codec.HMAC(crypt,message)
        return message

    @staticmethod
    def decode(codec,data):
        if AuthMessage.Command.INIT.value == data[7]:
            return AuthMessage._decode_init(data,codec)
        if AuthMessage.Command.HELO.value == data[7]:
            return AuthMessage._decode_helo(data,codec)
        if AuthMessage.Command.CKEY.value == data[7]:
            return AuthMessage._decode_ckey(data,codec)

    @staticmethod
    def _decode_init(data,codec):
        pointer = int.from_bytes(data[8:10],byteorder="big")
        length = int.from_bytes(data[10:12],byteorder="big")
        if len(data)<pointer+length:
            raise Exception("Decode AUTH_INIT: invalid packet length")
        nonce = int.from_bytes(data[12:16],byteorder="big")
        hmac = data[16:48]
        prime = data[pointer:pointer+length]
        return AuthMessage(codec,Message.Type.AUTH,AuthMessage.Command.INIT,[nonce],hmac,prime)

    @staticmethod
    def _decode_helo(data,codec):
        pointer = int.from_bytes(data[8:10],byteorder="big")
        length = int.from_bytes(data[10:12],byteorder="big")
        if len(data)<pointer+length:
            raise Exception("Decode AUTH_HELO: invalid packet length")
        nonces = [int.from_bytes(data[12:16],byteorder="big"),
                  int.from_bytes(data[16:20],byteorder="big")]
        hmac = data[20:52]
        dh_y = data[pointer:pointer+length]
        return AuthMessage(codec,Message.Type.AUTH,AuthMessage.Command.HELO,nonces,hmac,dh_y)

    @staticmethod
    def _decode_ckey(data,codec):
        pointer = int.from_bytes(data[8:10],byteorder="big")
        length = int.from_bytes(data[10:12],byteorder="big")
        if len(data)<pointer+length:
            raise Exception("Decode AUTH_CKEY: invalid packet length")
        nonce = data[12:16]
        hmac = data[16:48]
        dh_y = data[pointer:pointer+length]
        return AuthMessage(codec,Message.Type.AUTH,AuthMessage.Command.CKEY,[nonce],hmac,dh_y)

class RkeyMessage(Message):
    class Command(Enum):
        PROPOSE = 1
        CONFIRM = 2

        def toByte(self):
            return self.value.to_bytes(1,byteorder="big")

    def GetNext(self,crypt):
        if RkeyMessage.Command.PROPOSE == self.message_command:
            return self._handle_propose(crypt)
        if RkeyMessage.Command.CONFIRM == self.message_command:
            return None
        raise Exception("RkeyMessage.GetNext: Invalid command")

    def _handle_propose(self,crypt):
        crypt.rekey()
        dh_y = crypt.pubkey()
        message = Message(self.codec,Message.Type.RKEY,
                          RkeyMessage.Command.CONFIRM,[],None,dh_y)
        return message

    @staticmethod
    def decode(codec,data):
        if RkeyMessage.Command.PROPOSE.value == data[7]:
            return RkeyMessage._decode_propose(data,codec)
        if RkeyMessage.Command.CONFIRM.value == data[7]:
            return RkeyMessage._decode_confirm(data,codec)

    @staticmethod
    def _decode_propose(data,codec):
        pointer = int.from_bytes(data[8:10],byteorder="big")
        length = int.from_bytes(data[10:12],byteorder="big")
        if len(data)<pointer+length:
            raise Exception("Decode REKEY_PROPOSE: invalid packet length")
        dh_y = data[pointer:pointer+length]
        return RkeyMessage(codec,Message.Type.RKEY,RkeyMessage.Command.PROPOSE,[],None,dh_y)

    @staticmethod
    def _decode_confirm(data,codec):
        pointer = int.from_bytes(data[8:10],byteorder="big")
        length = int.from_bytes(data[10:12],byteorder="big")
        if len(data)<pointer+length:
            raise Exception("Decode REKEY_CONFIRM: invalid packet length")
        dh_y = data[pointer:pointer+length]
        return RkeyMessage(codec,Message.Type.RKEY,RkeyMessage.Command.CONFIRM,[],None,dh_y)

class TextMessage(Message):
    class Command(Enum):
        RESV = 1

        def toByte(self):
            return self.value.to_bytes(1,byteorder="big")

    def GetNext(self,crypt):
        return None

    @staticmethod
    def decode(codec,data):
        pointer = int.from_bytes(data[8:10],byteorder="big")
        length = int.from_bytes(data[10:12],byteorder="big")
        if len(data)<pointer+length:
            raise Exception("Decode REKEY_PROPOSE: invalid packet length")
        text = data[pointer:pointer+length]
        return TextMessage(codec,Message.Type.TEXT,TextMessage.Command.RESV,[],None,text)
