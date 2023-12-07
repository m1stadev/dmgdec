import struct
from pathlib import Path
from typing import BinaryIO, Optional, Union

import Crypto.Hash.HMAC
import Crypto.Hash.SHA1
from Crypto.Cipher import AES


class DMG:
    def __init__(
        self,
        *,
        filename: Optional[Union[str, Path]] = None,
        fd: Optional[BinaryIO] = None,
    ) -> None:
        if filename:
            self._fd = open(filename, 'rb')
        elif fd:
            self._fd = fd
        else:
            raise AttributeError('must specify either file object or filename')

        if self._fd.read(0x8) != b'encrcdsa':
            raise ValueError('not a valid encrypted dmg')

        self._fd.seek(0x0)

        header = self._fd.read(0x48)
        (
            self.block_iv_len,
            _,
            _,
            self.key_bits,
            _,
            _,
            _,
            self.block_len,
            self.data_len,
            self.data_offset,
        ) = struct.unpack('>6L16sLQQ', header[0xC:0x48])

    def __del__(self):
        self._fd.close()

    @property
    def nrblocks(self):
        return (self.data_len - 1) // self.block_len + 1

    @property
    def key(self):
        return self._key_data

    @key.setter
    def key(self, data: Union[str, bytes]):
        if isinstance(data, str):
            data = bytes.fromhex(str)

        self._key_data = (data[: self.key_bits // 8], data[self.key_bits // 8 :])

    def read_block(self, block_num: int) -> bytes:
        self._fd.seek(self.data_offset + block_num * self.block_len)
        data = self._fd.read(self.block_len)

        hm = Crypto.Hash.HMAC.new(self.key[1], digestmod=Crypto.Hash.SHA1)
        hm.update(struct.pack('>L', block_num))

        aes = AES.new(
            self.key[0], mode=AES.MODE_CBC, IV=hm.digest()[: self.block_iv_len]
        )

        data = aes.decrypt(data)
        if block_num == self.nrblocks - 1:
            trunk = self.data_len % self.block_len
            return data[:trunk]

        return data
