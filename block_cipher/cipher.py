#!/usr/bin/python3
from collections import deque
from pprint import pprint
from . import sbox
# import block_cipher.sbox as sbox
import hashlib
import random
import numpy as np
import time
import binascii

class BerezCipher():

    def __init__(self, path=None, message = None, key = None, fromFile = False):
        if (fromFile):
            with open(path, 'rb') as files:
                self.message = files.read()
        else:
            self.message = message
        # print("MSG", self.message)

        h = hashlib.sha256()
        h.update(key.encode('utf-8'))

        self.key = h.digest()
        self.internal_keys = []

    # Substitute block with the given sbox
    def sub_sbox(self, block, box):
        new_block = np.copy(block)
        for i in range(4):
            for j in range(4):
                # cell = int(block[i][j], 16)
                cell = block[i][j]
                new_block[i][j] = sbox.sub(cell, box)
        return new_block

    # Generate internal key used in each round
    def gen_internal_key(self, n_round):
        key_hashed = list(self.key)
        # print (key_hashed, type(key_hashed), len(key_hashed))

        # bagi ganjil-genap, XOR
        odd = np.array(key_hashed[::2])
        even = np.array(key_hashed[1::2])
        # print(type(odd))
        tmp = odd ^ even

        # ubah ke block, tambahin ke internal_keys
        block = np.array([tmp[x:x+4] for x in range(0, len(tmp), 4)])
        self.internal_keys.append(block)
        # print (block)

        # generate other key
        for i in range(n_round - 1):
            new_block = self.sub_sbox(block, sbox.sbox)
            new_block = block ^ new_block
            self.internal_keys.append(new_block)
            block = new_block

        # pprint(self.internal_keys)

    def transpose(self, message = None):
        output = [[message[3-i][j] for i in range(4)] for j in range(4)]
        return np.array(output)

    def transpose_back(self, message = None):
        output = [[message[i][3-j] for i in range(4)] for j in range(4)]
        return np.array(output)

    # shift message based on internal key on that round
    def shift_horizontal(self, message = None, key = None):
        output = []
        for i in range(4):
            item = deque(message[i])
            key_sum = sum(key[i])
            if (i % 2 == 0):
                item.rotate((key_sum % 4) * -1)
            else:
                item.rotate(key_sum % 4)
            output.append(list(item))
        return np.array(output)

    def shift_vertical(self, message = None, key = None):
        output = []
        for i in range(4):
            item = deque([message[j][i] for j in range(4)])
            key_sum = sum(key[i])
            if (i % 2 == 0):
                item.rotate((key_sum % 4) * -1)
            else:
                item.rotate(key_sum % 4)
            output.append(list(item))
        return np.array(output)

    # change a 16-byte msg to a block matrix
    def messageToBlock(self, message = None):
        pos = 0
        out = []
        for i in range(4):
            temp = []
            for j in range(4):
                temp.append(message[pos])
                pos += 1
            out.append(temp)
        # pprint(out)
        return np.array(out)

    # change list of message to list of block
    def messageToBlocks(self, n = 0, message = None):
        position = 0
        blocks = []
        for i in range(n):
            block = message[position:position+16]
            blocks.append(self.messageToBlock(block))
            position += 16
        return blocks

    # get block from bytes of message
    def getBlocks(self):
        # expand to 16 byte each
        temp = bytearray(self.message)
        while len(temp) % 32 != 0:
            temp.append(0)
        sum_blocks = len(temp) // 16
        # print(len(self.message))
        # print(len(temp))
        # print (temp, len(temp))
        blocks = self.messageToBlocks(sum_blocks, temp)
        return blocks

    def blocksToMessage(self, blocks = None):
        self.message = bytearray()
        for block in blocks:
            for row in block:
                for item in row:
                    self.message.append(item)
        return self.message

    # f function
    def f_function(self, block = None, key = None):
        # print(type(block), type(key))
        xor_result = block ^ key
        shift_result = self.shift_horizontal(xor_result, key)
        shift_result2 = self.shift_vertical(block, block)
        a  = shift_result ^ shift_result2

        # TODO: Ubah parameter shift jadi (block, num_shift)
        # shift vertical pake random dengan seed = jumlah message

        # subsitusi s-box
        sbox_result = self.sub_sbox(a, sbox.sbox)
        return sbox_result

    def get_num_round(self):
        random.seed(sum(self.key))
        n_round = random.randint(7,25)
        return n_round

    def feistel_network(self, blocks, n_round):
        block_left = blocks[0]
        block_right = blocks[1]

        #initiate with transpose
        block_left = self.transpose(block_left)
        block_right = self.transpose(block_right)

        # process block

        for i in range(n_round):
            key_internal = self.internal_keys[i]
            # Fungsi f terhadap blok kanan
            f_result = self.f_function(block_right, key_internal)

            # xor
            temp = block_left ^ f_result

            # tukar
            if (i < n_round - 1):
                block_left = block_right
                block_right = temp
            else:
                block_left = temp
                block_right = block_right

        block_left = self.transpose_back(block_left)
        block_right = self.transpose_back(block_right)

        return [block_left, block_right]

    def generate_iv(self):
        iv = [0,0]
        iv[0] = np.array([[random.randint(0,255) for i in range(4)] for i in range(4)])
        iv[1] = np.array([[random.randint(0,255) for i in range(4)] for i in range(4)])

        return iv

    def increment_iv(self, block):
        for idx in range(31,-1,-1):
            i = idx // 16
            j = (idx // 4) % 4
            k = idx % 4
            block[i][j][k] += 1
            if (block[i][j][k] > 255):
                block[i][j][k] = 0
            else:
                break
        return block

    def generate_cipher(self, decrypt=False, mode="ECB"):
        n_round = self.get_num_round()
        # print('round', n_round)
        blocks = self.getBlocks()
        # print("blocklen",len(blocks))
        self.gen_internal_key(n_round)
        # print('intkey', len(self.internal_keys))
        box = sbox.sbox

        if (decrypt and mode in ["CBC", "ECB"]):
            self.internal_keys = self.internal_keys[::-1]
            # print("decrypt")

        out_blocks = []
        # pprint(self.internal_keys)
        prev_block = iv = self.generate_iv()
        for i in range(0, len(blocks), 2):
            if (mode == "ECB"):
                cipher = self.feistel_network(blocks[i:i+2], n_round)
                out_blocks.append(cipher[0])
                out_blocks.append(cipher[1])
            elif (mode == "CBC"):
                curr_blocks = blocks[i:i+2]

                if (not decrypt):
                    curr_blocks[0] = curr_blocks[0] ^ prev_block[0]
                    curr_blocks[1] = curr_blocks[1] ^ prev_block[1]

                cipher = self.feistel_network(curr_blocks, n_round)

                if (decrypt):
                    cipher[0] = cipher[0] ^ prev_block[0]
                    cipher[1] = cipher[1] ^ prev_block[1]
                    prev_block = curr_blocks
                else:
                    prev_block = cipher

                out_blocks.append(cipher[0])
                out_blocks.append(cipher[1])
            elif (mode == "CTR"):
                cipher = self.feistel_network(iv, n_round)
                # print (cipher)
                cipher[0] = cipher[0] ^ blocks[i]
                cipher[1] = cipher[1] ^ blocks[i+1]

                iv = self.increment_iv(iv)

                out_blocks.append(cipher[0])
                out_blocks.append(cipher[1])
            elif (mode == "CFB"):
                curr_blocks = blocks[i:i+2]
                prev_block = self.feistel_network(prev_block,n_round)
                cipher = []
                cipher.append(curr_blocks[0] ^ prev_block[0])
                cipher.append(curr_blocks[1] ^ prev_block[1])
                out_blocks.append(cipher[0])
                out_blocks.append(cipher[1])

                if (decrypt):
                    prev_block = curr_blocks
                else:
                    prev_block = cipher
            elif (mode == "OFB"):
                curr_blocks = blocks[i:i+2]
                prev_block = self.feistel_network(prev_block, n_round)
                out_blocks.append(curr_blocks[0] ^ prev_block[0])
                out_blocks.append(curr_blocks[1] ^ prev_block[1])

        # print(len(out_blocks))
        cipher = self.blocksToMessage(out_blocks)
        return cipher


if __name__ == '__main__':
    MODE = "CBC"
    fancyDES = BerezCipher(path='../README.md',key = "(23232, 1)", fromFile=True)

    b = bytearray(fancyDES.message)

    cipher = fancyDES.generate_cipher(mode=MODE)
    print('Encrypted:')
    print(binascii.hexlify(cipher), len(cipher))

    fancyDES1 = BerezCipher(message=cipher, key = "(23232, 1)", fromFile=False)
    plainteks = fancyDES1.generate_cipher(decrypt=True, mode=MODE)
    print('Decrypted:')
    # print(binascii.hexlify(plainteks), len(plainteks))
    print(plainteks, len(plainteks))
    # write output to file
    # f = open('samples/output/output-'+MODE+'.txt', 'wb')
    # f.write(cipher)
    # f.close()
