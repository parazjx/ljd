#!/usr/bin/env python3
# -*- coding: UTF-8 -*- 

import struct  
import sys,os,shutil,binascii
from shutil import copyfile
from xxteafile.key import *

class xxteaFile():
    DELTA = 0x9E3779B9
    def __init__(self, file_path, out_file_path):
        file_path = file_path.strip()   #remove the space
        if self.isEncrypt(file_path):
            self.decrypt_file(file_path, out_file_path)
        else:
            parent_path = os.path.dirname(out_file_path)
            if not os.path.exists(parent_path):
                os.makedirs(parent_path)
            copyfile(file_path, out_file_path)

    def _long2str(self, v, w):  
        n = (len(v) - 1) << 2  
        if w:  
            m = v[-1]  
            if (m < n - 3) or (m > n): return ''  
            n = m  
        s = struct.pack('<%iL' % len(v), *v)  
        return s[0:n] if w else s  
    
    def _str2long(self, s, w):  
        n = len(s)  
        m = (4 - (n & 3) & 3) + n  
        s = s.ljust(m, b'\0')  
        v = list(struct.unpack('<%iL' % (m >> 2), s))  
        if w: v.append(n)  
        return v  
    
    def encrypt(self, str, key):  
        if str == '': return str  
        v = self._str2long(str, True)  
        k = self._str2long(bytes(key, encoding='utf-8').ljust(16, b'\0'), False)  
        n = len(v) - 1  
        z = v[n]  
        y = v[0]  
        sum = 0  
        q = 6 + 52 // (n + 1)  
        while q > 0:  
            sum = (sum + self.DELTA) & 0xffffffff  
            e = sum >> 2 & 3  
            for p in range(n):  
                y = v[p + 1]  
                v[p] = (v[p] + ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z))) & 0xffffffff  
                z = v[p]  
            y = v[0]  
            v[n] = (v[n] + ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[n & 3 ^ e] ^ z))) & 0xffffffff  
            z = v[n]  
            q -= 1  
        return self._long2str(v, False)  
    
    def decrypt(self, str, key):  
        if str == '': return str  
        v = self._str2long(str, False)  
        k = self._str2long(bytes(key, encoding='ascii').ljust(16, b'\0'), False)
        # k = [1970563447, 1467512927, 19781, 0]
        n = len(v) - 1  
        z = v[n]  
        y = v[0]  
        q = 6 + 52 // (n + 1)  
        sum = (q * self.DELTA) & 0xffffffff  
        while (sum != 0):  
            e = sum >> 2 & 3  
            for p in range(n, 0, -1):  
                z = v[p - 1]  
                v[p] = (v[p] - ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z))) & 0xffffffff  
                y = v[p]  
            z = v[n]  
            v[0] = (v[0] - ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[0 & 3 ^ e] ^ z))) & 0xffffffff  
            y = v[0]  
            sum = (sum - self.DELTA) & 0xffffffff  
        return self._long2str(v, True)  

    def encrypt_file(self, path):
        #open file
        src_file = open(path, 'rb')
        img_data = src_file.read()
        #do encrypt
        img_data = self.encrypt(img_data, KEY)
        des_file = open(path, 'wb')
        #add pre sign key
        pre_sign = struct.pack("i", SIGN_KEY)
        #rewrite
        des_file.write(pre_sign)
        des_file.write(img_data)
        des_file.close()
        print (path + " encrypt success")

    def decrypt_file(self, path, out_file_path):
        #open file
        src_file = open(path,'rb')
        img_data = src_file.read()
        #do decrypt
        img_data = self.decrypt(img_data[SIGN_LEN:], KEY)
        #rewite
        out_path = os.path.dirname(out_file_path)
        if not os.path.exists(out_path):
            os.makedirs(out_path)
        des_file = open(out_file_path,'wb')
        des_file.write(img_data)
        des_file.close()
        # print (path + " decrypt success")

    def isEncrypt(self, path):
        size = os.path.getsize(path)
        file = open(path, "rb")
        if size < SIGN_LEN:
            print("error: file size is too small")
            sys.exit()
        head = file.read(SIGN_LEN)
        flag = (head == bytes(SIGN, encoding='ascii'))
        file.close()
        return flag

def main():
    file_path = 'F:/lua/files/2020-08-29/src/app/Helper.lua'
    xx = xxteaFile(file_path, 'tttt.lua')

if __name__ == '__main__':
    main()

