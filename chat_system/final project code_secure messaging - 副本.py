from operator import xor
import random
from RSA import HandleRSA as rsa


class Scmsg:
    def __init__(self):
        self.encrypt_ip=[58,50,42,34,26,18,10,2,
        60,52,44,36,28,20,12,4,
        62,54,46,38,30,22,14,6,
        64,56,48,40,32,24,16,8,
        57,49,41,33,25,17,9,1,59,
        51,43,35,27,19,11,3,61,53,
        45,37,29,21,13,5,63,55,47,39,31,23,15,7]
        self.key=''
        self.L0=[]       

    #generate a key
    def generate_key(self):
        for i in range(8):
            self.key+=str(random.randint(0,1))
        return self.key

    #change the position of the number according to the table    
    def substitute(self,orig_text,table):
        result=''
        for i in table:
            result+=orig_text[i-1]
        return result

    #turn the message into binary numbers
    def msg2bin(self,msg):
        binary_converted = ''.join('{:08b}'.format(ord(c), 'b') for c in msg)
        if len(binary_converted)%64!=0:
            binary_converted+='0'*(64-len(binary_converted)%64)
        return binary_converted

    def bin2msg(self,bin):
        msg = ""
        for i in range(0,len(bin),8):
            msg += chr(int(bin[i:i+8],2))
        return msg

    #change the IP
    def IP_change(self,msg):
        bin_result=[]
        binary_converted = self.msg2bin(msg)
        for i in range(0,len(binary_converted),64):
            change_ip_binary=self.substitute(binary_converted[i:i+64],self.encrypt_ip)
            bin_result.append(change_ip_binary)
        return bin_result

    def IP_change_back(self, change_ip_binary):
        d={}
        binary_converted=''
        for i in range(len(self.encrypt_ip)):
            d[self.encrypt_ip[i]]=change_ip_binary[i]
        for i in range(1,65):
            binary_converted+=d[i]
        msg=self.bin2msg(binary_converted)
        return msg

    #the xor function
    def xorfunction(self,xor1,xor2):
        size = len(xor1)
        result = ""
        for i in range(0, size):
            result += '0' if xor1[i] == xor2[i%len(xor2)] else '1'
        return result

    #encrypt function
    def encrypt_msg(self,msg):
        self.generate_key()
        en_msg_total=''
        rsa().create_rsa_key()
        e_msg=rsa().encrypt(msg)
        bin_result=self.IP_change(e_msg)
        for en_msg in bin_result:
            self.L0.append(en_msg[0:32])
            N0=en_msg[32:]
            en_N0=self.xorfunction(N0,self.key)
            en_msg_total+=self.xorfunction(en_N0,en_msg[0:32])
        return en_msg_total

    #decrypt function
    def decrypt_msg(self,en_msg_total):
        msg=''
        for i in range(0,len(en_msg_total),32):
            en_msg=en_msg_total[i:i+32]
            en_N0=self.xorfunction(en_msg,self.L0[i//32])
            N0=self.xorfunction(en_N0,self.key)
            change_ip_binary=self.L0[i//32]+N0
            msg+=self.IP_change_back(change_ip_binary)
        d_msg=rsa().decrypt(msg)
        return d_msg
        
#test
if __name__=="__main__":
    test=Scmsg()
    en_msg=test.encrypt_msg('aahhhhhh hhhhhh \nhhhh')
    print(en_msg)
    print(test.decrypt_msg(en_msg))



    

    
        


