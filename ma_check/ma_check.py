#! /usr/bin/python3.7
# coding = utf-8

import mnemonic
from bip32utils import BIP32Key
from bip32utils import BIP32_HARDEN
import blocksmith

'''
This is a package for ETH wallet address generating from a BIP39 english mnemonic.
Enjoy it! Created by AlexHsu. Thank creators for mnemonic/bip32utils/blocksmith python pkg. 
'''

#get private key from word
def to_private_key(word):
	'''
	get private key from word!
	'''
	#generate seed from mnemonic word by mnemonic package
	m=mnemonic.Mnemonic("english")
	#xprv=m.to_hd_master_key(m.to_seed(words)) ;the same with BIP32Key.fromEntropy(seed)
	seed = m.to_seed(word)
	#generate extended private key(xprv) from seed 
	key = BIP32Key.fromEntropy(seed)
	xprv = BIP32Key.fromEntropy(seed).ExtendedKey()
	# redefined key with extended private key 
	key = BIP32Key.fromExtendedKey(xprv)
	#get the first account private for derivation path m/44'/60'/0'
	x=key.ChildKey(44 + BIP32_HARDEN) \
	     .ChildKey(60 + BIP32_HARDEN) \
	     .ChildKey(0 + BIP32_HARDEN) \
	     .ChildKey(0) \
	     .ChildKey(0) \
	     .PrivateKey().hex()
	return x

#generate eth address from private key with blocksmith
def prv_to_addr(x):
	address= \
	blocksmith.EthereumWallet.checksum_address(    \
	blocksmith.EthereumWallet.generate_address(x))
	return address
def ma_check(word,address):
        if prv_to_addr(to_private_key(word)) == address:
            print(word+"\nmatches\n"+address+"\n")
            return True
        else:
            return False

if __name__ == "__main__":
        '''
        usage: python3 this.py mnemonic_word address for checking one time!
               python3 this.py mnemonic_word for get address from mnemonic one time!
        '''
        import sys
        if len(sys.argv) == 3:
            test_word = sys.argv[1]
            test_address = sys.argv[2]
        elif len(sys.argv) == 2:
            test_word = sys.argv[1]
            print("The address for :\n\'"+test_word+"\'\nis:\n"+prv_to_addr(to_private_key(test_word)))
            sys.exit(0)
        else:
            test_word = "during couple bone cricket vote beyond thrive real issue pony bottom print"
            test_address = '0x2E1E86f2425a5b3a0b3f1AF50c8d0eDc9Fd610e7'
        if ma_check(test_word,test_address):
            print("That is :\nThe mnemonic:\n\'"+test_word+"\'\nmatch the wallet address: \n"+test_address+"\nTest OK!Good Job!!!")
	
