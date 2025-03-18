#dependencies pip install pycardano
#pip install cryptography


from blockfrost import ApiUrls
from pycardano import *
from dataclasses import dataclass
import os
import sys
from datetime import datetime, timezone # Get the current time in UTC
import requests
import json
import time
import logging
import getpass
import secrets

#encyptSeed
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

#Wallet Balance below this Value Will Cease Mining
WALLET_MIN = 10
MIN_BLOCK_TIME = 600000
NO_LIC_WAIT = 645000
# Suppress all warnings
logging.basicConfig(level=logging.ERROR)
# Specific logger for PyCardano's OgmiosV6ChainContext
ogmios_logger = logging.getLogger("pycardano.backend.ogmios_v6.OgmiosV6ChainContext")
ogmios_logger.setLevel(logging.ERROR)

env = False
net = 'MAINNET'
USE_BF = True

wizardPolicy = '12665eeb470a87eb7d610a8c9b1d9a663c4b7f05e347f51f209fe4e3'
wizard = MultiAsset.from_primitive({bytes.fromhex(wizardPolicy): {b'WIZARD': 1}})
manaPolicy = '3e9764b480ff7fc621fd81a638ec37dce75c29c525fa0e5d6f20ae51'

SPEND_SCRIPT_CBOR =  '5916ff010000323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232223253335734a666666ae900084cdc398220012400029405280a5014a0266600298103d87f800000300213300100300222232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323374a90001bb1498c8c8c8cccccccccccccd401002802403002c02001401c018084048034400c400840040e80e8926122222222222222323232323232323232533357346461360220026610c0260dea016900109919180180088009838a8058a999ab9a32309b0110014a02600204c264c66ae712410152004988c8c8ccccccc004004c1b4c1d140301000f00e801809888888894ccd55cf8030999999804000802802001801000899192999ab9a3230a501100133095013232333079323233307a307230785006100210014bd6f7b630810140000101000024411c12665eeb470a87eb7d610a8c9b1d9a663c4b7f05e347f51f209fe4e30010021001480012210657495a41524400480004c8c8c8c8c94ccd5cd1918550088009984a80983f2802240082646464646600a002006200260f6a0122002610202a00826600201801444666600e00400a00200620029444004c1acc1d140084cccc00401c0180140108888ccccccc030030d5d100580200180100080289aba100622222253335734646142022002a004264a666ae68c8c288044004cc21404c1e1401120d00f1323230030011001483403c4c94ccd5cd1918518088009984d009918518088009984a00983ca802a41a01e26461460220026610c0260f2a00a90504e008991918018008800a41d00e2646460060022002907a019180100091919192999ab9a3230a5011001330900130795002480084c8c8c00c0044004c1e940084c0040e48c8c8c94ccd5cd1918540088009984980983e280aa4004264a666ae68c8c2a4044004cc25005403d2000132533357346461540220026613402610002a01890640089919191919191999800800984000984380a80f80180811112999aab9f0031333005001002001132325333573464616a0220026614a02646466611202646466611402610402611002a00c2004200297adef6c610101400001010000280988010800a4000911044d414e4100480004c8c8c00c0044004cc88cdc0001000a802191919984480991919984500984100984400a80308010800a5eb7bdb18501400001010000280988010800a4000911044d414e410013001004233330060063574400a00200426ae8400c8894ccd5cd1918588088009985100a80128030999804001003000899319ab9c49108747265617375726500498400520001001375a646466a042200420029014184000a806099980081b81b0051111919192999ab9a3230af0110013309f013074501130725011132323003001100133223370000400260e4a02290010991918018008800a400046464666666600200260ea611002a0400a409e0300720704444444a666aae7c0184cccccc02000401401000c0080044c8c94ccd5cd19185c8088009985480991919984680991919984700984300a80308010800a5eb7bdb184101400001010000280b88010800a4000a01890000991919998018048040008030800a51132533357346461740220026615402646466611c02646466611e02610e02a00e2004200297adef6c61010140000101000024411c12665eeb470a87eb7d610a8c9b1d9a663c4b7f05e347f51f209fe4e30010021001480012210657495a41524400480004c94ccd5cd19185d8088009984f80984900a802280a89919192999ab9a3230be011001330a9013092015002480104c8c8c94ccd5cd1918608088009985c009985c009985c009985c009918608088009985600984000a801199119b810020013080015023502013230c1011001330ac013097015002332233700004002612e02a046900109918608088009985880984580a801184580a81189918608088009985600984200a801280989918608088009985600984300a801184300a8118991918018008800a511300100f2330040010021001309501500213300100c00b22333005002001003100130810150041333001009008006222333004003002001133300100800700522233330040030020080012222333333300c00c3574401600800600400200a26ae840188888894ccd5cd19185a808800998560099185a808800a802899185a8088009985280983a280ba41e8062646464a666ae68c8c2e0044004cc28c04c23005400920021533357346461700220026615202664466e04008004c238054008c20805406920809f491533357346461700220026613a02664466e04008004c20805401cc23805400920c0fc15132533357346461720220026615202664466e00008004c20c05406d2090de4e308f015003153335734646172022002a00e26002293099319ab9c32308d011001308f0150034984c0045262300214984c98cd5ce249067652616e6765004984c98cd5ce24810c6d696e426c6f636b54696d650049854ccd5cd19185c008800a501300114984c98cd5ce248109756e626f756e646564004988ccccccccccccccc04005402001c01808c00802812c12802c03c0380340140104004c23004c23004c1b4c2300540904c98cd5ce24810c446174756d732f436f696e73004984004c8ccd408c15007c4004c1bd40384c94ccd5cd1918550088009984a80a8082400426464646466666666600200260e4610a02a03a01609e09800608006c06a444444444a666aae7c0204cccccccc02800401c01801401000c0080044c8c94ccd5cd19185c0088009985400991919984600991919984680984280a80308010800a5eb7bdb1850140000101000024411c12665eeb470a87eb7d610a8c9b1d9a663c4b7f05e347f51f209fe4e30010021001480012210657495a41524400480004c8c8c94ccd5cd19185d8088009984f80984900a802a80a8992999ab9a3230bc011001330a7013090015003480104c8c8c94ccd5cd19185f8088009985b009985b009985b009985b009985b0099185f8088009985500983f2801183f2810899185f8088009985500983ca801184a80a810899185f8088009985500984200a801199119b800020013084015021480084c8c2fc044004cc2a804c254054008c2540540844c8c2fc044004cc2a804c224054008c2240540844c8c2fc044004cc2a804c208054008c2080540084c8c8c00c004400528898008079198020008010800984980a8018998008060059119801801000899800805805111998028010008018800983f28010999800804003802111192999ab9a3230bb011001330a601323233308f013232333090013088015009100210014bd6f7b630901400001010000244100100210014800122100332233700004002904072cd3b999119b82002001308001501d4830236dc044c8c8c8c8c94ccd5cd1918600088009985100a80124411c3456dea754a41765dede982ad40a21dc7a510ba1e6f495b8f6849bbb0013232300300110014a22600201c466600c0080020042002612402a0022002612402612402a00a26660020180120104446666666660200206ae8803c00c01801400800401001c4d5d080411111111192999ab9a3230b5011001330a601307a5017482483054ccd5cd19185a808800a501300114984c98cd5ce249064c69634c696d004984c0045262325333573464616c0220026613202611802a030906400899191919198028018008800a5110014a2264a666ae68c8c2dc044004cc29c04cc88cdc0801000984680a80c9838a80ca406026464600600220029444c0040888cc00800401c894ccd5cd19185b808800a8010a999ab9a3230b7011001330ae013230b7011001500913230b7011001500113333333300e00a009008002001006005004132633573892103642f70004984c98cd5ce2481076c696352617465004984005280a999ab9a3230aa0110014a026666666600200e09609002a07a078064062264c66ae71241067253746174650049888888888ccccccccccccccc02402001c01806001411c11801000c1000f80f4044008004888888888888888cccccccccccccccccc04003c03815c03403002c02802404c02001c01811401401000c0080044c94ccd5cd1918548088009984a00983ea80b240002646464a666ae68c8c2b0044004cc25c0540492000132323232533357346461600220026614e026461600220026613602646eb4d55cf19984f00a801119baf37520046aae740044c98cd5ce249084b65794572726f7200499400d403c4c8c2c0044004cc26c04c8c240044005400520021330050010031326335738921066e546f6b656e004984004c8dd59aab9e33309c01306b308601501e23375e6ea4008d55ce800899319ab9c491084b65794572726f720049940104005221044d414e41001325333573464615a0220026613002a02690010991919192999ab9a3230b1011001330a8013230b10110013309c0132375a6aae78ccc27c0540088cdd79ba900235573a002264c66ae712401084b65794572726f7200499400d200213230b10110013309c013230910110015001480084cc01400400c4c98cd5ce249066e546f6b656e004984004c8dd59aab9e33309d01306c308701501f23375e6ea4008d55ce800899319ab9c491084b65794572726f720049940144004c8ccd40901540804004c1c9403c54ccd5cd191856808800a5013300104d03b132633573892104626164520049888cc00c00800488ccc01400800c0044004c1f9405854ccd5cd191854808800a5013330010490050371326335738920107707572706f736500498888cccccccccccccccccc01002013000c1240480581041000080f80f40e80040e00dc02c0cc0c8888888888888888889261001307c5009100130793079500613263357389210677697a617264004984005280800a5010014a0200260c2a00220fc2446ea0cc88cdc1801000a801280089112999ab9a323084011001330755001480004c94ccd5cd1918428088009983828012400029110100001300114988c8c8c8c8ccc00400400c0188894ccd5cd1918458088009983da800a400026464646466600e00e0060022002664466e0c008005400d20800410013322337140040026460da200266ae80cc88cdc3001000a800a41000897ac0500213300400200122500210014890013264984204044204044204044204044204044c98cd5ce2481104e616d654572726f723a207e626f6f6c004984c98cd5ce2481144e616d654572726f723a2076616c696461746f72004984c98cd5ce24810e4e616d654572726f723a2074786f004984c98cd5ce2481134e616d654572726f723a2074786f446174756d004984c98cd5ce24810e4e616d654572726f723a20747869004984c98cd5ce24810e4e616d654572726f723a20737472004984c98cd5ce2481104e616d654572726f723a207374617465004984c98cd5ce2481194e616d654572726f723a2073746173685f7265717569726564004984c98cd5ce2481104e616d654572726f723a207374617368004984c98cd5ce24811e4e616d654572726f723a2072657175697265645f746f6b656e5f6e616d65004984c98cd5ce2481174e616d654572726f723a207265715f6c69635f6e616d65004984c98cd5ce2481134e616d654572726f723a2072656465656d6572004984c98cd5ce2481124e616d654572726f723a20707572706f7365004984c98cd5ce24810e4e616d654572726f723a20706b68004984c98cd5ce24810f4e616d654572726f723a2070616964004984c98cd5ce2481124e616d654572726f723a206f776e5f706964004984c98cd5ce2481134e616d654572726f723a206e6578745f6c6963004984c98cd5ce2481164e616d654572726f723a206c6f7765725f626f756e64004984c98cd5ce24811b4e616d654572726f723a206c69635f6d696e745f726174655f6f6b004984c98cd5ce2481144e616d654572726f723a206c69635f666f756e64004984c98cd5ce24810e4e616d654572726f723a206c656e004984c98cd5ce2481174e616d654572726f723a20666f756e645f77697a617264004984c98cd5ce2481104e616d654572726f723a20666c6f6f72004984c98cd5ce2481114e616d654572726f723a20646174756d73004984c98cd5ce2481104e616d654572726f723a20646174756d004984c98cd5ce2481134e616d654572726f723a20646174756d4f7574004984c98cd5ce2481124e616d654572726f723a20646174756d496e004984c98cd5ce24810c4e616d654572726f723a2064004984c98cd5ce24810e4e616d654572726f723a20644f6b004984c98cd5ce24810f4e616d654572726f723a2063726564004984c98cd5ce2481174e616d654572726f723a20636f6e74726163745574786f004984c98cd5ce24811a4e616d654572726f723a20636f6e747261637441646472657373004984c98cd5ce2481124e616d654572726f723a20636f6e74657874004984c98cd5ce2481264e616d654572726f723a2062797465735f6269675f66726f6d5f756e7369676e65645f696e74004984c98cd5ce2481104e616d654572726f723a206279746573004984c98cd5ce24810c4e616d654572726f723a2062004984c98cd5ce24810c4e616d654572726f723a2062004984c98cd5ce2481114e616d654572726f723a20616374696f6e004984c98cd5ce24810e4e616d654572726f723a20616363004984c98cd5ce24810c4e616d654572726f723a2061004984c98cd5ce2481134e616d654572726f723a205370656e64696e67004984c98cd5ce24811a4e616d654572726f723a20536f6d654f7574707574446174756d004984c98cd5ce24811b4e616d654572726f723a2053637269707443726564656e7469616c004984c98cd5ce2481114e616d654572726f723a20524557415244004984c98cd5ce2481124e616d654572726f723a204d696e74696e67004984c98cd5ce24811a4e616d654572726f723a2046696e697465504f53495854696d65004980048c00cc10400400c8c010d5d100080211bad3005303d001230043574400200646eacc020c0e80048c01cd5d100091bad30063038001005007007007230083574400246eb4c01cc0c800403c03c8ccc088dd618081817800900089bb14988dd698079817000918071816800918069aba200100c00c00c00c00d012012012012237566026604400246eb4c048c0840048c044d5d100091808180f80091998089bac301f301e001200113762931111bab3235573c666028008466ebc008d55ce800899bb0001374ca0046ea54008888dd6991aab9e33301300423375e0046aae740044cdd80009ba850023752a0044646660220024466e0000920024800140048c8dcc99192999ab9a3370e00690000a4501300015333573466e2000d2000133716902d1800980c80189800801919980918010009119b8b00100248900301f225333573466e24005200014bd60099aba03370066e18005201448180cc008008cdc1800a4028a0024646660200024466e2c0040092201005001010010010011230130012375c6028602600246eb4c04cc0480048c048c0440048c044d5d1000808911199180a912999aab9f00115004133574060066ae84004cc008008d5d1000801001911199180a112999aab9f0011500415333573460066ae840044d5d08008998010011aba20010020032223332301322253335573e004200226660060066ae88008cc010004d5d0801001001800911199918091112999aab9f0021001133004333003003357440040026ae8400800800c00403803dc7b8875e466e05200000171244a666ae680085400452811aab9d375400246aae78dd500091aba100123374a900119aba03750a0026ec52670e46460020020024466e200040088c8005400488cdc4800801119ba548008cd5d028009bb14988cdd2a400066ae80dd4a8009bb14988cdd2a400466ae80dd428009bb14988cdd2a400866ae814004dd8a4c466e9520023357406ea54004dd8a4c1'
import os

def check_occult_file():
    # Get the current working directory
    current_directory = os.getcwd()
    # Define the file path
    file_path = os.path.join(current_directory, "occult.txt") 
    # Check if the file exists
    return os.path.isfile(file_path)

def save_occult(data):
    # Get the current working directory
    current_directory = os.getcwd()
    # Define the file path
    file_path = os.path.join(current_directory, "occult.txt")
    with open(file_path, 'wb') as f:
        f.write(data)
def open_occult():
    # Get the current working directory
    current_directory = os.getcwd()
    # Define the file path
    file_path = os.path.join(current_directory, "occult.txt")
    with open(file_path, 'rb') as f:
        return f.read()
    # Check if the file exists


def wait_with_updates(total_wait_time):
    elapsed_time = 0
    interval = 30  # interval between updates (in seconds)
    
    while elapsed_time < total_wait_time:
        remaining_time = total_wait_time - elapsed_time
        if remaining_time < interval:
            print(f"Time remaining:  seconds...")
            
            time.sleep(remaining_time)
            break
        else:
            print(f"Time remaining: {remaining_time} seconds...")
            time.sleep(interval)
            elapsed_time += interval

import time

def wait_with_updates(total_wait_time):
    spinner = ['|', '/', '-', '\\']  # Characters for the spinner
    elapsed_time = 0
    interval = 2  # Interval between updates (in seconds)
    spinner_index = 0  # To track which spinner character to display
    print(f'Waiting for min Block Time to elapse...{total_wait_time}s⌛')
    
    while elapsed_time < total_wait_time:
        remaining_time = total_wait_time - elapsed_time
        spinner_char = spinner[spinner_index % len(spinner)]     
        # Overwriting the same line with a spinner and remaining time
        print(f"\r{spinner_char} Time remaining: {remaining_time:.1f} seconds... ", end="")
        
        sleep_time = min(interval, remaining_time)
        for _ in range(int(sleep_time)):  # Update spinner every second
            spinner_index += 1
            spinner_char = spinner[spinner_index % len(spinner)]
            print(f"\r{spinner_char} Time remaining: {remaining_time:.1f} seconds... ", end="")
            time.sleep(1)  # Update spinner every second
        
        elapsed_time += sleep_time


# Usage

magic_exists = check_occult_file()


def hamming_distance_128bit(nonce1: int, nonce2: int) -> int:
    """
    Calculate the Hamming distance between two 128-bit nonces represented as integers.

    :param nonce1: The first 128-bit nonce (integer)
    :param nonce2: The second 128-bit nonce (integer)
    :return: The Hamming distance (integer)
    """
    xor_result = bitwise_xor(nonce1, nonce2)  # Manually compute XOR
    distance = 0
    while xor_result:
        distance += xor_result % 2
        xor_result //= 2
    return distance

def find_unique_new_nonce(previous_nonce, min_distance):
    while True:
        nonce_hex = secrets.token_hex(32)
        nonce = int(nonce_hex,16)
        if hamming_distance_128bit(previous_nonce, nonce) >= min_distance:
            return [nonce,bytes.fromhex(nonce_hex)]
def bitwise_xor(a: int, b: int) -> int:
    """
    Perform a bitwise XOR operation on two integers manually.
    :param a: The first integer
    :param b: The second integer
    :return: The result of bitwise XOR operation
    """
    result = 0
    bit_position = 1
    while a > 0 or b > 0:
        bit_a = a % 2
        bit_b = b % 2
        xor_bit = (bit_a + bit_b) % 2
        result += xor_bit * bit_position
        a //= 2
        b //= 2
        bit_position *= 2
    return result

# Encrypt the data
def encrypt_data(data, key):
    iv = os.urandom(16)  # Generate a random initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext
# Decrypt the data
def decrypt_data(encrypted_data, key):
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return decrypted_data

def bytes_big_from_unsigned_int(b: int) -> bytes:
    """Converts an integer into the corresponding bytestring, big/network byteorder, unsigned"""
    assert b >= 0
    if b == 0:
        return b"\x00"
    acc = b""
    while b > 0:
        acc = bytes([b % 256]) + acc
        b //= 256
    return acc

def unsigned_int_from_bytes_big(b: bytes) -> int:
    """Converts a bytestring into the corresponding integer, big/network byteorder, unsigned"""
    acc = 0
    for i in range(len(b)):
        acc = acc * 256 + b[i]
    return acc

@dataclass()
class action(PlutusData):
    # StateRedeemer
    CONSTR_ID = 1
    state: int
    #in_ref: int
    #wiz_out_ref: int
    #lic_out_ref: int 

@dataclass()
class mining_datum(PlutusData):
    CONSTR_ID = 0 
    block_num: int
    block_time: int
    license_count: int
    minting_lic_no: int
    coins_remaining: int
    lic_mint_block: int #the block when a licence was minted
    #nonce: bytes
    
BASE_REWARD = 250

welcome = '''
                  .

                   .
         /^\     .
    /\   "V"
   /__\   I      O  o           
  //..\\  I     .
  \].`[/  I
  /l\/j\  (]    .  O
 /. ~~ ,\/I          .
 \\L__j^\/I       o
  \/--v}  I     o   .
  |    |  I   _________
  |    |  I c(`       ')o
  |    l  I   \.     ,/
_/j  L l\_!  _//^---^\\_ \n'''
print(welcome)
print('''
   __  __    _    _   _    _      __  __ ___ _   _ _____ ____  
  |  \/  |  / \  | \ | |  / \    |  \/  |_ _| \ | | ____|  _ \ 
  | |\/| | / _ \ |  \| | / _ \   | |\/| || ||  \| |  _| | |_) |
  | |  | |/ ___ \| |\  |/ ___ \  | |  | || || |\  | |___|  _ < 
  |_|  |_/_/   \_\_| \_/_/   \_\ |_|  |_|___|_| \_|_____|_| \_\ 
  ''')
time.sleep(4)

if net == 'TESTNET':
    nt = Network.TESTNET
else:
    nt = Network.MAINNET

ref_script = PlutusV2Script(bytes.fromhex(SPEND_SCRIPT_CBOR))
script_hash = plutus_script_hash(ref_script)

#mint_script = PlutusV2Script(bytes.fromhex(MINT_SCRIPT_CBOR))

if env == True:
    from staticVars import *
    hdwallet = HDWallet.from_mnemonic(SEED)
elif not magic_exists:
    print('Enter seed phrase: ')
    seedIn = input()
    hdwallet = HDWallet.from_mnemonic(seedIn)
    print('Encrypt and save seed and BF Key? (Y/N)')
    ss = input()
    if ss == 'Y':
        toilandtrouble = secrets.token_bytes(32)
        with open ('abracadabra.txt', 'wb') as f:
            f.write(toilandtrouble)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(toilandtrouble)
        key = digest.finalize()
        encrypted_data = encrypt_data(seedIn.encode(), key)
        save_occult(encrypted_data)
        print('Encrypted Seed Saved 🔒')      
    print()
    print('Enter blockfrost key:')
    BLOCK_FROST_PROJECT_ID = input()
    if ss == 'Y':
        current_directory = os.getcwd()
        # Define the file path
        file_path = os.path.join(current_directory, "bfrost.txt")
        with open(file_path, 'w') as f:
            f.write(BLOCK_FROST_PROJECT_ID)
    
elif magic_exists:
    print('Found key files!')
    with open ('abracadabra.txt', 'rb') as f:
        password_bytes = f.read()
    # Hash the password bytes to create a 256-bit key for AES encryption
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(password_bytes)
    key = digest.finalize()
    dseed = decrypt_data(open_occult(), key)
    hdwallet = HDWallet.from_mnemonic(dseed.decode())
    
    file_path = os.path.join(os.getcwd(), "bfrost.txt")
    with open(file_path, 'r') as f:
        BLOCK_FROST_PROJECT_ID = f.read()

hdwallet_stake = hdwallet.derive_from_path("m/1852'/1815'/0'/2/0")
stake_public_key = hdwallet_stake.public_key
stake_vk = PaymentVerificationKey.from_primitive(stake_public_key)
hdwallet_spend = hdwallet.derive_from_path("m/1852'/1815'/0'/0/0")
spend_public_key = hdwallet_spend.public_key
payment_vkey = PaymentVerificationKey.from_primitive(spend_public_key)
payment_skey = ExtendedSigningKey.from_hdwallet(hdwallet_spend)
stake_vkey = PaymentVerificationKey.from_primitive(stake_public_key)

print('__--* Initializing Miner! *--__ -->  🌟🪄💰⛏️\n\n')
time.sleep(3)
print(f'Miner Will exit when the configurable wallet minimum {WALLET_MIN} ₳ is reached')

if net == 'TESTNET':
    if USE_BF:
        chain_context = BlockFrostChainContext(project_id=BLOCK_FROST_PROJECT_ID,base_url=ApiUrls.preview.value,)
        print("Using blockfrost for chain context ❄️")
    else:
        print('Using Ogmios for Chain Context 🐲 ')
        chain_context = OgmiosV6ChainContext(OG_IP_TESTNET,network=Network.TESTNET)
    address = Address(payment_vkey.hash(),stake_vkey.hash(),network=Network.TESTNET)
    script_address = Address(script_hash, network=Network.TESTNET)
    print(f'script_address : {script_address}')
else:
    if USE_BF:
        print("Using blockfrost for chain context ❄️")
        chain_context = BlockFrostChainContext(project_id=BLOCK_FROST_PROJECT_ID,base_url=ApiUrls.mainnet.value,)
    else:
        print('Using Ogmios for Chain Context 🐲 ')
        chain_context = OgmiosV6ChainContext(OG_IP_MAINNET,network=Network.MAINNET)
    address = Address(payment_vkey.hash(),stake_vkey.hash(),network=Network.MAINNET)
    script_address = Address(script_hash, network=Network.MAINNET)    

#ref_script_utxos = chain_context.utxos('addr_test1vpk6pe2ga3vtdghv3p8z77f846m4kjgrkprya7extwd6washeqfmw')
ref_script_utxos = chain_context.utxos('addr1v9k6pe2ga3vtdghv3p8z77f846m4kjgrkprya7extwd6wasv3545t')
print(f'💰 Wallet Address:  {address.encode()}')

for utxo in ref_script_utxos:
    if utxo.output.script:
        #print(utxo)
        if ref_script == utxo.output.script:
            ref_script_utxo = utxo #spendingReferenceScript
            print('Found Spending Script ✅')
        #elif mint_script == utxo.output.script:
            #print('Found minting Script ✅')
            #mint_script_utxo = utxo

while True:
    try:
        if USE_BF:
            if net == 'TESTNET':
                chain_context = BlockFrostChainContext(project_id=BLOCK_FROST_PROJECT_ID,base_url=ApiUrls.preview.value,)
            else:
                chain_context = BlockFrostChainContext(project_id=BLOCK_FROST_PROJECT_ID,base_url=ApiUrls.mainnet.value,)
        else:
            if net == 'TESTNET':        
                chain_context = OgmiosV6ChainContext(OG_IP_TESTNET,network=Network.TESTNET)
            else:
                chain_context = OgmiosV6ChainContext(OG_IP_MAINNET,network=Network.MAINNET)
        
        wizardUtxos = chain_context.utxos(script_address)
        
        
        for utxo in wizardUtxos:
            if utxo.output.amount.multi_asset:
                for a in utxo.output.amount.multi_asset:
                    if a.payload.hex() == wizardPolicy:
                        wizardUtxo = utxo
                        print('Found the ' + "🧙‍✨")
                        #print(wizardUtxo)
                        rawCbor = utxo.output.datum.cbor.hex()
                        current_block_datum = mining_datum.from_cbor(rawCbor)

        if current_block_datum.block_num < 1000: #20000
            REWARD = BASE_REWARD * 4
        elif current_block_datum.block_num >= 1000 and current_block_datum.block_num < 10000: #2000 >= and < 100000
	        REWARD = BASE_REWARD * 2
        else:
            REWARD = BASE_REWARD
        
        stash_required = 0    
        if current_block_datum.block_num > 100:
            stash_required = current_block_datum.block_num // 20 # this must match the validators stash on production! --__---__--
            print(f'Stash requirement for mining: {stash_required} MANA 💎')
        
        MANA_OUT = MultiAsset.from_primitive({bytes.fromhex(manaPolicy): {b'MANA': REWARD + stash_required}})
        MANA_MINT = MultiAsset.from_primitive({bytes.fromhex(manaPolicy): {b'MANA': REWARD }})
        print(f'Mining block 🧱 {current_block_datum.block_num + 1}')
        print(f'Licence no. {current_block_datum.minting_lic_no} 📋  required for immedate mining')
        print(f'Previous Block EpochTime: {current_block_datum.block_time}')
        minerUtxos = chain_context.utxos(address)
        licenceNameArray = []
        stash_utxos = []
        stash_count = 0
        col_found = False
        lovelace_balance = 0
        for utxo in minerUtxos:
            lovelace_balance += utxo.output.amount.coin
            #print(utxo.output.amount.multi_asset)
            #print(utxo.output.amount)
            if utxo.output.amount.multi_asset:
                for a in utxo.output.amount.multi_asset:

                    if a.payload.hex() == manaPolicy:
                        tokens = utxo.output.amount.multi_asset[ScriptHash(a.payload)]
                        for name in tokens:
                            amount = tokens[AssetName(name.payload)]
                            if name.payload != b'MANA':
                                print(f'Found licence no. {int.from_bytes(name.payload, byteorder="big")}  📄 ')
                                licenceNameArray.append({'name':name.payload,'utxo': utxo})                            
                            elif name.payload == b'MANA':
                                stash_count += amount
                                if stash_count < stash_required:
                                    stash_utxos.append(utxo)
            else:
                #ada only
                if utxo.output.amount.coin == 5000000 and not col_found:
                    print('Collateral Utxo Found 💼')
                    col_utxo = utxo
                    col_found = True

        
        print(f'MINER rewards in wallet: {stash_count} 💵' )
        print(f'Ada Balance: {round(lovelace_balance/1000000,3)} ₳') 
        if lovelace_balance < WALLET_MIN * 1000000:
            print('Wallet minimum reached - exiting miner...')
            sys.exit()                  
        if stash_count < stash_required:
            print('You dont have enough MANA to mine! 💀')
            time.sleep(30)               
        
        #print(licenceNameArray)
        now = int(datetime.now(timezone.utc).timestamp() * 1000)
        have_licence = False
        for l in licenceNameArray:
            if unsigned_int_from_bytes_big(l['name']) == current_block_datum.minting_lic_no:
                have_licence =  True
        
        if now - current_block_datum.block_time < MIN_BLOCK_TIME:
            #print(f'Waiting for min Block Time to elapse...{(MIN_BLOCK_TIME - (now-current_block_datum.block_time))/1000}s⌛')
            wait_with_updates((MIN_BLOCK_TIME - (now-current_block_datum.block_time))/1000)
            #time.sleep((MIN_BLOCK_TIME - (now-current_block_datum.block_time))/1000)
        now = int(datetime.now(timezone.utc).timestamp() * 1000)    
        if not have_licence:
            print('No licence for current block waiting for open mining time...⏰')

            if now < current_block_datum.block_time + NO_LIC_WAIT:
                print(f'Sleeping 😴 for { -1 * (now - (current_block_datum.block_time + NO_LIC_WAIT)) /1000} seconds' )
                #time.sleep(1)
                time.sleep((NO_LIC_WAIT - (now-current_block_datum.block_time))/1000)
        
        
        #action 0 is mine 1 is mint
        '''    
        in_ref: int
        wiz_out_ref: int
        lic_out_ref: int 
        '''
        spendRedeemer =  Redeemer(action(0))
        mintRedeemer = Redeemer(action(0)) 
        
        if current_block_datum.license_count > current_block_datum.minting_lic_no:
            next_lic = current_block_datum.minting_lic_no + 1
        else:
            next_lic = 0
        
        now = int(datetime.now(timezone.utc).timestamp() * 1000)
        
        ##NONCE =================================================================================
        '''
        old_nonce_int = unsigned_int_from_bytes_big(current_block_datum.nonce)
        #make unique new nonce using hamming difference algorithm in utils needs a difference of 64
        nonces = find_unique_new_nonce(old_nonce_int,64)
        #nonce[0] is nonce as integer nonce[1] is bytes of hexstring nonce
        block_time_bytes = bytes_big_from_unsigned_int(now)
        sha256 = hashlib.sha256()
        sha256.update(block_time_bytes + nonces[1])
        sha256_bytes = sha256.digest()
        '''
        
        #old_nonce_int = unsigned_int_from_bytes_big(current_block_datum.nonce)
        #make unique new nonce using hamming difference algorithm in utils needs a difference of 64
        #nonces = find_unique_new_nonce(old_nonce_int,128)
        #-----New Block Datum Defined =============================-------------=========+++++
        newBlockDatum = mining_datum(current_block_datum.block_num + 1,
                                    now,
                                    current_block_datum.license_count,
                                    next_lic,
                                    current_block_datum.coins_remaining - REWARD,
                                    current_block_datum.lic_mint_block
                                    #nonces[1]
                                    )
        
        #tunaToConvert
        minVal = min_lovelace_post_alonzo(TransactionOutput(address, Value(1000000, MANA_OUT)),chain_context)            
        #Builder
        builder = TransactionBuilder(chain_context)
        if col_found:   
            builder.collaterals.append(col_utxo)
            builder.excluded_inputs.append(col_utxo)
        #builder.add_input_address(address)
        builder.add_output(TransactionOutput(script_address,Value(2500000,wizard), datum=newBlockDatum))#mustbeindex0 out
        
        
        #if stash_required:
        #    for utxo in stash_utxos:
        #        builder.add_input(utxo)
        #        print('AddedManaToInputs')
        if have_licence:
            print('Using Licence to mint immediately 🚀')
            for utxo in licenceNameArray:
                if unsigned_int_from_bytes_big(utxo['name']) == current_block_datum.minting_lic_no:
                    licToUse = MultiAsset.from_primitive({bytes.fromhex(manaPolicy): {utxo['name']: 1}})
                    builder.add_output(TransactionOutput(address,Value(2000000,licToUse))) #mustbeindex1 out
                    lic_utxo = utxo['utxo']
        #builder.add_input_address(address)
        #spendValidator
        ada_only = 0
        lovelace_balance = 0
        for utxo in minerUtxos:
            if col_found:
                if utxo != col_utxo:
                    #print('potential input added')
                    builder.potential_inputs.append(utxo)
                else:
                    print('skipping collateral utxo potential input')
            else:
                print('no collateral utxo adding all inputs as potential inputs')
                builder.potential_inputs.append(utxo)
            if utxo.output.amount.multi_asset:
                pass
            else:
                ada_only += 1
            lovelace_balance += utxo.output.amount.coin
        if ada_only < 4 and lovelace_balance > 25000000:
            print('Low Ada Only utxos - adding utxos for cheaper fees')
            builder.add_output(TransactionOutput(address,Value(4000000)))
            builder.add_output(TransactionOutput(address,Value(4000000)))

        builder.add_minting_script(ref_script_utxo,mintRedeemer)
        builder.mint = MANA_MINT
        builder.add_output(TransactionOutput(address,Value(minVal,MANA_OUT)))

        builder.add_script_input(wizardUtxo, script=ref_script_utxo, redeemer=spendRedeemer)
        builder.fee_buffer = 10000
        signed_tx = builder.build_and_sign([payment_skey], address,auto_validity_start_offset=-3,auto_ttl_offset=180)
        #print(signed_tx.transaction_body.inputs)
        #print(builder.collaterals)    
        chain_context.submit_tx(signed_tx.to_cbor())
        print(f' Tx fee: {signed_tx.transaction_body.fee/1000000}')
        print('Success - block mined '  + " " + str(signed_tx.id) + "⛏️")
        print('Waiting For Tx Confirmation - 🔍')
        sleep_cnt = 0
        while True:
            time.sleep(5)
            txFound = False
            
            #break
            minerUtxos = chain_context.utxos(address)
            for utxo in minerUtxos:
                if utxo.input.transaction_id.payload.hex() == str(signed_tx.id):
                    print('Transaction Onchain! Resuming Mining 🏗️')
                    txFound = True
                    break
            if txFound:
                break
            sleep_cnt += 1
            if sleep_cnt > 9:
                break
                print('Tx took to long to find - aborting search.')
    except Exception as e:
        exception_msg = str(e)
        print(e)
        # you only get traces if you usse ogmios chain context so these error messages only appear for Ogmios Users.. 
        if "'traces': ['minBlockTime']" in exception_msg:
            print('TxFailed: Smart Contract enforced min block Time yet to elapse ❌ ')
        #if "transaction contains unknown UTxO references as inputs" or "missing from UTxO set" in exception_msg:
        #   print('TxFailed: spent UTxO used in tx wait for settlement ❌')
        if "'traces': ['17" in exception_msg:
            print("TxFailed: Smart Contract enforced delay for Non licence holder ❌")
        if "'traces': ['wizard']" in exception_msg:
            print('No Wizard in Tx -- trying to deceive the gods? 💀')
        if "'traces': ['nToken']" in exception_msg:
            print('Minting more tokens than allowed -- 🕵️‍♂️ avarice.')
        if "'traces': ['NameError: dOk']" in exception_msg:
            print('Datums incorrect - mischief afoot? 🦊')
        #print(e)
        time.sleep(5)
        #print(builder.inputs)
        #print(builder.outputs)
        
    #sys.exit()
