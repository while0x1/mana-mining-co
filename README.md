<img src="https://github.com/while0x1/Mana-Mining/blob/main/manaLogo.PNG" width="200" height="200">

# About
MANA is a fair mineable meme token on the Cardano blockchain. There is no premine or insider allocation of MANA - - all tokens must be MINED fairly.  MANA was designed to be resistant to raids by bots. MANA has a fixed supply and the miner requires very little resources, it is not CPU or GPU intensive. A Mining NFT licence can be used to increase mining sucess but is not strictly required to mine.  

# How it works
Anyone can run the miner and mine MANA tokens. 

The contract tracks mana mining licences and assigns each successive block to a licence. If a miner has the licence for that block they receive an exclusive 40 second window with which to mine that block. If the licence holder does not mine the block in 40seconds that block can then be mined by anyone - no licence is required to mine a block after the 40second headstart has elapsed. The contract will increment the licence no. allowed to mint each successive block. After the licence count is reached the next block is open to anyone to mine ie no license assigned to mine. After all the licences have been cycled through the contract begins the cycle again assigning the next block to licence no 0. 

The contract also enforces a miner to hold a small amount of MANA in order to run the miner which increases over time in accordance with block production.

An NFT (WIZARD) is locked at the contract address and contains current state of MANA mining. 

# TLDR
- Fair Mineable Memecoin
- NFTs as mining licenses with each license having a number assigned to it.
- Every license number is eligible for immediate mining every cycle once. 
- Over time an increasing amount of $Mana holdings is required to mine. 

## Example Miner Output
Using blockfrost for chain context ❄️ <br>
script_address : addr_test1wrd2gp3uer0q4hc3ccnakf8w6w2t6cw6y0al0seheekn43cuyjaw2 <br>
💰 Wallet Address:  addr_test1qz... <br>
Found Spending Script ✅ <br>
Found the 🧙‍✨<br>
Stash requirement for mining: 26 MANA 💎 <br>
Mining block 🧱 134 <br>
Licence no. 1 📋  required for immedate mining <br>
Previous Block EpochTime: 1740790411320 <br>
Found licence no. 1  📄 <br>
MINER rewards in wallet: 2295 💵 <br>
mining_datum(block_num=134, block_time=1740799947207, license_count=2, minting_lic_no=2, coins_remaining=78837705, lic_mint_block=37) <br>
Using Licence to mint immediately 🚀 <br>
Success - block mined  295cd23f22aa607f89ea7005b4b462ecff95bb995052b463ad2725ef64e4ec3b⛏️ <br>

# Instructions

You will need a blockrost key to to query the relevant blockchain data for mining. A free key can be obtained here: https://blockfrost.io/

If you have access to an Ogmios instance the miner can be adapted to use OgmiosV6ChainContext to remove dependency on a blockfrost key. 

You will need to install python. https://www.python.org/downloads/

Alternatively you can install python directly through the microsoft app store on windows

The program was developed in python 3.10.12 and has been tested on windows(powershell)/WSL2/Ubuntu with 3.11.1.

Install dependencies using pip package manager - pip install pycardano

If you want to easily encrypt and store your keys for ease of use you will need to install the cryptography library - pip install cryptography

