import json
from hashlib import sha256

from eth_account import Account
from web3 import Web3, HTTPProvider

# Connect to Ganache
web3 = Web3(HTTPProvider("http://127.0.0.1:7545"))

# Check connection
if web3.is_connected():
    print("Connected to blockchain")
else:
    print("Failed to connect")

# Load contract ABI and Bytecode
with open('Block_Chain/artifacts/TransactionHandler.json', 'r') as file:
    contract_data = json.load(file)
    abi = contract_data['abi']
    bytecode = contract_data['data']['bytecode']['object']

# Set up the contract
contract = web3.eth.contract(abi=abi, bytecode=bytecode)


def create_account():
    # Create a new account
    new_account = web3.eth.account.create()

    # Print the private key and address of the new account
    print("New Account Private Key:", new_account._private_key.hex())
    print("New Account Address:", new_account.address)

    return new_account._private_key.hex(), new_account.address


def hash_function(data):
    """Hash data using SHA-256."""
    return sha256(data.encode('utf-8')).hexdigest()


def create_transaction(sender_id, receiver_id, message_text, file_hash, timestamp, key, address):
    # Set up account using private key
    key = "0xaf9277e7a5aa35f3f96b3910ea49b4794f98e449410bcc0b46763725f7fd9578"
    address = "0xA1A96CA413a9fb2169e9028dE2be4E5FCA629A83"
    account = Account.from_key(key)
    web3.eth.default_account = account.address

    """Prepare a blockchain transaction."""
    transaction_data = {
        "sender_id": sender_id,
        "receiver_id": receiver_id,
        "message_text": message_text,
        "file_hash": file_hash,
        "timestamp": str(timestamp)
    }
    data_string = json.dumps(transaction_data, sort_keys=True)
    data_hash = hash_function(data_string)

    # Prepare transaction
    transaction = {
        'to': address,  # This must be the receiver's Ethereum address
        'value': web3.to_wei(0, 'ether'),
        'gas': 2000000,
        'gasPrice': web3.to_wei('50', 'gwei'),
        'data': web3.to_hex(text=data_hash),
        'nonce': web3.eth.get_transaction_count(account.address)
    }
    signed_txn = account.sign_transaction(transaction)
    return signed_txn


def commit_transaction(signed_txn):
    """Send a signed transaction to the blockchain and return the transaction ID."""
    tx_hash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
    tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    return tx_receipt.transactionHash.hex()


def fetch_transaction(transaction_id):
    """Fetch a transaction from the blockchain."""
    try:
        transaction = web3.eth.get_transaction(transaction_id)
        return transaction
    except Exception as e:
        print(f"Error fetching transaction: {e}")
        return None
