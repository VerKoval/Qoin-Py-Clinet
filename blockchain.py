import hashlib
import uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from helperfunctions import *
import json
import requests
from helperStructs import *
import db
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

engine = create_engine("sqlite:///blockchain.db", echo=True)
Session = sessionmaker(bind=engine)
session = Session()


class Block:
    def __init__(self):
        self.transactions = []
        self.hash = ""
        self.prev_block_hash = ""

    def add_transaction(self, transaction):
        self.transactions.append(transaction)

    def get_transaction_count(self):
        return len(self.transactions)


class Transaction:
    def __init__(self, sender_id, sender_pub_key, receiver_pub_key, amount):
        # look up the user in the database and see if he has the funds to do this, if not, ABORT!
        self.sender_id = sender_id
        self.trxn_uuid = uuid.uuid4()
        self.sender_pub_key: Ed25519PublicKey = sender_pub_key
        self.receiver_pub_key = receiver_pub_key
        self.amount = amount
        self.trxn_hash = ""
        self.trnx_signature: bytes = bytes("", "utf-8")

    def generate_transaction_hash(self) -> str:
        transaction_string = f"sndrid{self.sender_id}-trxnid:{self.trxn_uuid}-sndrpk:{self.sender_pub_key}-" \
                             f"rcvrpk{self.sender_pub_key}-amt{self.amount}"
        transaction_string_as_bytes = bytes(transaction_string, 'utf-8')
        return hashlib.sha256(transaction_string_as_bytes).hexdigest()

    def sign_transaction(self):
        pass

    def print(self):
        print(f"""
        Transaction UUID: {self.trxn_uuid},
        Sender Public Key: {self.sender_pub_key[27:-26]},
        Receiver Public Key: {self.receiver_pub_key},
        Transaction Amount: {self.amount},
        Transaction Hash: {self.trxn_hash},
        Transaction Signature: {self.trnx_signature}
""")

    def as_dict_for_json(self):
        return ({
            "sender_id": self.sender_id,
            "trxn_uuid": str(self.trxn_uuid),
            "sender_pub_key": self.sender_pub_key,
            "receiver_pub_key": self.receiver_pub_key,
            "amount": self.amount,
            "trxn_hash": self.trxn_hash,
            "trxn_signature": binary_to_b64(self.trnx_signature)
        })


class BlockChain:
    def __init__(self):
        self.all_blocks = []
        self.pending_transactions = []

    def receive_transaction(self, transaction):
        self.pending_transactions.append(transaction)

    def add_block(self, new_block: Block):
        self.all_blocks.append(new_block)

    def mine_block(self):
        # create geneis block
        # genesis_block = db.Block(hash="GenesisBlock", prev_block_hash='GenesisBlock')
        # session.add(genesis_block)
        # session.commit()
        new_block = Block()

        print(session.query(db.Block).first())

        # get pending transactions from the server
        resp = requests.get("http://127.0.0.1:8000/blocks/transactions/pending/")
        pending_transactions_list = resp.json()
        # (self, sender_id, sender_pub_key, receiver_pub_key, amount)
        # pending_transactions_from_server
        pending_transactions_fs = []
        for transaction_data in pending_transactions_list:
            pending_transaction = Transaction(transaction_data.get("sender_id"), transaction_data.get("sender_pub_key"),
                                              transaction_data.get("receiver_pub_key"), transaction_data.get("amount"))
            pending_transaction.trxn_uuid = transaction_data.get("trxn_uuid")
            pending_transaction.trxn_hash = transaction_data.get("trxn_hash")
            pending_transaction.trnx_signature = transaction_data.get("trxn_signature")
            pending_transactions_fs.append(pending_transaction)

        # testing
        print(len(pending_transactions_fs))
        for tr in pending_transactions_fs:
            tr.print()

        # end testing block

        pending_transactions_copy = self.pending_transactions.copy()
        for pending_transaction in pending_transactions_copy:
            if BlockChain.verify_transaction(pending_transaction):
                new_block.add_transaction(pending_transaction)
                self.pending_transactions.remove(pending_transaction)
            if new_block.get_transaction_count() > 9:
                break
        if new_block.get_transaction_count() > 0:
            all_transactions_hashes_as_str = "".join([trxn.trxn_hash for trxn in new_block.transactions])

            # sending to the server
            new_block_hash = hashlib.sha256((bytes(all_transactions_hashes_as_str, 'utf-8'))).hexdigest()
            new_block.hash = new_block_hash
            payload = {
                "block_hash": "sbfhjbewfhb",
                "prev_block_hash": "sdfjhcwbdfhjk",
                "transactions": [trxn.as_dict_for_json() for trxn in pending_transactions_copy]
            }
            payload = json.dumps(payload)
            headers = {"Content-type": "application/json"}
            print(payload)
            # print(json.dumps(payload))
            # send the info to the server

            resp = requests.post("http://127.0.0.1:8000/blocks/new/", data=payload, headers=headers)
            self.add_block(new_block)

    @staticmethod
    def verify_transaction(transaction: Transaction) -> bool:
        # testing signature verification

        # if transaction.receiver_pub_key == "dhjfb":
        #     transaction.trxn_hash += "hsbkjdnckj"
        # end test

        # add functionality to check that the user has enough funds to make this transaction
        transaction_is_valid: bool = True
        if transaction.amount < 0:
            transaction_is_valid = False
            print("Invalid Transaction Amount!")
        try:
            serialization.load_pem_public_key(transaction.sender_pub_key.encode("utf-8"))\
                .verify(transaction.trnx_signature, bytes(transaction.trxn_hash, "utf-8"))
            print("Signature is valid")
        except:
            print("Transaction signature is invalid!")
            transaction_is_valid = False

        return transaction_is_valid

    def print_current_blocks(self):
        for (block_index, block) in enumerate(self.all_blocks):
            print("------------------------------")
            print(f"Block {block_index+1} hash: {block.hash}\n")
            for (trxn_index, trnx) in enumerate(block.transactions):
                print(f"Transaction {trxn_index+1}", end="")
                trnx.print()
            print("------------------------------")

    def get_and_verify_current_block_chain_state(self):
        all_blocks_list = requests.get("http://127.0.0.1:8000/blocks/all/")
        all_blocks_list = all_blocks_list.json()
        all_blocks= []
        for block_data in all_blocks_list:
            single_block = BlockStruct(block_data.get("id"), block_data.get("hash"), block_data.get("prev_block_hash"))
            single_block.print()
            all_blocks.append(single_block)

    # finish this function


class Wallet:
    def __init__(self, sender_id):
        self.sender_id = sender_id
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        # self.sender_id = sender_id
        # convert private key into string
        pem_private_key = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_key_str = pem_private_key.decode('utf-8')
        self.private_key = private_key_str

        # convert public key into string
        pem_public_key = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_str = pem_public_key.decode('utf-8')
        self.public_key = public_key_str

        # print(f"private key: {self.private_key[28:-27]}")
        # print(f"public key: {self.public_key[27:-26]}")

        self.balance = 1000
        # print(f"private key: {serialization.load_pem_private_key(self.private_key.encode('utf-8'), password=None)}")
        # print(f"public key: {serialization.load_pem_public_key(self.public_key.encode('utf-8'))}")

    def make_transaction(self, blockchain, sender_pub_key, amount):
        transaction = Transaction(self.sender_id, self.public_key, sender_pub_key, amount)
        transaction.trxn_hash = Wallet.generate_transaction_hash(transaction)
        transaction.trnx_signature = self.sign_transaction(transaction)
        print(transaction.as_dict_for_json())
        print(json.dumps(transaction.as_dict_for_json()))

        # Sending the transaction to the server so that is availble to everyone
        headers = {"Content-type": "application/json"}
        payload = json.dumps(transaction.as_dict_for_json())
        requests.post("http://127.0.0.1:8000/blocks/transactions/new/", data=payload, headers=headers)
        print(payload)
        blockchain.receive_transaction(transaction)

    @staticmethod
    def generate_transaction_hash(transaction: Transaction) -> str:
        transaction_string = f"id:{transaction.trxn_uuid}-sndrpk:{transaction.sender_pub_key}-" \
                             f"rcvrpk{transaction.sender_pub_key}-amt{transaction.amount}"
        transaction_string_as_bytes = bytes(transaction_string, 'utf-8')
        return hashlib.sha256(transaction_string_as_bytes).hexdigest()

    def sign_transaction(self, transaction: Transaction) -> bytes:
        transaction_signature = serialization.load_pem_private_key(self.private_key.encode("utf-8"), password=None)\
            .sign(bytes(transaction.trxn_hash, "utf-8"))
        return transaction_signature







