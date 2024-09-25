from blockchain import *

user = Wallet(3)
q_coin = BlockChain()
# q_coin.get_and_verify_current_block_chain_state()


# user.make_transaction(q_coin, "rfvefvefv", 3)
#
# user.make_transaction(q_coin, "dhjfb", 50)
#
q_coin.mine_block()
# user.make_transaction(q_coin, "fonjwc", 4)
# user.make_transaction(q_coin, "fonjwc", 4)
# user.make_transaction(q_coin, "fonjwc", 4)
# user.make_transaction(q_coin, "fonjwc", 4)
#
#
# q_coin.mine_block()
# q_coin.print_current_blocks()
# print(user.private_key)
# print(user.public_key)

#
# from sqlalchemy import Column, Integer, String, ForeignKey, Enum, create_engine
# from sqlalchemy.orm import declarative_base, relationship, sessionmaker
# from enum import Enum as PyEnum
#
# Base = declarative_base()
#
#
# # Choices equivalent in SQLAlchemy using Enum
# class StatusEnum(PyEnum):
#     pending = "pending"
#     verified = "verified"
#
#
# class Block(Base):
#     __tablename__ = 'block'
#     id = Column(Integer, primary_key=True, autoincrement=True)
#     hash = Column(String(200), nullable=False)
#     prev_block_hash = Column(String(200), nullable=False)
#
#
# class Transaction(Base):
#     __tablename__ = 'transaction'
#     id = Column(Integer, primary_key=True, autoincrement=True)
#     sender_id = Column(Integer, nullable=False)
#     trxn_uuid = Column(String(200), nullable=False)
#     sender_pub_key = Column(String(200), nullable=False)
#     receiver_pub_key = Column(String(200), nullable=False)
#     amount = Column(Integer, nullable=False)
#     trxn_hash = Column(String(200), nullable=False)
#     trxn_signature = Column(String(200), nullable=False)
#     parent_block_id = Column(Integer, ForeignKey('block.id'), nullable=False)
#     status = Column(Enum(StatusEnum), default=StatusEnum.pending)
#
#     parent_block = relationship("Block", back_populates="transactions")
#
#
# Block.transactions = relationship("Transaction", order_by=Transaction.id, back_populates="parent_block")
#
#
# class Wallet(Base):
#     __tablename__ = 'wallet'
#     id = Column(Integer, primary_key=True, autoincrement=True)
#     private_key = Column(String(200), nullable=False)
#     public_key = Column(String(200), nullable=False)
#     balance = Column(Integer, nullable=False)
#
#
# engine = create_engine("sqlite:///blockchain.db")
# Base.metadata.create_all(engine)
