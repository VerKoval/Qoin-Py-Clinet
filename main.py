from blockchain import *

user = Wallet(3)
q_coin = BlockChain()


user.make_transaction(q_coin, "rfvefvefv", 3)
#
# user.make_transaction(q_coin, "dhjfb", 50)
#
# q_coin.mine_block()
# user.make_transaction(q_coin, "fonjwc", 4)
# user.make_transaction(q_coin, "fonjwc", 4)
# user.make_transaction(q_coin, "fonjwc", 4)
# user.make_transaction(q_coin, "fonjwc", 4)
#
#
q_coin.mine_block()
# q_coin.print_current_blocks()
# print(user.private_key)
# print(user.public_key)
