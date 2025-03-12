import sys, time, json, os, hashlib
from ecdsa import VerifyingKey, SigningKey
from p2pnetwork.node import Node
from Crypto.Cipher import AES
from Crypto import Random

SERVER_ADDR = "zachcoin.net"
SERVER_PORT = 9067

class ZachCoinClient (Node):
    
    #ZachCoin Constants
    BLOCK = 0
    TRANSACTION = 1
    BLOCKCHAIN = 2
    UTXPOOL = 3
    COINBASE = 50
    DIFFICULTY = 0x0000007FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

    #Hardcoded gensis block
    blockchain = [
        {
            "type": BLOCK,
            "id": "b4b9b8f78ab3dc70833a19bf7f2a0226885ae2416d41f4f0f798762560b81b60",
            "nonce": "1950b006f9203221515467fe14765720",
            "pow": "00000027e2eb250f341b05ffe24f43adae3b8181739cd976ea263a4ae0ff8eb7",
            "prev": "b4b9b8f78ab3dc70833a19bf7f2a0226885ae2416d41f4f0f798762560b81b60",
            "tx": {
                "type": TRANSACTION,
                "input": {
                    "id": "0000000000000000000000000000000000000000000000000000000000000000",
                    "n": 0
                },
                "sig": "adf494f10d30814fd26c6f0e1b2893d0fb3d037b341210bf23ef9705479c7e90879f794a29960d3ff13b50ecd780c872",
                "output": [
                    {
                        "value": 50,
                        "pub_key": "c26cfef538dd15b6f52593262403de16fa2dc7acb21284d71bf0a28f5792581b4a6be89d2a7ec1d4f7849832fe7b4daa"
                    }
                ]
            }
        }
    ]
    utx = []
  
    def __init__(self, host, port, id=None, callback=None, max_connections=0):
        super(ZachCoinClient, self).__init__(host, port, id, callback, max_connections)

    def outbound_node_connected(self, connected_node):
        print("outbound_node_connected: " + connected_node.id)
        
    def inbound_node_connected(self, connected_node):
        print("inbound_node_connected: " + connected_node.id)

    def inbound_node_disconnected(self, connected_node):
        print("inbound_node_disconnected: " + connected_node.id)

    def outbound_node_disconnected(self, connected_node):
        print("outbound_node_disconnected: " + connected_node.id)

    def node_message(self, connected_node, data):
        #print("node_message from " + connected_node.id + ": " + json.dumps(data,indent=2))
        print("node_message from " + connected_node.id)

        if data != None:
            if 'type' in data:
                if data['type'] == self.TRANSACTION:
                    self.utx.append(data)
                elif data['type'] == self.BLOCKCHAIN:
                    self.blockchain = data['blockchain']
                elif data['type'] == self.UTXPOOL:
                    self.utx = data['utxpool']
                #TODO: Validate blocks
                # call validate block here
                # if (self.validate_block()):
                # add to blockchain

    def node_disconnect_with_outbound_node(self, connected_node):
        print("node wants to disconnect with oher outbound node: " + connected_node.id)
        
    def node_request_to_stop(self):
        print("node is requested to stop!")

    def mine_transaction(self, utx, prev):
        nonce = Random.new().read(AES.block_size).hex()
        while( int( hashlib.sha256(json.dumps(utx, sort_keys=True).encode('utf8') + prev.encode('utf-8') + nonce.encode('utf-8')).hexdigest(), 16) > self.DIFFICULTY):
            nonce = Random.new().read(AES.block_size).hex()
        pow = hashlib.sha256(json.dumps(utx, sort_keys=True).encode('utf8') + prev.encode('utf-8') + nonce.encode('utf-8')).hexdigest()
        
        return pow, nonce
    
    def sum_io(self, block, prev):
        # get input block number
        # index into that block, get output'
        # check that input is equal to sum of block outputs
        inp_transaction = block["input"]["n"]
        inp_val = prev[inp_transaction]["value"]

        cur_outputs = 0
        for i in range(len(block["output"])):
            cur_outputs += block["output"][i]["value"]

        return cur_outputs == inp_val

    def validate_transaction(self, transaction):
        print(transaction)
        req_fields = ["type", "input", "sig", "output"]
        inp_fields = ["id", "n"]
        out_fields = ["value", "pub_key"]
        inp_ref = {}
        for f in req_fields: # i.
            if f not in transaction:
                print("Invalid transaction: missing field", f)
                return False
            else:
                if f == "type": # ii.
                    if transaction["type"] != self.TRANSACTION:
                        print("Invalid transaction: type value is not transaction")
                        return False
                if f == "input":
                    for g in inp_fields:
                        if g == "id":
                            valid = False # iii.
                            for i in range(len(self.blockchain)):
                                t = transaction["input"]
                                b = self.blockchain[i]
                                if t["id"] in b["id"] and len(b["tx"]["output"]) >= t["n"] + 1: # iii.
                                    valid = True
                                    inp_ref = b["tx"]["output"]
                            if not valid:
                                    print("Invalid transaction: points to unverified block")
                                    return False
                        if g not in transaction[f]:
                            print("Invalid transaction: missing field", g)
                            return False
                elif f == "output":
                    for g in out_fields:
                        out = transaction[f]
                        for o in out:
                            if g not in o:
                                print("Invalid transaction: missing field", g)
                                return False
                        if not self.sum_io(transaction, inp_ref): # v.
                            print("Invalid transaction: sum of input does not equal sum of outputs")
                            return False
        return True
                            
    def validate_block(self, block):
        req_fields = ["type", "id", "nonce", "pow", "prev"]
        for f in req_fields: # a.
            if f not in block:
                print("Invalid block: missing field", f)
                return False
            else:
                if f == "type":
                    if block[f] != self.BLOCK: # b.
                        print("Invalid block: type value is not block")
                        return False
                if f == "id": # c.
                    block_id = hashlib.sha256(json.dumps(block['tx'], sort_keys=True).encode('utf8')).hexdigest()
                    if block[f] != block_id:
                        print("Invalid block: incorrect block id")
                        return False
                if f == "prev": # d.
                    if block[f] is not self.blockchain[len(self.blockchain)-1]["id"]: # should be last block on blockchain
                        print("Invalid block: does not point to previous block on blockchain")
                if f == "pow":  # e.
                    computed_pow = int(hashlib.sha256(json.dumps(block["tx"], sort_keys=True).encode('utf8') + block["prev"].encode('utf-8') + block["nonce"].encode('utf-8')).hexdigest(), 16)
                    if computed_pow != block["pow"] or int(computed_pow, 16) > self.DIFFICULTY:
                        print("Invalid block: Invalid proof of work")
                        return False
                if f == "tx": # f.
                    return self.validate_transaction(block[f])
                
    def create_utx(self):
        utx = {
            'type': self.TRANSACTION,
            'input': {
                'id': BLOCK_ID,
                'n': N
            },
            'sig': ECDSA_SIGNATURE,
            'output': [
                {
                    'value': AMOUNT,
                    'pub_key': ECDSA_PUBLIC_KEY
                },
                {
                    'value': AMOUNT,
                    'pub_key': ECDSA_PUBLIC_KEY
                }
            ]
        }
        return utx
        


def main():

    if len(sys.argv) < 3:
        print("Usage: python3", sys.argv[0], "CLIENTNAME PORT")
        quit()

    #Load keys, or create them if they do not yet exist
    keypath = './' + sys.argv[1] + '.key'
    if not os.path.exists(keypath):
        sk = SigningKey.generate()
        vk = sk.verifying_key
        with open(keypath, 'w') as f:
            f.write(sk.to_string().hex())
            f.close()
    else:
        with open(keypath) as f:
            try:
                sk = SigningKey.from_string(bytes.fromhex(f.read()))
                vk = sk.verifying_key
            except Exception as e:
                print("Couldn't read key file", e)

    #Create a client object
    client = ZachCoinClient("127.0.0.1", int(sys.argv[2]), sys.argv[1])
    client.debug = False

    time.sleep(1)

    client.start()

    time.sleep(1)

    #Connect to server 
    client.connect_with_node(SERVER_ADDR, SERVER_PORT)
    print("Starting ZachCoin™ Client:", sys.argv[1])
    time.sleep(2)

    while True:
        os.system('cls' if os.name=='nt' else 'clear')
        slogan = " You can't spell \"It's a Ponzi scheme!\" without \"ZachCoin\" "
        print("=" * (int(len(slogan)/2) - int(len(' ZachCoin™')/2)), 'ZachCoin™', "=" * (int(len(slogan)/2) - int(len('ZachCoin™ ')/2)))
        print(slogan)
        print("=" * len(slogan),'\n')
        x = input("\t0: Print keys\n"
                  "\t1: Print blockchain\n"
                  "\t2: Print UTX pool\n"
                  "\t3: Create UTX\n"
                  "\t4: Mine a block\n\n"
                  "Enter your choice -> ")
        try:
            x = int(x)
        except:
            print("Error: Invalid menu option.")
            input()
            continue
        if x == 0:
            print("sk: ", sk.to_string().hex())
            print("vk: ", vk.to_string().hex())
        elif x == 1:
            print(json.dumps(client.blockchain, indent=1))
        elif x == 2:
            print(json.dumps(client.utx, indent=1))

        # TODO: Add options for creating and mining transactions
        # as well as any other additional features
        elif x == 3:
            pass
        elif x == 4:
            tx = client.utx[1]
            #print(block)

            client.validate_transaction(tx)
            #client.mine_transaction()
        

        input()
        
if __name__ == "__main__":
    main()