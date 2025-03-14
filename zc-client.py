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
                for i in range(len(self.blockchain) - 1, -1, -1):
                    if self.validate_block(self.blockchain[i]):
                        self.utx.append(self.blockchain[i]["tx"])
                        self.blockchain.remove(self.blockchain[i])

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
    
    def sum_io(self, block, prev, from_block=False):
        # get input block number
        # index into that block, get output'
        # check that input is equal to sum of block outputs
        inp_transaction = block["input"]["n"]
        inp_val = prev[inp_transaction]["value"]
        if not isinstance(inp_val, int):
            print("Invalid UTX: input not an integer")
            return False

        cur_outputs = 0
        b = 0
        if  from_block:
            b = 1
        for i in range(len(block["output"]) - b):
            t = block["output"][i]["value"]
            if isinstance(t, int):
                cur_outputs += t
            else:
                print("Invalid UTX: outputs are not integers")
                return False
        print(cur_outputs, inp_val)
        return cur_outputs == inp_val

    def validate_transaction(self, transaction, from_block=False):
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
                        if not self.sum_io(transaction, inp_ref, from_block): # v.
                            print("Invalid transaction: sum of input does not equal sum of outputs")
                            return False
                        

        
        # iv
        """for block in self.blockchain:
            if block["tx"]["input"]["id"] == transaction["input"]["id"] and block["tx"]["input"]["n"] == transaction["input"]["n"]:
                print("Invalid transaction: Attempted double spending")
                return False"""
            
        # vi
        for output in transaction["output"]:
            if output["value"] <= 0:
                print("Invalid transaction: Output value not a positive number")
                return False
            if len(output["pub_key"]) > 96: # this could be wrong, idk if i can just check if its bigger than 96
                print("Invalid transaction: Public key longer than 96 bytes")
                return False
            # viii
            try:
                vk = VerifyingKey.from_string(bytes.fromhex(output["pub_key"]))
            except: 
                print("Invalid transaction: signature is not hex encoded")
                return False
            try:
                vk.verify(bytes.fromhex(transaction["sig"]), 
                             json.dumps(transaction["input"], sort_keys=True).encode("utf8") + json.dumps(transaction["output"], sort_keys=True).encode("utf8"))
            except:
                print("Invalid transaction: signature does not verify")
                return False

        return True
                            
    def validate_block(self, block):
        req_fields = ["type", "id", "nonce", "pow", "prev", "tx"]
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
                    ind = self.blockchain.index(block)
                    if block[f] != self.blockchain[ind-1]["id"]:
                        print(block[f], self.blockchain[ind-1]["id"])
                        print("Invalid block: does not point to previous block on blockchain")
                        return False
                if f == "pow":  # e.
                    computed_pow = hashlib.sha256(json.dumps(block["tx"], sort_keys=True).encode('utf8') + block["prev"].encode('utf-8') + block["nonce"].encode('utf-8')).hexdigest()
                    if computed_pow != block["pow"]: #or int(computed_pow, 16) > self.DIFFICULTY:
                        print("Invalid block: Invalid proof of work")
                        return False
                if f == "tx": # f.
                    return self.validate_transaction(block[f], from_block=True)
                
    def create_utx(self, sk, p_pk, o_pk, input_block, amt):
        #Creating a signature for a UTX
        sig = sk.sign(json.dumps(utx['input'], sort_keys=True).encode('utf8') + json.dumps(utx['output'], sort_keys=True).encode('utf8')).hex()
        output_lst = [{
            'value': amt,
            'pub_key': o_pk
        }]
        if amt < input_block["n"]:
            output_lst.append(
                {
                    'value': (input_block["n"] - amt),
                    'pub_key': p_pk
                }
            )

        utx = {
            'type': self.TRANSACTION,
            'input': input_block,   # format is {'value': value, 'n': n}
            'sig': sig,
            'output': output_lst
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
            y = input("What block number in UTX?\n")    #  testing... change to random?
            tx = client.utx[int(y)]
            client.validate_transaction(tx)
            """if client.validate_transaction(tx):
                client.mine_transaction(tx, client.blockchain[-1]["id"])"""

        input()
        
if __name__ == "__main__":
    main()