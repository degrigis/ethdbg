
import cmd
import web3
import argparse
import configparser
import os
import sys 

from evm import *
from utils import *
from ethdbg_exceptions import *

# GLOBALS 
DEFAULT_BLOCK = "last"
DEFAULT_CHAINRPC = "ws://172.17.0.1:8546"

def get_w3_provider(web3_host):
    if web3_host.startswith('http'):
        provider = web3.HTTPProvider(
            web3_host,
        )
    elif web3_host.startswith('ws'):
        provider = web3.WebsocketProvider(
            web3_host,
            websocket_timeout=60 * 5,
            websocket_kwargs={
                'max_size': 1024 * 1024 * 1024,
            },
        )
    else:
        raise Exception("Unknown web3 provider")
    w3 = web3.Web3(provider)
    assert w3.is_connected()
    return w3


def get_evm(w3, block_number, myhook):
    VMClass = get_vm_for_block(block_number, myhook)
    
    db = MyChainDB(AtomicDB(StubMemoryDB(w3)))

    vm = VMClass(
        header            = build_block_header(w3, block_number),
        chain_context     = StubChainContext(),
        chaindb           = db,
        consensus_context = None,
    )

    old_block = w3.eth.get_block(block_number - 1)
    state_root = bytes(old_block['stateRoot'])

    header = vm.get_header()
    header = header.copy(gas_used = 0, state_root=state_root)
    execution_context = vm.create_execution_context(
                header, vm.previous_hashes, vm.chain_context)
    vm._state = vm.get_state_class()(vm.chaindb.db, execution_context, header.state_root)

    return vm, header

def get_txn(pk, chainid, calldata, gas, maxPriorityFeePerGas, maxFeePerGas, nonce, value, to):
    account = Account.from_key(pk)

    txn: web3.types.TxParams = {
        'chainId':              chainid,
        'data':                 bytes.fromhex(calldata),
        'gas':                  gas,
        'maxPriorityFeePerGas': maxPriorityFeePerGas,
        'maxFeePerGas':         maxFeePerGas,
        'nonce':                nonce,
        'value':                value,
        'to':                   to
    }

    return txn

def get_config():
    # Parse file using ConfigParser
    config = configparser.ConfigParser()
    config.read(os.path.expanduser('~/.ethdbg'))
    return config

def get_chainid(chain_name):
    if chain_name == "mainnet":
        return 1
    elif chain_name == "sepolia":
        return 11155111
    else:
        raise Exception("Unknown chain name")

class CallFrame():
    def __init__(self, address, msg_sender, tx_origin, value, calltype, callsite):
        # Initialize attributes with args
        self.address = address

        self.msg_sender = msg_sender
        self.tx_origin = tx_origin
        self.value = value
        self.calltype = calltype
        self.callsite = callsite
        
class EthDbgShell(cmd.Cmd):

    intro = 'Welcome to the ethdbg shell. Type help or ? to list commands.\n'
    prompt = f'{RED_COLOR}ethdbg{RESET_COLOR}➤ '
     
    def __init__(self, ethdbg_conf, w3, chain, chainrpc, block, target, calldata):
        # call the parent class constructor
        super().__init__()
        
        # The config for ethdbg
        self.tty_rows, self.tty_columns = get_terminal_size()
        self.ethdbg_conf = ethdbg_conf
        self.account = Account.from_key(self.ethdbg_conf['user.account']['pk'])
        
        # EVM stuff 
        self.w3 = w3
        
        # Chain context
        self.chain = chain
        self.chainrpc = chainrpc
        self.block = block
        
        # Tx context
        self.target = target
        self.value = 0
        self.calldata = calldata if calldata else ''
        self.gas = 6_000_000 # silly default value 
        self.maxPriorityFeePerGas = 0
        self.maxFeePerGas = 1_000 * (10 ** 9)
        
        # The *CALL trace between contracts
        self.callstack = []
        
        # Recording here the SSTOREs, the dictionary is organized 
        # per account so we can keep track of what storages slots have 
        # been modified for every single contract that the transaction touched
        self.sstores = {}

        # Recording here the SLOADs, the dictionary is organized 
        # per account so we can keep track of what storages slots have 
        # been modified for every single contract that the transaction touched
        self.sloads = {}
        
        # Debugger state
        # ==============
        #  Whether the debugger is running or not
        self.started = False
        #  Breakpoints PCs
        self.breakpoints = set()
        self.mnemonic_bps = set()
        
        #  History of executed opcodes
        self.history = list()
        #  The computation object of py-evm
        self.comp = None
        #  Used for step command
        self.temp_break = False
        #  Weather we want to display the execute ops
        self.log_op = False
    
    def only_when_started(func):
        def wrapper(self, *args, **kwargs):
            if self.started:
                return func(self, *args, **kwargs)
            else:
                print("You need to start the debugger first. Use 'start' command")
        return wrapper

    # COMMANDS 
    def do_chain(self, arg):
        print(f'{self.chain}@{self.block}:{self.chainrpc}')
        
    def do_block(self, arg):
        print(f'{self.block}')

    def do_account(self, arg):
        print(f'{self.account.address}')

    def do_target(self, arg):
        # Check if there is an argument
        # (as of now, once the target is set, you cannot unset it)
        if arg and not self.started:
            self.target = arg
        else:
            print(f'{self.target}')
    
    def do_value(self, arg):
        if arg and not self.started:
            self.value = arg
        else:
            print(f'{self.value}')    

    def do_gas(self, arg):
        if arg and not self.started:
            self.gas = arg
        else:
            print(f'{self.gas} wei')

    def do_maxPriorityFeePerGas(self, arg):
        if arg and not self.started:
            self.maxPriorityFeePerGas = arg
        else:
            print(f'{self.maxPriorityFeePerGas} wei')

    def do_maxFeePerGas(self, arg):
        if arg and not self.started:
            self.maxFeePerGas = arg
        else:
            print(f'{self.maxFeePerGas} wei')

    def do_calldata(self, arg):
        if arg and not self.started:
            self.calldata = arg
        else:
            print(f'{self.calldata}')    
    
    def do_storageat(self, arg):
        if arg:
            print(f'{self.w3.eth.get_storage_at(self.target, arg).hex()}')
        else:
            print("Usage: storageat <slot>")

    def do_breaks(self,arg):
        # Print all the breaks
        for b_idx, b in enumerate(self.breakpoints):
            print(f'Breakpoint {b_idx} at {hex(b)}')

    def do_break(self, arg):
        if arg:
            self.breakpoints.add(int(arg,16))
            print(f'Breakpoint set at {arg}')
    
    def do_mbreak(self, arg):
        if arg:
            self.mnemonic_bps.add(arg.upper())
            print(f'Mnemonic breakpoint set at {arg}')
    
    def do_mbreaks(self, arg):
        # Print all the mbreaks
        for b_idx, b in enumerate(self.mnemonic_bps):
            print(f'Mnemonic breakpoint {b_idx} at {b}')
    
    @only_when_started
    def do_continue(self, arg):
        self._resume()

    do_c = do_continue
    do_cont = do_continue

    @only_when_started         
    def do_step(self, arg):
        if self.started == False:
            print("No execution started. Use 'start' command to start it.")
            return
        else:
            # We set the breakpoint to the next instruction
            self.temp_break = True
            self._resume()
    
    do_s = do_step
  
    def do_clear(self, arg):
        if arg:
            self.breakpoints.remove(int(arg,16))
            print(f'Breakpoint cleared at {arg}')
      
    def do_start(self, arg):
        if self.started:
            return
        if self.target == "0x0":
            print("No target set. Use 'target' command to set it.")
            return
        if self.calldata == '' and self.started == False:
            print("No calldata set. Proceeding with empty calldata.")
        
        vm, header = get_evm(self.w3, self.block, self._myhook)
        
        txn = get_txn(self.ethdbg_conf['user.account']['pk'], 
                      get_chainid(self.chain), 
                      self.calldata, 
                      self.gas, 
                      self.maxPriorityFeePerGas, 
                      self.maxFeePerGas, 
                      self.w3.eth.get_transaction_count(self.ethdbg_conf['user.account']['address']), 
                      self.value, 
                      self.target)
        
        raw_txn = bytes(self.account.sign_transaction(txn).rawTransaction)

        txn = vm.get_transaction_builder().decode(raw_txn)
        
        self.started = True
        
        origin_callframe = CallFrame(self.target, self.account.address, self.account.address, self.value, "-", "-")
        self.callstack.append(origin_callframe)
        
        receipt, comp = vm.apply_transaction(
            header=header,
            transaction=txn,
        )
        
    def do_log_op(self, arg):
        self.log_op = not self.log_op
        print(f'Logging opcodes: {self.log_op}')
    
    def do_quit(self, arg):
        sys.exit()
    
    do_q = do_quit

    @only_when_started
    def do_memory(self, args):
        read_args = args.split(" ")
        if len(read_args) != 2:
            print("Usage: memory <offset> <length>")
            return
        else:
            offset, length = args.split(" ")[0], args.split(" ")[1]
            print(f'{self.comp._memory.read(int(offset,16), int(length,10)).hex()}')

    # INTERNALS  
    def _resume(self):
        raise ExitCmdException()
        
    def _get_callstack(self):
        message = f"{GREEN_COLOR}Callstack {RESET_COLOR}"
        
        fill = HORIZONTAL_LINE
        align = '<'
        width = max(self.tty_columns,0)
        
        title = f'{message:{fill}{align}{width}}'+'\n'
        legend = f'[ Legend: Address | CallType | CallSite | msg.sender ]\n'
        
        calls_view = ''
        for call in self.callstack[::-1]:
            calls_view += call.address + ' | ' + call.calltype + ' | ' + call.callsite + ' | ' + call.msg_sender + '\n'
        
        return title + legend + calls_view
    
    def _get_disass(self):
        message = f"{GREEN_COLOR}Disassembly {RESET_COLOR}"
        
        fill = HORIZONTAL_LINE
        align = '<'
        width = max(self.tty_columns,0)
        
        title = f'{message:{fill}{align}{width}}'+'\n'
        
        # print the last 10 instructions, this can be configurable later
        _history = ''
        rev_history = self.history[::-1] 
        curr_ins = rev_history[0]
        slice_history = rev_history[1:10]
        slice_history = slice_history[::-1]
        for insn in slice_history:
            _history += '  ' + insn + '\n'
        _history += f'→ {RED_COLOR}{self.history[-1]}{RESET_COLOR}' + '\n'
        return title + _history

    def _get_metadata(self):
        message = f"{GREEN_COLOR}Metadata {RESET_COLOR}"
        
        fill = HORIZONTAL_LINE
        align = '<'
        width = max(self.tty_columns,0)
        
        title = f'{message:{fill}{align}{width}}'+'\n'
        
        # Fetching the metadata from the state of the computation
        curr_account_code = '0x' + self.comp.msg.code_address.hex()
        curr_account_storage = '0x' + self.comp.msg.storage_address.hex()
        curr_balance = self.comp.state.get_balance(self.comp.msg.storage_address)
        gas_remaining = self.comp.get_gas_remaining()
        gas_used = self.comp.get_gas_used()
        gas_limit = self.comp.state.gas_limit
        
        _metadata = f'Current Code Account: {curr_account_code} | Current Storage Account: {curr_account_storage}\n'
        _metadata += f'Balance: {curr_balance} wei | Gas Remaining: {gas_remaining} | Gas Used: {gas_used} | Gas Limit: {gas_limit}'
        
        return title + _metadata
    
    def _get_stack(self):
        message = f"{GREEN_COLOR}Stack {RESET_COLOR}"
        
        fill = HORIZONTAL_LINE
        align = '<'
        width = max(self.tty_columns,0)
        
        title = f'{message:{fill}{align}{width}}'+'\n'
        
        _stack = ''
        for entry_slot, entry in enumerate(self.comp._stack.values[::-1][0:10]):
            entry_type = entry[0]
            entry_val = entry[1]
            if entry_type == bytes:
                entry_val = entry_val.hex()
                try:
                    # Automatically decode strings if you can :) 
                    entry_val_str = bytes.fromhex(entry_val).decode('utf-8')
                except UnicodeDecodeError:
                    entry_val_str = ''
                if entry_val_str != '':
                    _stack += f'| {hex(entry_slot)} | 0x{entry_val}  {entry_val_str!r}\n'
                else:
                    _stack += f'| {hex(entry_slot)} | 0x{entry_val}\n'
            else:
                # it's an int
                _stack += f'| {hex(entry_slot)} | {hex(entry_val)}\n'
        
        return title + _stack 
    
    def _get_storage(self):
        message = f"{GREEN_COLOR}Read Storage Slots{RESET_COLOR}"
        
        fill = HORIZONTAL_LINE
        align = '<'
        width = max(self.tty_columns,0)
        
        title = f'{message:{fill}{align}{width}}'+'\n'
        
        # Iterate over sloads for this account
        _sload_log = ''
        ref_account = '0x' + self.comp.msg.storage_address.hex()
        if ref_account in self.sloads:      
            ref_account_sloads = self.sloads[ref_account]
            for slot, val in ref_account_sloads.items():
                _sload_log += f'{slot} -> {hex(val)}\n'
        
        return title + _sload_log
        
    def _display_context(self, cmdloop=True):
        callstack_view = self._get_callstack()
        print(callstack_view)
        disass_view = self._get_disass()
        print(disass_view)
        metadata_view = self._get_metadata()
        print(metadata_view)
        stack_view = self._get_stack()
        print(stack_view)
        storage_view = self._get_storage()
        print(storage_view)
        
        if cmdloop:
            try:
                self.cmdloop(intro='')
            except ExitCmdException:
                pass
        
    def _myhook(self, opcode: Opcode, computation: ComputationAPI):
        # Store a reference to the computation to make it 
        # accessible to the comamnds
        self.comp = computation
        
        _opcode_str = f'{hex(computation.code.program_counter)} {opcode.mnemonic}'
        if self.log_op:
            print(_opcode_str)
            
        self.history.append(_opcode_str)

        # BREAKPOINT MANAGEMENT
        if computation.code.program_counter in self.breakpoints or self.temp_break:
            self.temp_break = False
            self._display_context()
        elif opcode.mnemonic in self.mnemonic_bps:
            self._display_context()  
        elif opcode.mnemonic == "STOP":
            self._display_context()

        if opcode.mnemonic == "SSTORE":
            ref_account = '0x' + computation.msg.storage_address.hex()
            slot_id = 0
            slot_val = 0
            
            import ipdb; ipdb.set_trace()
            
            if ref_account not in self.sstores.keys():
                self.sstores[ref_account] = {}
                self.sstores[ref_account][slot_id] = slot_val
            else:
                self.sstores[ref_account][slot_id] = slot_val
                
        if opcode.mnemonic == "SLOAD":
            ref_account = '0x' + computation.msg.storage_address.hex()
        
            slot_id = computation._stack.values[-1]

            if slot_id[0] == bytes:
                slot_id = '0x' + slot_id[1].hex()
            else:
                slot_id = hex(slot_id[1])
            
            # CHECK THIS
            slot_val = computation.state.get_storage(computation.msg.storage_address, int(slot_id,16))
            
            if ref_account not in self.sloads.keys():
                self.sloads[ref_account] = {}
                self.sloads[ref_account][slot_id] = slot_val
            else:
                self.sloads[ref_account][slot_id] = slot_val

        if opcode.mnemonic in CALL_OPCODES:
            
            if opcode.mnemonic == "CALL":
                contract_target = computation._stack.values[-2]
                
                # FIXME 
                if contract_target[0] == bytes:
                    contract_target = '0x' + contract_target[1].hex()
                else:
                    contract_target = hex(contract_target[1])
                
                value_sent = computation._stack.values[-3]
                if value_sent[0] == bytes:
                    value_sent = value_sent[1].hex()
                else:
                    value_sent = hex(value_sent[1])

                # We gotta parse the callstack according to the *CALL opcode                     
                new_callframe = CallFrame(
                                        contract_target,
                                        '0x' + computation.msg.code_address.hex(),
                                        '0x' + computation.transaction_context.origin.hex(), 
                                        value_sent, 
                                        "CALL", 
                                        hex(computation.code.program_counter)
                                        )   
                self.callstack.append(new_callframe)
            
            else:
                print(f"Plz add support for {opcode.mnemonic}")
            
        if opcode.mnemonic in RETURN_OPCODES:
            if opcode.mnemonic == "REVERT":
                print(f'{YELLOW_COLOR}>>>Execution Reverted at {computation.msg.code_address.hex()}@{hex(computation.code.program_counter)}<<<{RESET_COLOR}')
            self.callstack.pop()

        opcode(computation=computation)
        
       

    
# We require a .ethdbg config file in ~/.ethdbg
# This will pull the account to use for the transaction and related private key
if __name__ == "__main__":
    
    # Check if there is an argument
    # Parse the argument using argparse 
    parser = argparse.ArgumentParser()
    
    # parse optional argument
    parser.add_argument("--txid", help="address of the smart contract we are debugging", default=None)
    parser.add_argument("--chain", help="chain name", default="mainnet")
    parser.add_argument("--chainrpc", help="url to connect to geth (infura or private)", default=DEFAULT_CHAINRPC)
    
    parser.add_argument("--target", help="address of the smart contract we are debugging", default=None)
    parser.add_argument("--block", help="reference block", default=DEFAULT_BLOCK)
    parser.add_argument("--calldata", help="calldata to use for the transaction", default=None)
    
    
    # Declare an argument that is going to have multiple values
    args = parser.parse_args()
            
    ethdbg_conf = get_config()
    
    w3 = get_w3_provider(args.chainrpc)
    
    if args.block == "last":
        block_ref = w3.eth.block_number
    else:
        block_ref = int(args.block)

    target = args.target
    chain = args.chain 
    chainrpc = args.chainrpc
    calldata = args.calldata
    
    # We use txid if we want to replay a transaction with out account.
    # WARNING: the result MAY differ since you are using a different 'from'
    if args.txid:
        if args.target or args.calldata:
            print("You can't specify a txid and a target/calldata/block")
            sys.exit(1) 
        else:
            tx_data = w3.eth.get_transaction(args.txid)
            target = tx_data['to']
            calldata = tx_data['input'][2:]
            block = tx_data['blockNumber']
            
            if int(tx_data['chainId'],16) != get_chainid(chain):
                print("The provided chainid is different from the chainid of the transaction you are trying to debug")
                sys.exit(1)

    ethdbgshell = EthDbgShell(ethdbg_conf, w3, chain, chainrpc, block_ref, target, calldata)
    ethdbgshell.cmdloop()
