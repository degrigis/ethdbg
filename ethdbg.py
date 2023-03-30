
import cmd
from hexbytes import HexBytes
import web3
import argparse
import configparser
import os
import re
import sys
import sha3
from pyevmasm_fixed import disassemble, disassemble_all, disassemble_hex, disassemble_one, Instruction

from evm import *
from utils import *
from ethdbg_exceptions import *

DEFAULT_NODE_URL = "ws://172.17.0.1:8546"

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
    VMClass = get_vm_for_block(w3.eth.chain_id, block_number, myhook)

    db = MyChainDB(AtomicDB(StubMemoryDB(w3)))

    vm = VMClass(
        header            = build_block_header(w3, block_number),
        chain_context     = StubChainContext(),
        chaindb           = db,
        consensus_context = None,
    )

    old_block = w3.eth.get_block(block_number-1)
    state_root = bytes(old_block['stateRoot'])
    header = vm.get_header()
    header = header.copy(gas_used = 0, state_root=state_root)
    execution_context = vm.create_execution_context(
                header, vm.previous_hashes, vm.chain_context)
    vm._state = vm.get_state_class()(vm.chaindb.db, execution_context, header.state_root)

    return vm, header

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
        raise Exception(f"Unknown chain name {chain_name}")

def get_chain_name(id):
    if id == 1:
        return "mainnet"
    elif id == 11155111:
        return "sepolia"
    else:
        raise Exception("Unknown chain id")

class CallFrame():
    def __init__(self, address, msg_sender, tx_origin, value, calltype, callsite):
        # Initialize attributes with args
        self.address = address

        self.msg_sender = msg_sender
        self.tx_origin = tx_origin
        self.value = value
        self.calltype = calltype
        self.callsite = callsite

ALLOWED_COND_BPS = ['addr', 'saddr', 'op', 'pc']
BPS_RE_PATTERN = r"(.*)(==|=|!=|>|<|<=|>=)(.*)"
ETH_ADDRESS = r'^(0x)?[0-9a-fA-F]{40}$'


class Breakpoint():
    def __init__(self, break_args):
        
        # Processing of the breakpoint conditions
        self.conditions = list()
        
        self.pc = None
        self.op = None
        self.simple_bp = False
        
        # Is this a simple breakpoint?
        # This is the case if len(break_args) == 1 and none of the ALLOWED_COND_BPS is in break_args[0]
        if len(break_args) == 1 and not any(cond_keyword in break_args[0] for cond_keyword in ALLOWED_COND_BPS):
            self.simple_bp = True
            # Is it a valid opcode
            if break_args[0].upper() in ALL_EVM_OPCODES:
                self.op = break_args[0].upper()
            else:
                # Is it a valid pc?
                try:
                    self.pc = int(break_args[0],16)
                except Exception:
                    raise InvalidBreakpointException()
        else:
            for break_arg in break_args:
                matches = re.findall(BPS_RE_PATTERN, break_arg)[0]
                if len(matches) != 3:
                    print(f"Invalid breakpoint condition {break_arg}. Skipping.")
                    continue
                else:
                    what  = matches[0]
                    when  = matches[1]
                    value = matches[2]
                    # Validation of the breakpoints parameters here
                    if self._validate_bp(what, when, value):
                        self.conditions.append((what, when, value))
                    else:
                        raise InvalidBreakpointException()
    
    def __str__(self):
        _bp_str = ''
        
        if self.simple_bp:
            _bp_str += "Simple Breakpoint at "
            if self.op:
                _bp_str += f'{self.op}'
            elif self.pc:
                _bp_str += f'{hex(self.pc)}'
        else:
            _bp_str += "Conditional Breakpoint if "
            for condition in self.conditions:
                what = condition[0]
                when  = condition[1]
                value = condition[2]
                _bp_str += f'{what} {when} {value} '
        
        return _bp_str
                    
    def _validate_bp(self,what, when, value):
        if what not in ALLOWED_COND_BPS:
            return False

        # Now we want to check the type of the value given a 'what'
        if what == 'pc':
            try:
                int(value,16)
            except Exception:
                return False
            return True
        elif what == 'op':
            if value.upper() in ALL_EVM_OPCODES:
                return True
            else:
                return False
        elif what == 'addr' or what == 'saddr':
            if re.match(ETH_ADDRESS, value):
                return True
            else:
                return False
        elif 'storage' in what:
            storage_index = what.split('[')[1].split(']')[0]
            try:
                # Storage index must be a hex number
                int(storage_index,16)
            except Exception:
                return False
        else:
            return False    
                   
    def eval_bp(self, comp, opcode):
                
        if self.simple_bp:
            if self.op:
                return opcode.mnemonic == self.op
            elif self.pc:
                return self.pc == comp.code.program_counter
            else:
                return False
        else:
            for condition in self.conditions:
                what = condition[0]
                when  = condition[1]
                value = condition[2]
                
                if when == '=':
                    when = '==' # because I'm a nice guy           
                
                if what == 'pc':
                    pc_val = int(value,16)

                    expr = f'{pc_val} {when} {comp.code.program_counter}'
                    if not eval(expr):
                        return False
                    
                elif what == 'op':
                    value = value.upper()
                    expr = f'"{value}" {when} "{opcode.mnemonic}"'
                    if not eval(expr):
                        return False
                
                elif what == 'addr':
                    # Warning: this is not checksummed
                    curr_code_addr = '0x' + comp.msg.code_address.hex()
                    value = value.lower()
                    expr = f'{value} {when} {curr_code_addr}'
                    if not eval(expr):
                        return False
                    
                elif what == 'saddr':
                    # Warning: this is not checksummed
                    curr_storage_addr = '0x' + comp.msg.storage_address.hex()
                    value = value.lower()
                    expr = f'{value} {when} {curr_storage_addr}'
                    if not eval(expr):
                        return False
                else:
                    return False
            
            # It's a hit of a conditional bp! 
            return True

class TransactionDebugTarget:
    def __init__(self, w3) -> None:
        self.w3: web3.Web3 = w3

        self._defaults = {}

        self._target_address = None
        self._chain_name = None
        self._chain_id = None
        self._fork_name = None
        self._calldata = None
        self._block_number = None
        self._txid = None
        self._source_address = None
        self._source_private_key = None
        self._gas = None
        self._value = None
        self._sender = None
        self._origin = None
        self._gas_price = None
        self._max_fee_per_gas = None
        self._max_priority_fee_per_gas = None
        self._nonce = None

    def set_default(self, key, value):
        self._defaults[key] = value

    def set_defaults(self, **defaults):
        self._defaults.update(**defaults)

    def clear_defaults(self):
        self._defaults = {}

    @property
    def nonce(self):
        return self._nonce if self._nonce is not None else self._defaults.get('nonce', None)

    @nonce.setter
    def nonce(self, nonce):
        if nonce is not None:
            self._nonce = nonce

    @property
    def source_address(self):
        return self._source_address if self._source_address is not None else self._defaults.get('source_address', None)

    @source_address.setter
    def source_address(self, address):
        if address is not None:
            self._source_address = self.w3.to_checksum_address(address)

    @property
    def from_pk(self):
        return self._source_private_key if self._source_private_key is not None else self._defaults.get('from_pk', None)

    @from_pk.setter
    def from_pk(self, pk):
        if pk is not None:
            self._source_private_key = HexBytes(pk).hex()

    @property
    def target_address(self):
        return self._target_address if self._target_address is not None else self._defaults.get('target_address', None)

    @target_address.setter
    def target_address(self, address):
        if address is not None:
            self._target_address = self.w3.to_checksum_address(address)

    @property
    def calldata(self):
        return self._calldata if self._calldata is not None else self._defaults.get('calldata', None)

    @calldata.setter
    def calldata(self, calldata):
        if calldata is not None:
            self._calldata = HexBytes(calldata).hex()

    @property
    def chain(self):
        return self._chain_name

    @chain.setter
    def chain(self, chain=None):
        if chain is None:
            return

        self._chain_id = None
        self._chain_name = None

        if type(chain) is int:
            self.chain_id = chain
        elif type(chain) is str:
            self.chain_name = chain
        else:
            raise ValueError(f"Unknown chain type: {type(chain)} = {repr(chain)}")

    @property
    def chain_id(self):
        return self._chain_id

    @property
    def chain_name(self):
        return self._chain_name

    @chain_id.setter
    def chain_id(self, id):
        assert type(id) is int
        assert (self._chain_name is None) or (self._chain_name == get_chain_name(id))

        self._chain_id = id
        self._chain_name = get_chain_name(id)

    @chain_name.setter
    def chain_name(self, chain):
        assert type(chain) is str
        assert (self._chain_id is None) or (self._chain_id == get_chainid(chain))
        self._chain_name = chain
        self._chain_id = get_chainid(chain)

    @property
    def fork(self):
        return self._fork_name if self._fork_name is not None else self._defaults.get('fork', None)

    @fork.setter
    def fork(self, fork):
        assert self._fork_name is None or self._fork_name == fork
        if fork is not None:
            self._fork = fork

    @property
    def block_number(self):
        return self._block_number if self._block_number is not None else self._defaults.get('block_number', None)

    @block_number.setter
    def block_number(self, block_number):
        if block_number is not None:
            self._block_number = block_number
        return self

    @property
    def transaction_hash(self):
        return self._txid if self._txid is not None else self._defaults.get('transaction_hash', None)

    @transaction_hash.setter
    def transaction_hash(self, txid=None):
        assert self._txid is None or self._txid == txid
        if txid is not None:
            self._txid = txid

    @property
    def gas(self):
        return self._gas if self._gas is not None else self._defaults.get('gas', None)

    @gas.setter
    def gas(self, gas=None):
        assert self._gas is None or self._gas == gas
        if gas is not None:
            self._gas = gas

    @property
    def value(self):
        return self._value if self._value is not None else self._defaults.get('value', None)

    @value.setter
    def value(self, value=None):
        if value is not None:
            self._value = value

    @property
    def sender(self):
        return self._sender if self._sender is not None else self._defaults.get('sender', None)

    @sender.setter
    def sender(self, sender=None):
        if sender is not None:
            self._sender = self.w3.to_checksum_address(sender)

    @property
    def origin(self):
        return self._origin if self._origin is not None else self._defaults.get('origin', None)

    @origin.setter
    def origin(self, origin=None):
        if origin is not None:
            self._origin = self.w3.to_checksum_address(origin)

    @property
    def gas_price(self):
        return self._gas_price if self._gas_price is not None else self._defaults.get('gas_price', None)

    @gas_price.setter
    def gas_price(self, gas_price=None):
        if gas_price is not None:
            self._gas_price = gas_price

    @property
    def max_fee_per_gas(self):
        return self._max_fee_per_gas if self._max_fee_per_gas is not None else self._defaults.get('max_fee_per_gas', None)

    @max_fee_per_gas.setter
    def max_fee_per_gas(self, max_fee_per_gas=None):
        if max_fee_per_gas is not None:
            self._max_fee_per_gas = max_fee_per_gas

    @property
    def max_priority_fee_per_gas(self):
        if self._max_priority_fee_per_gas is not None:
            return self._max_priority_fee_per_gas
        else:
            return self._defaults.get('max_priority_fee_per_gas', None)

    @max_priority_fee_per_gas.setter
    def max_priority_fee_per_gas(self, max_priority_fee_per_gas=None):
        if max_priority_fee_per_gas is not None:
            self._max_priority_fee_per_gas = max_priority_fee_per_gas

    def replay_transaction(self, txid, **kwargs) -> 'TransactionDebugTarget':
        assert txid is not None
        txid = HexBytes(txid).hex()

        tx_data = self.w3.eth.get_transaction(txid)
        self.transaction_hash = txid

        self.defaults = {
            'block_number': self.w3.eth.block_number,
            'chain_id': self.w3.eth.chain_id,
        }

        # TODO pull default account and private key from ethpwn
        self.target_address = kwargs.pop('to', None) or tx_data.get('to', None)
        self.source_address = kwargs.pop('from', None) or tx_data.get('from', None)
        self.calldata = kwargs.pop('calldata', None) or kwargs.pop('input', None) or tx_data.get('input', None)

        for k, v in tx_data.items():
            k_snake = to_snake_case(k)
            value = kwargs.pop(k_snake, None) or kwargs.pop(k, None) or v
            try:
                setattr(self, k_snake, value)
            except AttributeError:
                pass

        for k, v in kwargs.items():
            if v is not None:
                setattr(self, k, v)

        return self

    def new_transaction(self, to, calldata, **kwargs):
        self.target_address = to
        self.calldata = calldata

        # TODO pull default account and private key from ethpwn
        self.source_address = kwargs.pop('from', None)
        self.block_number = kwargs.pop('block_number', self.w3.eth.block_number)
        self.chain = kwargs.pop('chain', hex(self.w3.eth.chain_id))
        self.fork = kwargs.pop('fork', self.w3.eth.fork)

        for k, v in kwargs.items():
            if v is None:
                continue
            try:
                setattr(self, k, v)
            except AttributeError:
                pass

        return self


    def get_transaction_dict(self, **defaults):
        assert self.chain_id is not None
        assert self.source_address is not None
        assert self.nonce is not None

        txn: web3.types.TxParams = {
            'chainId':              self.chain_id,
            'data':                 HexBytes(self.calldata),
            'gas':                  self.gas,
            'gasPrice':             self.gas_price,
            'nonce':                self.nonce,
            'value':                self.value,
            'to':                   self.target_address
        }

        return txn


class EthDbgShell(cmd.Cmd):

    intro = '\nType help or ? to list commands.\n'
    prompt = f'{RED_COLOR}ethdbg{RESET_COLOR}➤ '

    def __init__(self, ethdbg_conf, w3, debug_target):
        # call the parent class constructor
        super().__init__()

        # The config for ethdbg
        self.tty_rows, self.tty_columns = get_terminal_size()
        self.ethdbg_conf = ethdbg_conf
        self.account = Account.from_key(self.ethdbg_conf['user.account']['pk'])

        # EVM stuff
        self.w3 = w3

        self.debug_target: TransactionDebugTarget = debug_target
        self.debug_target.set_defaults(
            gas=6_000_000, # silly default value
            gas_price=(10 ** 9) * 1000,
            value=0,
            calldata='',
            to='0x0',
            origin=self.account.address,
            sender=self.account.address,
        )

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
        self.breakpoints = list()

        # Used for finish command
        self.temp_break_finish = False
        self.finish_curr_stack_depth = None

        #  History of executed opcodes
        self.history = list()
        #  The computation object of py-evm
        self.comp = None
        #  Used for step command
        self.temp_break = False
        #  Whether we want to display the execute ops
        self.log_op = False

    def only_when_started(func):
        def wrapper(self, *args, **kwargs):
            if self.started:
                return func(self, *args, **kwargs)
            else:
                print("You need to start the debugger first. Use 'start' command")
        return wrapper

    def reset_dbg_state(self):
        self.history = list()
        self.comp = None
        self.temp_break = False
        self.log_op = False
        self.sstores = {}
        self.sloads = {}
        self.callstack = []
        self.started = False

    # COMMANDS
    def do_chain(self, arg):
        print(f'{self.debug_target.chain}@{self.debug_target.block_number}:{self.w3.provider.endpoint_uri}')

    def do_block(self, arg):
        if arg and not self.started:
            self.debug_target.block_number = arg
        print(f'{self.debug_target.block_number}')

    def do_account(self, arg):
        print(f'{self.account.address}')

    def do_target(self, arg):
        # Check if there is an argument
        # (as of now, once the target is set, you cannot unset it)
        if arg and not self.started:
            self.debug_target.target_address = arg
        else:
            print(f'{self.debug_target.target_address}')

    def do_hextostr(self, arg):
        try:
            print(f'"{HexBytes(arg).decode("utf-8")}"')
        except Exception:
            print(f'Invalid hex string')

    def do_funcid(self, arg):
        arg = arg.encode('utf-8')
        k = sha3.keccak_256()
        k.update(arg)
        print("Function signature: 0x{}".format(k.hexdigest()[0:8]))

    def do_value(self, arg):
        if arg and not self.started:
            self.debug_target.value = int(arg,10)
        else:
            print(f'{self.debug_target.value}')

    def do_gas(self, arg):
        if arg and not self.started:
            self.debug_target.gas = int(arg,10)
        else:
            print(f'{self.debug_target.gas} wei')

    def do_start(self, arg):
        if self.started:
            answer = input("Debugger already started. Do you want to restart the debugger? [y/N] ")
            if answer.lower() == 'y':
                raise RestartDbgException()
            return
        if self.debug_target.target_address == "0x0":
            print("No target set. Use 'target' command to set it.")
            return
        if not self.debug_target.calldata and self.started == False:
            print("No calldata set. Proceeding with empty calldata.")

        vm, header = get_evm(self.w3, self.debug_target.block_number, self._myhook)

        assert self.debug_target.fork is None or self.debug_target.fork == vm.fork
        self.debug_target.set_default('fork', vm.fork)

        txn = self.debug_target.get_transaction_dict()
        raw_txn = bytes(self.account.sign_transaction(txn).rawTransaction)
        txn = vm.get_transaction_builder().decode(raw_txn)

        self.started = True

        origin_callframe = CallFrame(
            self.debug_target.target_address,
            self.account.address,
            self.account.address,
            self.debug_target.value,
            "-",
            "-")
        self.callstack.append(origin_callframe)

        self.temp_break = True

        receipt, comp = vm.apply_transaction(
            header=header,
            transaction=txn,
        )

    def do_context(self, arg):
        if self.started:
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
        else:
            quick_view = self._get_quick_view(arg)

    def do_calldata(self, arg):
        if arg and not self.started:
            self.debug_target.calldata = arg
        else:
            print(f'{self.debug_target.calldata}')

    def do_weitoeth(self, arg):
        try:
            print(f'{int(arg) / 10**18} ETH')
        except Exception:
            print(f'Invalid wei amount')

    def do_ethtowei(self, arg):
        try:
            print(f'{float(arg) * 10**18} wei')
        except Exception:
            print(f'Invalid ETH amount')

    def do_storageat(self, arg1):
        if not arg1:
            print("Usage: storageat [<address>:]<slot>[:<count>]")
            return

        address = None
        if ':' in arg1:
            address, slot = arg1.split(':')
            slot = int(slot, 0)
            address = HexBytes(address).hex()
        else:
            slot = int(arg1, 0)

        address = self.comp.msg.storage_address if self.started else self.debug_target.target_address
        try:
            if self.started:
                value_read = self.comp.state.get_storage(address, slot)
            else:
                value_read = self.w3.eth.get_storage_at(address, slot)
        except Exception as e:
            print("Something went wrong while fetching storage:")
            print(f' Error: {RED_COLOR}{e}{RESET_COLOR}')

        print(f' {CYAN_COLOR}[r]{RESET_COLOR} Slot: {slot} | Value: {hex(value_read)}')

    @only_when_started
    def do_sstores(self, arg):
        # Displat all the sstores issued during the tx
        for ref_account, sstores in self.sstores.items():
            print(f'Account: {ref_account}:')
            for sstore_slot, sstore_val in sstores.items():
                print(f' {YELLOW_COLOR}[w]{RESET_COLOR} Slot: {sstore_slot} | Value: {sstore_val}')

    @only_when_started
    def do_sloads(self, arg):
        # Displat all the sstores issued during the tx
        for ref_account, sloads in self.sloads.items():
            print(f'Account: {ref_account}:')
            for sload_slot, sload_val in sloads.items():
                print(f' {CYAN_COLOR}[r]{RESET_COLOR} Slot: {sload_slot} | Value: {hex(sload_val)}')

    def do_breaks(self,arg):
        # Print all the breaks
        for b_idx, b in enumerate(self.breakpoints):
            print(f'Breakpoint {b_idx} | {b}')

    def do_break(self, arg):
        # parse the arg
        break_args = arg.split(" ")
        try:
            bp = Breakpoint(break_args)
            self.breakpoints.append(bp)
        except InvalidBreakpointException as e:
            print("Invalid breakpoint")
    
    do_b = do_break

    @only_when_started
    def do_finish(self, arg):
        if len(self.callstack) > 1:
            self.temp_break_finish = True
            self.finish_curr_stack_depth = len(self.callstack)
            self._resume()


    def do_ipython(self, arg):
        import IPython; IPython.embed()

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
            if arg == "all":
                self.breakpoints = set()
                self.mnemonic_bps = set()
                print("All breakpoints cleared")
            else:
                # Check if arg is a hex number
                try:
                    arg = int(arg,16)
                    del self.breakpoints[arg]
                    print(f'Breakpoint cleared at {arg}')
                except Exception:
                    print("Invalid breakpoint")

    def do_run(self, arg):
        if self.started:
            answer = input("Debugger already started. Do you want to restart the debugger? [y/N] ")
            if answer.lower() == 'y':
                raise RestartDbgException()
            return
        if not self.debug_target.target_address:
            print("No target set. Use 'target' command to set it.")
            return
        if not self.debug_target.calldata and self.started == False:
            print("No calldata set. Proceeding with empty calldata.")

        vm, header = get_evm(self.w3, self.debug_target.block_number, self._myhook)
        self.debug_target.set_default('fork', vm.fork)

        txn = self.debug_target.get_transaction_dict()
        raw_txn = bytes(self.account.sign_transaction(txn).rawTransaction)
        txn = vm.get_transaction_builder().decode(raw_txn)

        self.started = True

        origin_callframe = CallFrame(self.debug_target.target_address, self.account.address, self.account.address, self.debug_target.value, "-", "-")
        self.callstack.append(origin_callframe)

        receipt, comp = vm.apply_transaction(
            header=header,
            transaction=txn,
        )

    do_r = do_run

    def do_log_op(self, arg):
        self.log_op = not self.log_op
        print(f'Logging opcodes: {self.log_op}')

    def do_quit(self, arg):
        print()
        sys.exit()

    def do_EOF(self, arg):
        print()
        # quit if user says yes or hits ctrl-d again
        try:
            if input(f" {BLUE_COLOR}[+] EOF, are you sure you want to quit? (y/n) {RESET_COLOR}") == 'y':
                self.do_quit(arg)
        except EOFError:
            self.do_quit(arg)
        except KeyboardInterrupt:
            pass
        finally:
            print()

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

        calls_view = ''
        max_call_opcode_length = max(len('CallType'), max(len(call.calltype) for call in self.callstack))
        max_pc_length = max(len('CallSite'), max(len(call.callsite) for call in self.callstack))
        calltype_string_legend = 'CallType'.ljust(max_call_opcode_length)
        callsite_string_legend = 'CallSite'.rjust(max_pc_length)
        legend = f'{"[ Legend: Address":42} | {calltype_string_legend} | {callsite_string_legend} | {"msg.sender":42} | msg.value ]\n'
        for call in self.callstack[::-1]:
            color = ''
            if call.calltype == "CALL":
                color = PURPLE_COLOR
                calltype_string = f'{call.calltype}'
            elif call.calltype == "DELEGATECALL" or call.calltype == "CODECALL":
                color = RED_COLOR
                calltype_string = f'{call.calltype}'
            elif call.calltype == "STATICCALL":
                color = BLUE_COLOR
                calltype_string = f'{call.calltype}'
            elif call.calltype == "CREATE":
                color = ORANGE_COLOR
                calltype_string = f'{call.calltype}'
            else:
                calltype_string = f'{call.calltype}'
            calltype_string = calltype_string.ljust(max_call_opcode_length)
            callsite_string = call.callsite.rjust(max_pc_length)
            calls_view += f'{call.address:42} | {color}{calltype_string}{RESET_COLOR} | {callsite_string} | {call.msg_sender:42} | {call.value} \n'

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

        _metadata = f'Current Code Account: {YELLOW_COLOR}{curr_account_code}{RESET_COLOR} | Current Storage Account: {YELLOW_COLOR}{curr_account_storage}{RESET_COLOR}\n'
        _metadata += f'Balance: {curr_balance} wei | Gas Remaining: {gas_remaining} | Gas Used: {gas_used} | Gas Limit: {gas_limit}'

        return title + _metadata

    def _get_stack(self, attempt_decode=False):
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
                entry_val_str = ''
                if attempt_decode:
                    try:
                        # Automatically decode strings if you can :)
                        entry_val_str = bytes.fromhex(entry_val).decode('utf-8')
                    except UnicodeDecodeError:
                        pass
                if entry_val_str != '':
                    _stack += f'{hex(entry_slot)}│ 0x{entry_val}  {entry_val_str!r}\n'
                else:
                    _stack += f'{hex(entry_slot)}│ 0x{entry_val}\n'
            else:
                # it's an int
                _stack += f'{hex(entry_slot)}│ {hex(entry_val)}\n'

        return title + _stack

    def _get_storage(self):
        ref_account = '0x' + self.comp.msg.storage_address.hex()
        message = f"{GREEN_COLOR}Active Storage Slots [{ref_account}]{RESET_COLOR}"

        fill = HORIZONTAL_LINE
        align = '<'
        width = max(self.tty_columns,0)

        title = f'{message:{fill}{align}{width}}'+'\n'
        legend = f'[ Legend: Slot Address -> Value ]\n'

        # Iterate over sloads for this account
        _sload_log = ''
        if ref_account in self.sloads:
            ref_account_sloads = self.sloads[ref_account]
            for slot, val in ref_account_sloads.items():
                _sload_log += f'{CYAN_COLOR}[r]{RESET_COLOR} {slot} -> {hex(val)}\n'

        # Iterate over sstore for this account
        _sstore_log = ''
        ref_account = '0x' + self.comp.msg.storage_address.hex()
        if ref_account in self.sstores:
            ref_account_sstores = self.sstores[ref_account]
            for slot, val in ref_account_sstores.items():
                _sstore_log += f'{YELLOW_COLOR}[w]{RESET_COLOR} {slot} -> {val}\n'


        return title + legend + _sload_log + _sstore_log

    def _get_quick_view(self, arg):
        # print the current configuration of EthDebugger
        message = f"{GREEN_COLOR}Quick View{RESET_COLOR}"
        fill = HORIZONTAL_LINE
        align = '<'
        width = max(self.tty_columns,0)

        title = f'{message:{fill}{align}{width}}'

        if arg != 'init':
            print(title)

        assert not self.started, "Debugger already started."

        # print the chain context and the transaction context
        print(f'Account: {YELLOW_COLOR}{self.account.address}{RESET_COLOR} | Target Contract: {YELLOW_COLOR}{self.debug_target.target_address}{RESET_COLOR}')
        print(f'Chain: {self.debug_target.chain} | Node: {self.w3.provider.endpoint_uri} | Block Number: {self.debug_target.block_number}')
        print(f'Value: {self.debug_target.value} | Gas: {self.debug_target.gas}')

    def _display_context(self, cmdloop=True):
        metadata_view = self._get_metadata()
        print(metadata_view)
        disass_view = self._get_disass()
        print(disass_view)
        stack_view = self._get_stack()
        print(stack_view)
        callstack_view = self._get_callstack()
        print(callstack_view)
        storage_view = self._get_storage()
        print(storage_view)

        if cmdloop:
            try:
                self.cmdloop(intro='')
            except ExitCmdException:
                pass
            except RestartDbgException:
                raise RestartDbgException()

    def _myhook(self, opcode: Opcode, computation: ComputationAPI):
        # Store a reference to the computation to make it
        # accessible to the comamnds
        self.comp = computation

        # the computation.code.__iter__() has already incremented the program counter by 1, account for this
        pc = computation.code.program_counter - 1

        with computation.code.seek(pc):
            opcode_bytes = computation.code.read(64) # max 32 byte immediate + 32 bytes should be enough, right???

        assert self.debug_target.fork is not None
        if opcode_bytes:
            insn: Instruction = disassemble_one(opcode_bytes, pc=pc, fork=self.debug_target.fork)
            assert insn is not None, "64 bytes was not enough to disassemble?? or this is somehow an invalid opcode??"
            assert insn.mnemonic == opcode.mnemonic, "disassembled opcode does not match the opcode we're currently executing??"
            hex_bytes = ' '.join(f'{b:02x}' for b in insn.bytes[:5])
            if insn.size > 5: hex_bytes += ' ...'
            _opcode_str = f'{pc:#06x}  {hex_bytes:18} {str(insn):20}    // {insn.description}'
        else:
            _opcode_str = f'{pc:#06x}  {"":18} {opcode.mnemonic:15} [WARNING: no code]'

        if self.log_op:
            print(_opcode_str)

        self.history.append(_opcode_str)

        # BREAKPOINT MANAGEMENT
        for sbp in self.breakpoints:
            if sbp.eval_bp(self.comp, opcode):
                self._display_context()
        
        if self.temp_break:
            self.temp_break = False
            self._display_context()
        #elif opcode.mnemonic in self.mnemonic_bps:
        #    self._display_context()
        
        if self.temp_break_finish and len(self.callstack) < self.finish_curr_stack_depth:
            # Reset finish break condition
            self.temp_break_finish = False
            self.finish_curr_stack_depth = None
            self._display_context()
        elif opcode.mnemonic == "STOP":
            self._display_context()

        if opcode.mnemonic == "SSTORE":
            ref_account = '0x' + computation.msg.storage_address.hex()

            slot_id = computation._stack.values[-1]
            slot_id = HexBytes(slot_id[1]).hex()

            slot_val = computation._stack.values[-2]
            slot_val = HexBytes(slot_val[1]).hex()

            if ref_account not in self.sstores.keys():
                self.sstores[ref_account] = {}
                self.sstores[ref_account][slot_id] = slot_val
            else:
                self.sstores[ref_account][slot_id] = slot_val

        if opcode.mnemonic == "SLOAD":
            ref_account = '0x' + computation.msg.storage_address.hex()

            slot_id = computation._stack.values[-1]
            slot_id = HexBytes(slot_id[1]).hex()

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
                contract_target = HexBytes(contract_target[1]).hex()

                value_sent = int.from_bytes(HexBytes(computation._stack.values[-3][1]), byteorder='big')

                # We gotta parse the callstack according to the *CALL opcode
                new_callframe = CallFrame(
                                        contract_target,
                                        '0x' + computation.msg.code_address.hex(),
                                        '0x' + computation.transaction_context.origin.hex(),
                                        value_sent,
                                        "CALL",
                                        hex(pc)
                                        )
                self.callstack.append(new_callframe)

            elif opcode.mnemonic == "DELEGATECALL":
                contract_target = computation._stack.values[-2]
                contract_target = HexBytes(contract_target[1]).hex()

                value_sent = int.from_bytes(HexBytes(computation._stack.values[-3][1]), byteorder='big')

                # We gotta parse the callstack according to the *CALL opcode
                new_callframe = CallFrame(
                                        contract_target,
                                        self.callstack[-1].msg_sender,
                                        '0x' + computation.transaction_context.origin.hex(),
                                        value_sent,
                                        "DELEGATECALL",
                                        hex(pc)
                                        )
                self.callstack.append(new_callframe)

            elif opcode.mnemonic == "STATICCALL":
                contract_target = computation._stack.values[-2]
                contract_target = HexBytes(contract_target[1]).hex()

                value_sent = int.from_bytes(HexBytes(computation._stack.values[-3][1]), byteorder='big')

                # We gotta parse the callstack according to the *CALL opcode
                new_callframe = CallFrame(
                                        contract_target,
                                        '0x' + computation.msg.code_address.hex(),
                                        '0x' + computation.transaction_context.origin.hex(),
                                        value_sent,
                                        "STATICCALL",
                                        hex(pc)
                                        )
                self.callstack.append(new_callframe)


            elif opcode.mnemonic == "CREATE":
                contract_value = HexBytes(computation._stack.values[-1][1]).hex()
                code_offset = HexBytes(computation._stack.values[-2][1]).hex()
                code_size = HexBytes(computation._stack.values[-3][1]).hex()
                new_callframe = CallFrame(
                    '0x' + '0' * 40,
                    '0x' + computation.msg.code_address.hex(),
                    '0x' + computation.transaction_context.origin.hex(),
                    contract_value,
                    "CREATE",
                    hex(pc)
                )
                self.callstack.append(new_callframe)


            else:
                print(f"Plz add support for {opcode.mnemonic}")

        if opcode.mnemonic in RETURN_OPCODES:
            if opcode.mnemonic == "REVERT":
                error = '""'
                try:
                    error =  self.comp.error
                except Exception:
                    pass
                print(f'{YELLOW_COLOR}>>> Execution Reverted at 0x{computation.msg.code_address.hex()} | PC: {hex(pc)} | Message: {error} <<<{RESET_COLOR}')
                self._display_context()

            self.callstack.pop()

        # Execute the opcode!
        opcode(computation=computation)


    def print_license(self):
        print(f"{YELLOW_COLOR}⧫ {BOLD_TEXT}ethdbg 0.1 ⧫ - The CLI Ethereum Debugger{RESET_COLOR}")
        print("License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>")
        print("This is free software: you are free to change and redistribute it.")
        print("There is NO WARRANTY, to the extent permitted by law.\n")

# We require a .ethdbg config file in ~/.ethdbg
# This will pull the account to use for the transaction and related private key
if __name__ == "__main__":

    # Check if there is an argument
    # Parse the argument using argparse
    parser = argparse.ArgumentParser()

    # parse optional argument
    parser.add_argument("--txid", help="address of the smart contract we are debugging", default=None)
    parser.add_argument("--chain", help="chain name", default=None)
    parser.add_argument("--node-url", help="url to connect to geth node (infura, alchemy, or private)", default=DEFAULT_NODE_URL)
    parser.add_argument("--target", help="address of the smart contract we are debugging", default=None)
    parser.add_argument("--block", help="reference block", default=None)
    parser.add_argument("--calldata", help="calldata to use for the transaction", default=None)
    args = parser.parse_args()

    ethdbg_conf = get_config()
    w3 = get_w3_provider(args.node_url)

    if args.txid:
        # replay transaction mode
        debug_target = TransactionDebugTarget(w3)
        debug_target.replay_transaction(args.txid, chain=args.chain, to=args.target, block_number=args.block, calldata=args.calldata)
    else:
        # interactive mode
        debug_target = TransactionDebugTarget(w3)
        debug_target.new_transaction(to=args.target, calldata=args.calldata, chain=args.chain, block_number=args.block)

    ethdbgshell = EthDbgShell(ethdbg_conf, w3, debug_target=debug_target)
    ethdbgshell.print_license()

    while True:
        try:
            ethdbgshell.cmdloop()
        except ExitCmdException:
            print("Program terminated.")
            continue
        except RestartDbgException:
            ethdbgshell = EthDbgShell(ethdbg_conf, w3, debug_target=debug_target)
