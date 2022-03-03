package state

import (
	"errors"
	"fmt"
	"math/big"

	"git.mills.io/prologic/bitcask"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

type TransferDirOnly int
type PotentialIdentity int

const (
	From TransferDirOnly = iota //The "Address" is the receiver
	To                          //The "Address" is the sender
)

const (
	NotDecided PotentialIdentity = iota
	Victim
	Neither
	Beneficiary
)

type TransferDir struct {
	tdo  TransferDirOnly
	addr common.Address
}
type TransferAmount struct {
	td  TransferDir
	amt common.Hash
}
type IndividualAdversaryAccountHelper struct {
	id  PotentialIdentity
	amt common.Hash
}
type TransferInfo struct {
	addr1 common.Address
	addr2 common.Address
	amt   common.Hash
	token common.Address
}
type AccountTransferInfoPerToken struct {
	token     common.Address
	earn_flag bool
	amt       common.Hash
}
type AccountTransferInfo struct {
	acct      common.Address
	tokenflow []AccountTransferInfoPerToken
}
type AdversaryAccount struct {
	// account balance trace
	//Address 1: the owner of the tokens
	//Address 2: the contract address of the token
	//TransferDir: the token flow direction of the transfer
	//Vec<U256>: the trace of the toke flows
	balance_traces map[common.Address]map[common.Address][]TransferAmount
	// store all transfers in order
	transfer_in_order []TransferInfo
	//Track all address flash loan potential attack
	flash_loan_information map[common.Address]IndividualAdversaryAccountHelper
	// potential flash loan transaction
	old_tx *types.Message
	//old_tx contract address. It is set when init if old_tx is Call. Set after executing if old_tx is Create
	old_tx_contract_address *common.Address
	// Nonce of Adversary account.
	nonce uint64
	// Nonce of my account,
	my_nonce uint64
	// new deploy transaction, NOTICE that it may be None if old_tx is deploy tx
	new_deploy_tx *types.Message
	// new flash loan transaction, NOTICE that it may be also a deploy transaction if old_tx is deploy tx
	new_tx *types.Message
	// new call for init. It should be used if new_tx fails.
	new_init_func_call_tx *types.Message
	//temp contract addresses created in this transcation
	temp_contract_addresses []common.Address
	//target beneficiary addresses to replace in data instead of sender and old_tx_contract_address
	target_beneficiary_addresses []common.Address
}

func NewAdversaryAccount(n uint64, t *types.Message, m_n uint64) *AdversaryAccount {
	tmp_old_tx_contract_address := t.To()
	aa := &AdversaryAccount{
		balance_traces:               make(map[common.Address]map[common.Address][]TransferAmount),
		transfer_in_order:            []TransferInfo{},
		flash_loan_information:       make(map[common.Address]IndividualAdversaryAccountHelper),
		old_tx:                       nil,
		old_tx_contract_address:      tmp_old_tx_contract_address,
		nonce:                        n,
		my_nonce:                     m_n,
		new_deploy_tx:                nil,
		new_tx:                       nil,
		new_init_func_call_tx:        nil,
		temp_contract_addresses:      []common.Address{},
		target_beneficiary_addresses: []common.Address{},
	}
	return aa
}
func (aa *AdversaryAccount) set_balance(addr common.Address, related_addr common.Address, bal common.Hash, token_addr common.Address, sender_receiver bool) {
	if balinfo := aa.balance_traces[addr]; balinfo != nil {
		if val := balinfo[token_addr]; val != nil {
			if sender_receiver {
				val = append(val, TransferAmount{TransferDir{From, related_addr}, bal})
			} else {
				val = append(val, TransferAmount{TransferDir{To, related_addr}, bal})
			}
			aa.balance_traces[addr][token_addr] = val
		} else {
			var tmp []TransferAmount
			if sender_receiver {
				tmp = append(tmp, TransferAmount{TransferDir{From, related_addr}, bal})
			} else {
				tmp = append(tmp, TransferAmount{TransferDir{To, related_addr}, bal})
			}
			aa.balance_traces[addr][token_addr] = tmp
		}
	} else {
		var tmp []TransferAmount
		if sender_receiver {
			tmp = append(tmp, TransferAmount{TransferDir{From, related_addr}, bal})
		} else {
			tmp = append(tmp, TransferAmount{TransferDir{To, related_addr}, bal})
		}
		aa.balance_traces[addr] = make(map[common.Address][]TransferAmount)
		aa.balance_traces[addr][token_addr] = tmp
	}
}

func (aa *AdversaryAccount) set_token_flow(addrfrom common.Address, addrto common.Address, amt common.Hash, token_addr common.Address) {
	if _, ok := ERC_TOKEN_INFORMATION_MAP[token_addr]; ok {
		aa.transfer_in_order = append(aa.transfer_in_order, TransferInfo{addrfrom, addrto, amt, token_addr})
		aa.set_balance(addrfrom, addrto, amt, token_addr, true)
		aa.set_balance(addrto, addrfrom, amt, token_addr, false)
	}
}

func (aa *AdversaryAccount) identify_helper() []AccountTransferInfo {
	var ret []AccountTransferInfo
	for a, b := range aa.balance_traces {
		// assert.Equal(len(b) > 0, true, "TransferAmount per token should not be empty!")
		var inner_ret []AccountTransferInfoPerToken
		for c, d := range b {
			// assert.Equal(len(d) > 0, true, "TransferAmount should not be empty!")
			earn_flag := true
			benefit := common.BigToHash(big.NewInt(0))
			for _, e := range d {
				if e.td.tdo == From {
					if earn_flag {
						if e.amt.Big().Cmp(benefit.Big()) == -1 {
							earn_flag = true
							benefit = common.BigToHash(big.NewInt(0).Sub(benefit.Big(), e.amt.Big()))
						} else {
							earn_flag = false
							benefit = common.BigToHash(big.NewInt(0).Sub(e.amt.Big(), benefit.Big()))
						}
					} else {
						earn_flag = false
						benefit = common.BigToHash(big.NewInt(0).Add(e.amt.Big(), benefit.Big()))
					}
				} else {
					if earn_flag {
						earn_flag = true
						benefit = common.BigToHash(big.NewInt(0).Add(e.amt.Big(), benefit.Big()))
					} else {
						if e.amt.Big().Cmp(benefit.Big()) == -1 {
							earn_flag = false
							benefit = common.BigToHash(big.NewInt(0).Sub(benefit.Big(), e.amt.Big()))
						} else {
							earn_flag = true
							benefit = common.BigToHash(big.NewInt(0).Sub(e.amt.Big(), benefit.Big()))
						}
					}
				}
			}
			inner_ret = append(inner_ret, AccountTransferInfoPerToken{c, earn_flag, benefit})
		}
		ret = append(ret, AccountTransferInfo{a, inner_ret})
	}
	return ret
}

func (aa *AdversaryAccount) anaylsis_net_profit_in_one_thousandth_usd() {
	ret_vec := aa.identify_helper()
	if len(ret_vec) > 0 {
		for _, pack := range ret_vec {
			addr := pack.acct
			values := pack.tokenflow
			earn_flag := true
			benefit := common.BigToHash(big.NewInt(0))
			for _, flow := range values {
				a := flow.token
				b := flow.earn_flag
				c := flow.amt
				if ti, ok := ERC_TOKEN_INFORMATION_MAP[a]; ok {
					price := ti.price
					decimal := ti.decimals
					net_value := common.BigToHash(big.NewInt(0).Div(big.NewInt(0).Mul(c.Big(), price.Big()), decimal.Big()))
					if earn_flag {
						if b {
							earn_flag = true
							benefit = common.BigToHash(big.NewInt(0).Add(net_value.Big(), benefit.Big()))
						} else {
							if net_value.Big().Cmp(benefit.Big()) == 1 {
								earn_flag = false
								benefit = common.BigToHash(big.NewInt(0).Sub(net_value.Big(), benefit.Big()))
							} else {
								earn_flag = true
								benefit = common.BigToHash(big.NewInt(0).Sub(benefit.Big(), net_value.Big()))
							}
						}
					} else {
						if !b {
							earn_flag = false
							benefit = common.BigToHash(big.NewInt(0).Add(net_value.Big(), benefit.Big()))
						} else {
							if net_value.Big().Cmp(benefit.Big()) == 1 {
								earn_flag = true
								benefit = common.BigToHash(big.NewInt(0).Sub(net_value.Big(), benefit.Big()))
							} else {
								earn_flag = false
								benefit = common.BigToHash(big.NewInt(0).Sub(benefit.Big(), net_value.Big()))
							}
						}
					}
				} else {
					fmt.Println("ERROR: The token address is not recognizable!")
				}
			}
			var val IndividualAdversaryAccountHelper
			if benefit.Big().Cmp(big.NewInt(0)) == 0 {
				val.id = Neither
			} else if earn_flag {
				val.id = Beneficiary
				val.amt = benefit
			} else {
				val.id = Victim
				val.amt = benefit
			}
			aa.flash_loan_information[addr] = val
		}
	}
}
func (aa *AdversaryAccount) find_flash_loan_end_positions() ([]TransferInfo, []TransferInfo) {
	var flash_loan_start []TransferInfo
	var flash_loan_start_return []TransferInfo
	var flash_loan_end_return []TransferInfo
	for _, i := range aa.transfer_in_order {
		from := i.addr1
		to := i.addr2
		amt := i.amt
		token := i.token
		for _, j := range FLASH_LOAN_CONTRACT_ADDRESSES {
			if j == from {
				flash_loan_start = append(flash_loan_start, i)
			}
		}
		for _, k := range FLASH_LOAN_CONTRACT_ADDRESSES {
			if k == to {
				for _, m := range flash_loan_start {
					if m.addr1 == to && m.amt.Big().Cmp(amt.Big()) < 1 && m.token == token {
						flash_loan_start_return = append(flash_loan_start_return, m)
						flash_loan_end_return = append(flash_loan_end_return, i)
					}
				}
			}
		}
	}
	if len(flash_loan_end_return) <= 0 {
		return []TransferInfo{}, []TransferInfo{}
	} else {
		return flash_loan_start_return, flash_loan_end_return
	}
}

func (aa *AdversaryAccount) token_transfer_flash_loan_check(assemable_new bool) bool {
	aa.anaylsis_net_profit_in_one_thousandth_usd()
	var beneficiary []common.Address
	var victim []common.Address
	for addr, result := range aa.flash_loan_information {
		if result.id == Beneficiary {
			beneficiary = append(beneficiary, addr)
		} else if result.id == Victim {
			victim = append(victim, addr)
		}
	}
	if len(beneficiary) == 0 {
		return false
	}
	start, _ := aa.find_flash_loan_end_positions()
	if len(start) > 0 {
		for _, ri := range start {
			a := ri.addr1
			b := ri.addr2
			c := ri.amt
			d := ri.token
			fmt.Println("Flash Loan Address ", a, "sends ", c, " of token address ", d, " to Address ", b)
			aa.old_tx_contract_address = &b
			//DEBUGGING: print all Beneficiary and Victim
			for addr, result := range aa.flash_loan_information {
				if result.id == Beneficiary {
					fmt.Println("Address", addr, " gains ", result.amt, " in 0.0001 USD unit")
				} else if result.id == Victim {
					fmt.Println("Address", addr, " loses ", result.amt, " in 0.0001 USD unit")
				}
			}
		}
	} else {
		return false
	}
	found_in_beneficiary := false
	for _, i := range beneficiary {
		if i == aa.old_tx.From() || i == *aa.old_tx_contract_address {
			found_in_beneficiary = true
		}
	}
	if !found_in_beneficiary {
		for _, addr := range beneficiary {
			if trans := aa.balance_traces[addr]; trans != nil {
				only_receive_from_sender_and_contract := true
				for _, infos := range trans {
					for _, i := range infos {
						if i.td.tdo == To {
							if !(i.td.addr == aa.old_tx.From() || i.td.addr == *aa.old_tx_contract_address) {
								only_receive_from_sender_and_contract = false
							}
						}
					}
				}
				if only_receive_from_sender_and_contract {
					found_it := false
					for _, t := range aa.target_beneficiary_addresses {
						if t == addr {
							found_it = true
						}
					}
					if !found_it {
						aa.target_beneficiary_addresses = append(aa.target_beneficiary_addresses, addr)
					}
				}
			}
		}
		if len(aa.target_beneficiary_addresses) == 0 {
			fmt.Println("sender and contract address are both not beneficiary. Front run tx will not be assembled!")
			return false
		}
	}
	if assemable_new {
		aa.assemable_new_transactions()
	}
	return true
}
func (aa *AdversaryAccount) assemable_new_transactions() {
	if aa.old_tx.To() == nil {
		new_data := aa.old_tx.Data()
		if len(aa.target_beneficiary_addresses) != 0 {
			for _, addr_to_be_replaced := range aa.target_beneficiary_addresses {
				new_data = replace_hardcoded_address_in_data(addr_to_be_replaced, FRONTRUN_ADDRESS, new_data)
			}
		}
		new_data = replace_hardcoded_address_in_data(aa.old_tx.From(), FRONTRUN_ADDRESS, new_data)
		aa.new_deploy_tx = nil
		msg := types.NewMessage(FRONTRUN_ADDRESS, nil, aa.old_tx.Nonce(), aa.old_tx.Value(), aa.old_tx.Gas(), aa.old_tx.GasPrice(), new_data, aa.old_tx.AccessList(), true)
		aa.old_tx = &msg
	} else {
		if deploy_gas_price, deploy_gas, deploy_value, is_create_action, call_address, deploy_data, ok := Get_contract_init_data_with_init_call(*aa.old_tx_contract_address); ok == nil {
			replaced_deploy_data := deploy_data
			if len(aa.target_beneficiary_addresses) != 0 {
				for _, addr_to_be_replaced := range aa.target_beneficiary_addresses {
					replaced_deploy_data = replace_hardcoded_address_in_data(addr_to_be_replaced, FRONTRUN_ADDRESS, replaced_deploy_data)
				}
			}
			var tmp *common.Address
			if is_create_action == 1 {
				tmp = nil
			} else {
				tmp = &call_address
			}
			deploy_msg := types.NewMessage(FRONTRUN_ADDRESS, tmp, aa.my_nonce, deploy_value.Big(), deploy_gas.Big().Uint64(), deploy_gas_price.Big(), replaced_deploy_data, aa.old_tx.AccessList(), true)
			aa.new_deploy_tx = &deploy_msg
			new_address := crypto.CreateAddress(FRONTRUN_ADDRESS, aa.my_nonce)
			fmt.Println("New contract address is assemabled into front run tx")
			call_data := replace_hardcoded_address_in_data(*aa.old_tx_contract_address, new_address, aa.old_tx.Data())
			call_data = replace_hardcoded_address_in_data(aa.old_tx.From(), FRONTRUN_ADDRESS, call_data)
			if len(aa.target_beneficiary_addresses) != 0 {
				for _, addr_to_be_replaced := range aa.target_beneficiary_addresses {
					call_data = replace_hardcoded_address_in_data(addr_to_be_replaced, FRONTRUN_ADDRESS, call_data)
				}
			}
			var tmp_call *common.Address
			if *aa.old_tx.To() == *aa.old_tx_contract_address {
				tmp_call = &new_address
			} else {
				tmp_call = aa.old_tx.To()
			}
			msg := types.NewMessage(FRONTRUN_ADDRESS, tmp_call, aa.my_nonce+1, aa.old_tx.Value(), aa.old_tx.Gas(), aa.old_tx.GasPrice(), call_data, aa.old_tx.AccessList(), true)
			aa.new_tx = &msg
			//prepare potential init func call tx
			if init_call_gas_price, init_call_gas, init_call_value, init_call_data, ok := Get_contract_init_func_call_with_init_call(*aa.old_tx_contract_address); ok == nil {
				replaced_init_call_data := replace_hardcoded_address_in_data(*aa.old_tx_contract_address, FRONTRUN_ADDRESS, init_call_data)
				replaced_init_call_data = replace_hardcoded_address_in_data(aa.old_tx.From(), FRONTRUN_ADDRESS, replaced_init_call_data)
				if len(aa.target_beneficiary_addresses) != 0 {
					for _, addr_to_be_replaced := range aa.target_beneficiary_addresses {
						replaced_init_call_data = replace_hardcoded_address_in_data(addr_to_be_replaced, FRONTRUN_ADDRESS, replaced_init_call_data)
					}
				}
				new_init_func_call_msg := types.NewMessage(FRONTRUN_ADDRESS, tmp_call, aa.my_nonce+1, init_call_value.Big(), init_call_gas.Big().Uint64(), init_call_gas_price.Big(), replaced_init_call_data, aa.old_tx.AccessList(), true)
				aa.new_init_func_call_tx = &new_init_func_call_msg
			} else {
				fmt.Println("No found information for contract init call address.")
			}
		} else {
			aa.new_init_func_call_tx = nil
			fmt.Println("No found information for contract address. Front run tx assembling failed!")
		}
	}
}
func Overwrite_new_tx(new_tx_as_input types.Message, overwrite_contract_address common.Address) types.Message {
	wrong_address := new_tx_as_input.To()
	call_data := replace_hardcoded_address_in_data(*wrong_address, overwrite_contract_address, new_tx_as_input.Data())
	msg := types.NewMessage(new_tx_as_input.From(), &overwrite_contract_address, new_tx_as_input.Nonce(), new_tx_as_input.Value(), new_tx_as_input.Gas(), new_tx_as_input.GasPrice(), call_data, new_tx_as_input.AccessList(), true)
	return msg
}
func Overwrite_new_tx_nonce(new_tx_as_input types.Message, new_nonce uint64) types.Message {
	msg := types.NewMessage(new_tx_as_input.From(), new_tx_as_input.To(), new_nonce, new_tx_as_input.Value(), new_tx_as_input.Gas(), new_tx_as_input.GasPrice(), new_tx_as_input.Data(), new_tx_as_input.AccessList(), true)
	return msg
}
func (aa *AdversaryAccount) get_txs() (*types.Message, *types.Message) {
	return aa.new_deploy_tx, aa.new_tx
}
func (aa *AdversaryAccount) get_txs_with_init_call() (*types.Message, *types.Message, *types.Message) {
	return aa.new_deploy_tx, aa.new_tx, aa.new_init_func_call_tx
}

//useless function. Can be removed
func (aa *AdversaryAccount) store_contract_address(addr common.Address) {
	aa.temp_contract_addresses = append(aa.temp_contract_addresses, addr)
}

func replace_hardcoded_address_in_data(address_in common.Address, address_out common.Address, data []byte) []byte {
	parsed_data := data
	if len(data) >= 20 {
		for i := 0; i < len(data)-20; i++ {
			if address_in == common.BytesToAddress(data[i:i+20]) {
				for j := 0; j < 20; j++ {
					parsed_data[i+j] = address_out[j]
				}
			}
		}
	}
	return parsed_data
}

// func Get_contract_init_data(contract common.Address) (common.Hash, common.Hash, common.Hash, byte, common.Address, []byte, error) {
// 	var r1 common.Hash
// 	var r2 common.Hash
// 	var r3 common.Hash
// 	var r4 byte
// 	var r5 common.Address
// 	var r6 []byte
// 	db, _ := bitcask.Open("contract_db")
// 	defer db.Close()
// 	if val, ok := db.Get(contract.Bytes()); ok == nil {
// 		r1 = common.BytesToHash(val[0:32])
// 		r2 = common.BytesToHash(val[32:64])
// 		r3 = common.BytesToHash(val[64:96])
// 		r4 = val[96]
// 		r5 = common.BytesToAddress(val[97:117])
// 		r6 = val[117:]
// 	} else {
// 		return r1, r2, r3, r4, r5, r6, errors.New("no data found")
// 	}
// 	return r1, r2, r3, r4, r5, r6, nil
// }

// func Set_contract_init_data(contract common.Address, gas_price common.Hash, gas common.Hash, value common.Hash, data []byte, is_create_action byte, call_address common.Address, sender common.Address) {
// 	db, _ := bitcask.Open("contract_db")
// 	defer db.Close()
// 	parsed_data := replace_hardcoded_address_in_data(sender, FRONTRUN_ADDRESS, data)
// 	var raw_data []byte
// 	raw_data = append(raw_data, gas_price.Bytes()...)
// 	raw_data = append(raw_data, gas.Bytes()...)
// 	raw_data = append(raw_data, value.Bytes()...)
// 	raw_data = append(raw_data, is_create_action)
// 	raw_data = append(raw_data, call_address.Bytes()...)
// 	raw_data = append(raw_data, parsed_data...)
// 	db.Put(contract.Bytes(), raw_data)
// }

func Set_contract_init_data_with_init_call(contract common.Address, gas_price common.Hash, gas common.Hash, value common.Hash, data []byte, is_create_action byte, call_address common.Address, sender common.Address) {
	db, _ := bitcask.Open("contract_db")
	defer db.Close()
	parsed_data := replace_hardcoded_address_in_data(sender, FRONTRUN_ADDRESS, data)
	var raw_data []byte
	raw_data = append(raw_data, gas_price.Bytes()...)
	raw_data = append(raw_data, gas.Bytes()...)
	raw_data = append(raw_data, value.Bytes()...)
	raw_data = append(raw_data, is_create_action)
	raw_data = append(raw_data, call_address.Bytes()...)
	raw_data = append(raw_data, make([]byte, 32)...)
	raw_data = append(raw_data, parsed_data...)
	db.Put(contract.Bytes(), raw_data)
}
func Get_contract_init_data_with_init_call(contract common.Address) (common.Hash, common.Hash, common.Hash, byte, common.Address, []byte, error) {
	var r1 common.Hash
	var r2 common.Hash
	var r3 common.Hash
	var r4 byte
	var r5 common.Address
	var r6 []byte
	db, _ := bitcask.Open("contract_db")
	defer db.Close()
	if val, ok := db.Get(contract.Bytes()); ok == nil {
		r1 = common.BytesToHash(val[0:32])
		r2 = common.BytesToHash(val[32:64])
		r3 = common.BytesToHash(val[64:96])
		r4 = val[96]
		r5 = common.BytesToAddress(val[97:117])
		is_init_call_stored := val[117:149]
		is_init_call_stored_int := new(big.Int)
		is_init_call_stored_int.SetBytes(is_init_call_stored)
		if is_init_call_stored_int.Cmp(big.NewInt(0)) == 0 {
			r6 = val[149:]
		} else {
			r6 = val[149 : 149+is_init_call_stored_int.Int64()]
		}
	} else {
		return r1, r2, r3, r4, r5, r6, errors.New("no data found")
	}
	return r1, r2, r3, r4, r5, r6, nil
}
func Check_and_set_contract_init_func_call_data_with_init_call(contract common.Address, gas_price common.Hash, gas common.Hash, value common.Hash, data []byte, sender common.Address) bool {
	db, _ := bitcask.Open("contract_db")
	defer db.Close()
	if val, ok := db.Get(contract.Bytes()); ok == nil {
		is_init_call_stored := val[117:149]
		is_init_call_stored_int := new(big.Int)
		is_init_call_stored_int.SetBytes(is_init_call_stored)
		if is_init_call_stored_int.Cmp(big.NewInt(0)) == 0 {
			r6 := val[149:]
			is_init_call_stored_bytes := big.NewInt(int64(len(r6))).Bytes()
			raw_data := val
			for i := 0; i < 32; i++ {
				raw_data[117+i] = is_init_call_stored_bytes[i]
			}
			parsed_data := replace_hardcoded_address_in_data(sender, FRONTRUN_ADDRESS, data)
			raw_data = append(raw_data, gas_price.Bytes()...)
			raw_data = append(raw_data, gas.Bytes()...)
			raw_data = append(raw_data, value.Bytes()...)
			raw_data = append(raw_data, parsed_data...)
			db.Put(contract.Bytes(), raw_data)
			return true
		}
	}
	return false
}
func Get_contract_init_func_call_with_init_call(contract common.Address) (common.Hash, common.Hash, common.Hash, []byte, error) {
	var r1 common.Hash
	var r2 common.Hash
	var r3 common.Hash
	var r6 []byte
	db, _ := bitcask.Open("contract_db")
	defer db.Close()
	if val, ok := db.Get(contract.Bytes()); ok == nil {
		is_init_call_stored := val[117:149]
		is_init_call_stored_int := new(big.Int)
		is_init_call_stored_int.SetBytes(is_init_call_stored)
		if is_init_call_stored_int.Cmp(big.NewInt(0)) == 0 {
			return r1, r2, r3, r6, errors.New("no data found")
		} else {
			r1 = common.BytesToHash(val[149+is_init_call_stored_int.Int64()+0 : 149+is_init_call_stored_int.Int64()+32])
			r2 = common.BytesToHash(val[149+is_init_call_stored_int.Int64()+32 : 149+is_init_call_stored_int.Int64()+64])
			r3 = common.BytesToHash(val[149+is_init_call_stored_int.Int64()+64 : 149+is_init_call_stored_int.Int64()+96])
			r6 = val[149+is_init_call_stored_int.Int64()+96:]
		}
	} else {
		return r1, r2, r3, r6, errors.New("no data found")
	}
	return r1, r2, r3, r6, nil
}
