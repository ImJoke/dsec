# SKILL: CTF Blockchain (Web3/Smart Contracts)

## Description
Methodology for attacking Ethereum and EVM-compatible smart contracts in CTF challenges.

## Trigger Phrases
blockchain, web3, smart contract, solidity, ether, evm, reentrancy, fallback, delegatecall

## Methodology

### Initial Recon & Decompilation
1. **Source Code Check:** Look for provided `.sol` files. If only bytecode is given, use [ethervm.io/decompile](https://ethervm.io/decompile) or Panoramix (via Etherscan) to decompile to Solidity-like syntax.
2. **Environment Setup:** Use `Foundry` (cast/forge) or `Hardhat` for interaction. Connect to the provided RPC endpoint.
   - `cast call <address> "func(uint256)" 123 --rpc-url <url>`
   - `cast send <address> "func(uint256)" 123 --private-key <key> --rpc-url <url>`

### Vulnerability Classes
1. **Reentrancy:**
   - Look for `call.value()` before state updates (e.g., updating balances after sending Ether).
   - Exploit: Write an attacker contract with a `fallback()` or `receive()` function that calls the vulnerable function again before the first invocation finishes.
2. **Integer Overflow/Underflow:**
   - Common in Solidity < 0.8.0 unless `SafeMath` is used.
   - Exploit: Subtracting 1 from 0 yields `2^256 - 1`, bypassing balance checks.
3. **Access Control (tx.origin vs msg.sender):**
   - Look for `require(tx.origin == owner)`.
   - Exploit: Phishing contract. When the victim calls the attacker contract, and the attacker contract calls the vulnerable contract, `tx.origin` is the victim, but `msg.sender` is the attacker contract.
4. **Unsafe Delegatecall:**
   - Look for `address.delegatecall()`. It executes code from the target address but in the *context* of the calling contract (preserving storage, `msg.sender`, `msg.value`).
   - Exploit: Provide an address with malicious code that overwrites critical storage slots (like the owner address).
5. **Storage Layout & Private Variables:**
   - "Private" variables are visible on the blockchain!
   - Exploit: `cast storage <address> <slot_index> --rpc-url <url>` to read hidden passwords or flags. Remember that EVM packs multiple small variables into a single 32-byte slot.
6. **Bad Randomness:**
   - Using `block.timestamp`, `blockhash`, or `block.difficulty` for randomness.
   - Exploit: Write an attacker contract that computes the same values in the exact same transaction block to guess the random number perfectly.

## Tools
- `foundry` (forge, cast, anvil)
- `brownie` / `hardhat` / `web3.py`
- `slither` (static analysis)
- `mythril` (symbolic execution)
