# Mixer Model

## Goals

We want to find a way to deposit some money into an anonymity set and then withdraw from it later so that those two transactions cannot be linked together. This results globally in a transaction between two different public accounts without knowing the origin of the transfer.

```
0xABC -> MIXER -> 0xDEF
```

### Non-Goals

- Full key/address management (we'll only use one-time keys)
- Multi-Asset
- Full Private Transfers
- Programmable Private Coins

## Design

We'll add two mixer extrinsics: `mint` (enter the mixer) and `claim` (exit the mixer) which will verify zero-knowledge proofs of validity before updating the ledger state.

### Minting

To mint a new coin a user should compute a ZKP for the following computation:

```rust
fn mint(key: Key, amount: Balance) -> UTXO {
    utxo_hash(key, amount)
}
```

where `amount` and `UTXO` are public inputs. We can choose `utxo_hash` to be any ZK-friendly hash function. We'll choose Poseidon in this case.

#### Ledger Check

- `amount` can be withdrawn from the `origin` account
- `UTXO` does not appear in the UTXO Set
- verify ZKP

#### Ledger Update

- `amount` is withdrawn from the public account
- `UTXO` is inserted in the UTXO Set and the merkle root is updated

### Claiming

To claim a minted token to another account the user should compute a ZKP for the following computation:

```rust
fn claim(key: Key, amount: Balance, merkle_tree: MerkleTree) -> (MerkleRoot, VoidNumber) {
  let utxo = utxo_hash(key, amount);
  assert!(merkle_tree.contains(utxo));
  let void_number = void_number_hash(key, utxo);
  (merkle_tree.root(), void_number)
}
```

where the `amount`, `merkle_tree.root()`, and `void_number` are public inputs. We again choose `void_number` to be (a different instantiation of) the Poseidon hash function.

#### Ledger Check

- the `MerkleRoot` matches the current merkle root of the ledger (or older!)
- the `void_number` does not appear in the Void Number Set
- verify ZKP

#### Ledger Update

- `amount` is deposited into the `origin` account
- `void_number` is added to the Void Number set
