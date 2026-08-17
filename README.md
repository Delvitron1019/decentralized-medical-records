# Decentralized Medical Records

Patient-controlled access to medical records, enforced by a Solidity smart
contract. Three actor types — patients, hospitals, insurers — hold genuinely
different permissions over the same data.

**Reproducible from a clean clone.** `npm install && npm test`.

---

## Results

**25 / 25 tests passing.** Solidity 0.8.24, optimizer on (200 runs), Hardhat +
ethers v6.

### Gas costs

| Operation | Avg gas | Note |
|---|---:|---|
| Deployment | 957,064 | 1.6% of block limit |
| `addRecord` | 98,688 | writes a new record pointer |
| `grantRole` | 51,559 | admin assigns hospital/insurer |
| `shareRecord` | 50,649 | share one record with one party |
| `grantAccess` | 48,494 | standing grant |
| `pause` | 47,022 | |
| `revokeRecordShare` | 24,262 | |
| `revokeAccess` | **23,700** | cheapest write in the contract |

Two things in that table are deliberate rather than accidental.

**Revocation is the cheapest operation** — half the cost of granting. Withdrawing
consent should never be the expensive path, because cost is friction and friction
on consent withdrawal is a safety problem, not just a UX one. It comes out cheap
because revoking writes a zero and earns a storage refund; the design and the
economics happen to agree here.

**`addRecord` ranges 82,494–99,594.** The low end is a repeat write to a patient
who already has records; the high end initialises a fresh storage slot. That gap
is the cold-versus-warm storage cost, and it means the first record for any
patient is meaningfully more expensive than their tenth.

---

## The design decision that matters

**No patient data goes on-chain.** Only a content hash — an IPFS CID or the
hash of an encrypted payload — plus metadata.

This isn't an optimisation, it's the entire architecture. On-chain data is
permanent, world-readable, and cannot be deleted. Putting protected health
information there would be irreversible and unlawful under GDPR's right to
erasure. The chain stores *who may access what*; the encrypted payload lives
off-chain.

Most "blockchain for healthcare" designs get this wrong, and it's the first
thing worth checking in any of them.

## Permissions

| Role | Can do | Cannot do |
|---|---|---|
| **Patient** | Own their records, grant and revoke access, share individual records | — |
| **Hospital** | Write records for patients who granted write access; read what it authored | Read records it didn't author without a grant |
| **Insurer** | Read only records a patient explicitly shared | Ever write a clinical record |
| **Admin** | Assign hospital/insurer roles, pause the contract | **Read any record** |

That last cell is deliberate. An administrator who can grant themselves access
to any record defeats the point of the system, so there is no admin override on
`grantAccess` — only the patient can authorise access to their own data.

## What revocation actually does

Revoking access stops **future** reads of the pointer. It cannot un-read data
already fetched and decrypted, and it cannot claw back a copy.

Any system claiming otherwise is misrepresenting what a blockchain can enforce.
Real revocation needs off-chain key rotation and re-encryption; this contract
enforces the authorisation layer only. There is a test asserting this
forward-only behaviour rather than pretending it away.

## On the read guard

`getRecord` is a `view` function, so its access check is advisory against a
determined observer — anyone can read contract storage directly off a public
chain. Confidentiality comes from the payload being encrypted off-chain, not
from this check.

The check still earns its place: honest clients cannot accidentally over-reach,
and the authorisation state itself becomes auditable on-chain.

## Testing

Access-control contracts are judged on what they **refuse**, not what they
allow. Most of this suite asserts a revert:

- A hospital with no grant, or with read-only access, cannot write
- An insurer cannot write even when granted write permission — the role gate
  stops it before the permission check
- A second hospital cannot read records it didn't author
- A record-level share exposes *that record only*, not the patient's history
- An insurer trusted by patient B cannot reach patient A's records
- Revocation blocks further reads and writes
- Pausing blocks writes but **still allows revocation** — a patient must be able
  to withdraw consent during an incident freeze, or the pause switch becomes a
  weapon against them

## Running it

```bash
npm install
npm test
```

Gas report:

```bash
npm run gas
```

## Repo layout

```
├── contracts/MedicalRecords.sol
├── test/MedicalRecords.test.js
├── results/gas-report.txt
└── hardhat.config.js
```

## Limitations

- **Not audited.** Access-control bugs are the classic smart-contract failure
  mode. This is a portfolio project, not production code, and it has had no
  formal review.
- **Never deployed to a public testnet.** Everything runs against Hardhat's
  in-process network.
- **No key management.** The contract assumes payloads are encrypted off-chain
  and says nothing about how keys reach authorised parties — which is the
  genuinely hard part of the problem.
- **Gas costs grow with the number of grants**, and a patient with many
  providers pays for each. Batched grants or a Merkle-root approach would be
  the next step.
- **No emergency clinical access.** Real systems need break-glass access for
  unconscious patients; a design where consent is strictly required has an
  obvious failure mode in an emergency room, and this contract does not solve it.
- **The AI in the original project title is absent here.** This is the access
  control layer only. Naming it "Decentralized AI" would be describing something
  that does not exist in the code.
