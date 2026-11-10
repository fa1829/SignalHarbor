# chall2026-the-varnyr-glitch

## 🛸 The Varnyr Glitch  
**ECDSA Private Key Recovery via Biased Nonce Generation & Lattice Attacks**

---

## Challenge Type
- [ ] Offline  
- [x] Online  

## Design Type
- [ ] Black-Box  
- [x] White-Box (cryptographic artifacts provided)

## Designer(s)
- Khandoker git Faisal

---

## Overview

**The Varnyr Glitch** is a cryptography challenge demonstrating a
*real-world ECDSA implementation failure* caused by **insufficient nonce entropy**.

Participants analyze cryptographic artifacts exposed through an internal
audit interface of the *Klumgon Interstellar Transfer Gateway* (KIT),
discovering that ECDSA nonces were generated with reduced entropy.
This weakness allows recovery of the Overseer's private key using
**lattice-based cryptanalysis**.

The challenge mirrors failures seen in:
- fintech payment systems
- hardware wallets
- blockchain signing software
- embedded authentication services

---

## Educational Goals

Participants will learn to:

1. Understand ECDSA signing internals  
2. Identify why nonce unpredictability is critical  
3. Recognize partial nonce leakage scenarios  
4. Model ECDSA signatures as a **Hidden Number Problem (HNP)**  
5. Apply **LLL lattice reduction** to recover secret keys  
6. Appreciate how *implementation flaws*, not broken math, cause real breaches

---

## Skills Tested

- API reconnaissance  
- White-box cryptographic analysis  
- Modular arithmetic & ECDSA equations  
- Hidden Number Problem formulation  
- Lattice construction & LLL reduction  
- Practical use of **SageMath** (or equivalent tooling)

---

## Real-World Relevance

Similar vulnerabilities have caused catastrophic failures in:

- **PlayStation 3 ECDSA** (2010)  
- **Android Bitcoin wallets** (2013)  
- Hardware wallet firmware bugs  
- Payment & authentication systems using weak PRNGs  

This challenge aligns directly with **Interac's fintech security focus**:
it demonstrates how subtle entropy mistakes in transaction signing
can lead to complete system compromise.

---

## Difficulty

- **Category:** Crypto  
- **Difficulty:** Medium → Hard  
- **Estimated Points:** ~400  
- **Expected Solve Rate:** 15–25%  
- **Average Solve Time:** 2–4 hours (advanced crypto participants)

---

## Category(ies)

- [x] `crypto`  
- [ ] `web`  
- [ ] `pwn`  
- [ ] `re`  
- [ ] `misc`

---

## Project Structure

```
chall2026-the-varnyr-glitch/
├── HACKME.md                      # Participant-facing story & intro
├── README.md                      # Organizer & reviewer documentation
├── offline-artifacts/             # Offline challenge artifacts (if any)
│   └── .gitkeep
├── solution/
│   ├── solve_sage.py             # Reference lattice solution
│   ├── solution.md               # Complete solution walkthrough
│   ├── Dockerfile.sage           # Solver container (SageMath)
│   └── FLAGS.md                  # Flag + solver instructions
└── source/
    ├── server.py                 # Online challenge server
    ├── templates/
    │   └── index.html            # Narrative frontend + submission UI
    ├── data/
    │   ├── signatures.json       # Exported ECDSA signatures
    │   └── signatures.meta.json  # Signature metadata
    ├── Dockerfile
    ├── docker-compose.yml
    ├── requirements.txt
    └── README.md
```

---

## Intended Solve Flow (High-Level)

1. Player visits the KIT gateway landing page  
2. Reconnaissance reveals internal audit endpoints  
3. Audit export exposes ECDSA `(r, s, z)` signature data  
4. Signature metadata hints at reduced nonce entropy  
5. Player identifies nonce MSB bias / entropy bound  
6. ECDSA equations are reformulated as a Hidden Number Problem  
7. A lattice is constructed using observed signatures  
8. **LLL reduction** recovers the private key  
9. The recovered key is submitted to the gateway  
10. The system authenticates and returns the flag  

---

## Cryptographic Core

- **Curve:** `secp256k1`
- **Vulnerability:** nonce entropy reduced (224 bits instead of 256)
- **Attack Class:** Hidden Number Problem (HNP)
- **Solution Technique:** Lattice reduction (LLL)

---

## References

1. P. Q. Nguyen, I. E. Shparlinski,  
   *The Insecurity of the Digital Signature Algorithm with Partially Known Nonces*,  
   Journal of Cryptology, 2002.

2. N. Howgrave-Graham,  
   *Finding Small Roots of Univariate Modular Equations Revisited*,  
   Cryptography and Coding, 1997.

3. D. J. Bernstein et al.,  
   *Understanding Cryptographic Failures in ECDSA*.

---

## Quick Start (Organizers / Reviewers)

### Running the Challenge Server

```bash
cd source/
docker compose down
docker compose build --no-cache
docker compose up -d
```

### Verify Server Status

```bash
curl http://localhost:13337/api/status
```

**Expected Response:**
```json
{
  "service": "Klumgon Interstellar Transfer Gateway",
  "protocol": "Varnyr-Sig",
  "curve": "secp256k1",
  "audit": "NONCE ENTROPY REDUCTION DETECTED"
}
```

### Testing the Solution

```bash
cd solution/

# Using Docker with SageMath
docker build -f Dockerfile.sage -t varnyr-solver .
docker run --rm -v $(pwd)/../source/data:/solver/source/data varnyr-solver

# Or run directly with SageMath installed
sage solve_sage.py
```

---

## Flag Format

`ATHACKCTF{...}`

---

## Recent Changes

### Version 1.1 (Feb 2026)
- ✅ Added `offline-artifacts/` folder per template requirements
- ✅ Shortened `HACKME.md` from 65 lines to 9 lines
- ✅ Reduced excessive hints in frontend (`index.html`)
- ✅ Simplified `signatures.meta.json` to remove step-by-step progression hints
- ✅ Added comprehensive `solution.md` walkthrough
- ✅ Streamlined `FLAGS.md` to remove overly detailed solving steps

### Version 1.0 (Initial Release)
- Initial challenge design and implementation

---

## Notes for Organizers

### Deployment

The challenge runs as a Flask web service on port 13337. No external dependencies beyond Docker are required for deployment.

### Difficulty Tuning

The challenge difficulty can be adjusted by:
- Reducing/increasing the number of provided signatures
- Adjusting the nonce entropy (currently 224 bits)
- Modifying the metadata hints in `signatures.meta.json`

### Solution Validation

The private key is hardcoded in `source/server.py`:
```python
PRIVATE_KEY_INT = int(
    "fffffffffffffffffffffffffffffffd755db9cd5e9140777fa4bd19a06c8283",
    16,
)
```

Flag is returned when this exact key is submitted via the `/api/submit` endpoint.

---

## Support

For questions or issues, contact the challenge designer or open an issue in the repository.
