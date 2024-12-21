# Vote

This repository contains a cryptographically secure voting platform that implements homomorphic encryption, threshold encryption, and zero-knowledge proofs (ZKPs) for a secure and verifiable voting process. The platform includes the following components:

1. **Registrar:** Verifies that all voters are registered and can only vote once.
2. **Tallyer:** Validates votes during the tallying process.
3. **Arbiters:** Generate election parameters and collaboratively decrypt the final vote tally.
4. **Voters:** Cast votes, view election results, and verify the integrity of their votes.

Each component uses advanced cryptographic techniques to ensure the privacy, security, and fairness of the voting process.

## Installation
1. Install dependencies: Follow the instructions in the `INSTALL.md` file to install necessary cryptographic libraries and dependencies for your platform.
2. Build the Project: Use `make build` to build the project.
3. Run the Platform: After building the project, you can start the system by running the following commands for each component:
  - Start the registrar using `./registrar`.
  - Start the tallyer using `./tallyer`.
  - Start the arbiters using `./arbiters`.
  - Start the voters using `./voters`.

## Key Files
- `/src/registrar/registrar.go`: Contains the logic for voter registration and verification.
- `/src/tallyer/tallyer.go`: Manages the vote tallying process and vote validation.
- `/src/arbiter/arbiter.go`: Implements the arbiter protocol for collaborative decryption.
- `/src/voter/voter.go`: Handles the vote submission and viewing process for voters.
- `/crypto/homomorphic/encryption.go`: Contains the implementation of additively homomorphic encryption.
- `/crypto/threshold/encryption.go`: Implements threshold encryption for multi-party decryption.
- `/crypto/zkp/proofs.go`: Contains the implementation of zero-knowledge proofs used for vote validation.

## Cryptographic Techniques

### Additively Homomorphic Encryption

Additively homomorphic encryption allows parties to perform computations on encrypted data without needing to decrypt it first. In this system, voters encrypt their votes (1 or 0) using additively homomorphic encryption. The tallyer then performs the addition of encrypted votes without needing to decrypt them, preserving privacy.

For example, the encryption scheme used in this system is a variation of the ElGamal encryption scheme, which is additively homomorphic. The encryption of a vote is represented as a pair (`c1`, `c2`), and the tallying process combines encrypted votes using the homomorphic addition operation `HomAdd`.

### Threshold Encryption

Threshold encryption allows a ciphertext to be decrypted only when a predefined threshold number of parties (the arbiters) collaborate. This ensures that no single party has control over the decryption key, thereby increasing security.

The system uses threshold ElGamal encryption, where each arbiter holds a part of the secret key. The final decryption of the vote tally is performed by combining the partial decryptions from all the arbiters.

For more details, refer to the implementation in `/crypto/threshold/encryption.go`.

### Zero-Knowledge Proofs

Zero-knowledge proofs (ZKPs) allow a party (the prover) to prove to another party (the verifier) that they know a piece of information without revealing the actual information. In this system, ZKPs are used to ensure that a vote is valid (either 0 or 1) without revealing the actual vote.

The system implements the Disjunctive Chaum-Pedersen (DCP) protocol, a Sigma-OR protocol, which enables the voter to prove that their vote is either 0 or 1 without revealing which one. This proof ensures that no invalid votes are cast.

The implementation of ZKPs can be found in `/crypto/zkp/proofs.go`.

## Usage

### Voter Interaction

1. The registrar registers the voter and provides them with an encrypted vote.
2. The voter submits the encrypted vote, and the system generates a proof using ZKPs to ensure the vote is valid.
3. The arbiters use their shares of the secret key to decrypt the final vote tally once the election ends.

### Tallying Votes

The Tallyer component listens for vote submissions, verifies the validity of each vote, and updates the encrypted tally. The tally can be updated without revealing the individual votes using the homomorphic encryption scheme.

### Decrypting the Results

Once the election is over, the Arbiters collaborate to decrypt the final vote tally using threshold encryption, ensuring that no single party has full control over the decryption process.
