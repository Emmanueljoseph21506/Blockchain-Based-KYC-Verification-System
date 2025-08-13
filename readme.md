# Blockchain-Based KYC Verification System

A decentralized Know Your Customer (KYC) verification system built on Stacks blockchain using Clarity smart contracts.

## Features

- Secure identity verification management
- Authorized verifier system
- Verification request handling
- Privacy-preserving verification checks
- Expiry-based verification status

## Contract Functions

### Administrative Functions
- `set-verifier`: Set a new verifier address
- `add-authorized-verifier`: Add new authorized verifier
- `remove-authorized-verifier`: Remove authorized verifier

### Verification Functions
- `verify-identity`: Create new KYC verification
- `revoke-verification`: Revoke existing verification
- `request-verification`: Request KYC verification
- `approve-verification-request`: Approve pending request
- `reject-verification-request`: Reject pending request

### Read Functions
- `get-verification-status`: Get full verification details
- `get-verification-request`: Get request details
- `is-verified`: Check if address is verified

## Usage

1. Deploy the contract using Clarinet
2. Set authorized verifiers using `add-authorized-verifier`
3. Users can request verification using `request-verification`
4. Authorized verifiers can verify identities using `verify-identity`
5. Services can check verification status using `is-verified`

## Security

- Only authorized verifiers can create/revoke verifications
- Verification status includes expiry timestamp
- Request system ensures user consent
```
