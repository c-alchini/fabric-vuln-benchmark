# Fabric Vulnerability Benchmark

## Overview

This repository provides a purposely vulnerable Hyperledger Fabric chaincode designed for experimental evaluation of security and static analysis tools.

The contract was developed as a controlled benchmark artifact containing intentionally injected vulnerabilities commonly discussed in the context of Go-based chaincodes for permissioned blockchains. It is intended to support reproducible research on vulnerability detection and DevSecOps practices in Hyperledger Fabric environments.

This project is strictly for research and educational purposes and must not be used in production systems.

## Vulnerability Design
#### Platform-specific issues
* Read-after-write
* Phantom read
* Cross-channel invocation

#### Privacy data leakage
* Private data in arguments
* Private data in branch conditions
* Private data in return payloads

#### Internal non-determinism
* Global variable
* Struct field misuse
* Pointer usage (address storage)
* Timestamp storage
* Uncontrolled concurrency
* Iteration over maps (range over maps)

#### Common implementation flaws
* Unchecked parameters
* Unhandled errors
* Conversion overflow
* Arithmetic overflow