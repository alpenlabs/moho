# Moho

This repository contains the infrastructure for the inductive proof mechanism
within Strata.  This is essential for implementing snap sync, upgrades, and
other essential features low down on the stack.

## Moho design

The external interface of the Moho proof is a mechanism to prove that, by
starting from an input `R_0` and a state `S_0` we can reach a state `R_i` and
`S_i`, where there's some way to verify a chain of inputs from `R_0` to `R_i`.
Each step of the state transition can control the next state transition computed
on their outputs, but these changes are hidden away in the inductive proof.

A more extensive design document will be released, detailing these pieces in
more formal language.

## Repository structure

While this repository implements the spec that we are working on internally,
there are some pieces in this repo that support downstream uses.

In particular is the "proof runtime".  This is a framework we expect downstream
consumers of the Moho proof will use to aid in writing the inner proof that the
Moho proof inductively verifies.  It's not strictly part of the Moho design
itself, but it provides useful infrastructure on top of the low-level proof
interface that supports using it to verify a state machine.  Consumers implement
the `MohoProgram` trait, defining state types and implementation logic, then
plug it into the proof runtime implementation within the proof program.

The recursive Moho proof itself lives in `crates/recursive-proof`. The SP1 guest
that runs it is in `guest-builder/sp1`. The build produces the guest ELF and the
SP1 Groth16 predicate, which consumers such as the bridge use as the trust
anchor for Moho proofs. Each release tag attaches these files to its GitHub
release, so downstream repos can use them without building the guest. See
[`guest-builder/sp1/README.md`](guest-builder/sp1/README.md) for the
prerequisites, how to build the files, and how to check a release.
