# World State View Update

## Abstract

### Motivation

To keep a constant access to a `World State View` and keep it sync
with a `Block Storage` at the same time we need to find away to
provide consistent and a very fast way to update `WSV`.

### Results

As a result we use message passing concurrency model via rust
asynchronous channels. A channel between `Kura` and `WSV` is used to
send updates of the `Block Storage` keeping ownership of `WSV` outside of the `Kura`.

### Conclusion

Message passing communication can provide an effective way to 
`WSV` updates keeping minimum overhead and small latency.

## Introduction

`Iroha` new data flows from clients and other peers through consensus into `Kura`.
`Kura` should not only commit this data into `Block Store`, it should also update
`World State View`. At the same time queries from clients and statefull validation of new
transactions should be able to read this state. We are looking for a performant way to
keep `World State View` in sync with `Block Store` not loosing compiler protection from
locks and shared memory related problems. 

## Methods

To find the most suitable way we should measure performance prototyping different solutions.

## Results

### futures::channel::mpsc


