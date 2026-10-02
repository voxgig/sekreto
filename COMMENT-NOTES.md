# Implementation rationale

Provider resolution and explicit vault mutation are separate APIs. Restricted vault keys enforce their grants, and an invalid credential must fail rather than fall through the provider chain as a missing value.

The core library's dependency boundary and explicit provider registration are documented in the [agent guide](AGENTS.md).

Check corpus shape separately from generating the JSON consumed by every port. Unifying the shape during generation can omit optional empty containers and alter assertions.

The Rust library sources read no file outside their crate's `src/` at compile time. `@voxgig/sdkgen` vendors those files alone into each generated SDK as modules, where an `include_str!` of a document beside the crate does not resolve. The mini vault crate root therefore carries no crate-level documentation: a description and a usage example are in `rust/README.md`, and `rust/plugins/minivault/tests/minivault.rs` exercises the same API.
