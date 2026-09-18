# Implementation rationale

Provider resolution and explicit vault mutation are separate APIs. Restricted vault keys enforce their grants, and an invalid credential must fail rather than fall through the provider chain as a missing value.

The Rust mini-vault usage example remains compiled as a documentation test through [the included crate documentation](rust/plugins/minivault/COMMENT-NOTES.md).

The core library's dependency boundary and explicit provider registration are documented in the [agent guide](AGENTS.md).

Check corpus shape separately from generating the JSON consumed by every port. Unifying the shape during generation can omit optional empty containers and alter assertions.
