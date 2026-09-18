The mini vault: every secret a project owns, encrypted, in one file.

A store this library owns outright rather than a client for a server
somebody else runs. It has a master key and restricted keys, and it is
the port's worked example of a definition publishing an API beside its
provider: a chain READS, and writing is a deliberate act with an
interface of its own.

```no_run
use voxgig_sekreto::{Options, ProviderSpec, Sekreto};
use voxgig_sekreto_minivault::{createvault, minivault, vaultof, VaultOptions};

let vault = createvault(&VaultOptions {
    file: "app.skmv".to_string(),
    passphrase: "master".to_string(),
    ..Default::default()
})
.unwrap();
vault.set("api.token", "tok01").unwrap();

let mut secrets = Sekreto::new(Options {
    plugins: vec![minivault()],
    providers: vec![ProviderSpec {
        kind: "minivault".to_string(),
        file: "app.skmv".to_string(),
        passphrase: "master".to_string(),
        ..Default::default()
    }],
    ..Default::default()
})
.unwrap();

let _ = secrets.get("api.token").unwrap();            // the chain reads
let _ = vaultof(&secrets, "").unwrap().list().unwrap(); // the API writes
```

A port of typescript/plugins/minivault.ts, which is canonical.
