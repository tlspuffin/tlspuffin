---
title: 'Adding differential fuzzing to a protocol'
---

Adding differential fuzzing to a protocol fuzzer require adapting both the mapper and the PUTs.

## Protocol level

At the protocol level, you have to set up how to compare knowledge and claims and how to decrypt encrypted messages.

### Knowledge comparison

In order to compare knowledge all randomized types and fields must be ignored. There are two distinct mechanisms to do this:

+ A blacklist/whitelist for types present in the `KnowledgeStore`
+ Code annotations to compare fields in comparable types

#### Types to compare

Whitelisting types is done in the implementation of the `ProtocolTypes` trait using and `differential_fuzzing_whitelist`.
This function return an `Option<Vec<TypeId>>`. In the case of Rustls, the only type of clear text message is `MessagePayload` so we can just add this type to our whitelist and all other types would be ignored:

```rust
fn differential_fuzzing_whitelist() -> Option<Vec<TypeId>> {
    Some(vec![TypeId::of::<MessagePayload>()])
}
```

On the contrary if only some types corresponds to encrypted messages, you can use the blacklist to ignore those.


#### Comparing protocol messages


The first step to compare your protocol types is to make them comparable using the `Comparable` crate. To do that just use `#[derive(Comparable)]` on your type. Make sure all of its subtypes also derives from `Comparable`.

```rust
#[derive(Debug, Clone, Extractable, Comparable)]
#[extractable(TLSProtocolTypes)]
pub struct ServerHelloPayload {
    pub legacy_version: ProtocolVersion,
    pub random: Random,
    pub session_id: SessionID,
    pub cipher_suite: CipherSuite,
    pub compression_method: Compression,
    pub extensions: ServerExtensions,
}
```

Now if we want to ignore some fields which values are randomized between execution we can add a `#[comparable_ignore]` annotation:

```rust
#[derive(Debug, Clone, Extractable, Comparable)]
#[extractable(TLSProtocolTypes)]
pub struct ServerHelloPayload {
    pub legacy_version: ProtocolVersion,
    #[comparable_ignore]
    pub random: Random,
    #[comparable_ignore]
    pub session_id: SessionID,
    pub cipher_suite: CipherSuite,
    pub compression_method: Compression,
    pub extensions: ServerExtensions,
}
```

And finally, if some fields needs to be transformed to be compared, for example if you want to sort a list before comparing it, you can create a `#[comparable_synthetic]` field that will apply the transformation and ignore the original field. 

```rust
#[derive(Debug, Clone, Extractable, Comparable)]
#[extractable(TLSProtocolTypes)]
pub struct ServerHelloPayload {
    #[comparable_synthetic {
        let sorted_extensions = |x: &Self| -> ServerExtensions {
            let mut ext = x.extensions.clone();
            ext.0.sort_by(puffin::codec::compare_encoding);
            ext
        };
    }]
    pub legacy_version: ProtocolVersion,
    #[comparable_ignore]
    pub random: Random,
    #[comparable_ignore]
    pub session_id: SessionID,
    pub cipher_suite: CipherSuite,
    pub compression_method: Compression,
    #[comparable_ignore]
    pub extensions: ServerExtensions,
}
```

### Claim comparison

Claim comparison require similar work to the knowledge comparison. Some types of claims can be blacklisted using `ProtocolTypes::differential_fuzzing_claims_blacklist()` and randomized content could be ignored using `#[comparable_ignore]`.

### Decryption recipe

To try to decrypt encrypted messages exchanged during the session, you can provide some decryption terms that will use the secrets collected through the claims.

This might require to extract some new internal states from the PUTs and add them to the claims in order to have all the required elements to decrypt the messages.

Those terms should be provided by `ProtocolTypes::differential_fuzzing_terms_to_eval`. This function takes the list of agents of the trace as parameter to determine which message should be taken from which agent.

Example of TLS message decryption recipes:

```rust
fn differential_fuzzing_terms_to_eval(
        agents: &Vec<AgentDescriptor<Self::PUTConfig>>,
    ) -> Vec<puffin::algebra::Term<Self>> {
        let mut is_server = false;
        let mut server = AgentName::new();
        let mut is_client = false;
        let mut client = AgentName::new();

        for agent in agents {
            if agent.protocol_config.typ == AgentType::Server {
                is_server = true;
                server = agent.name;
            } else if agent.protocol_config.typ == AgentType::Client {
                is_client = true;
                client = agent.name;
            }
        }

        let mut terms = vec![];

        if is_server {
            terms.push(term! {
                fn_decrypt_handshake_flight_with_secret(
                K((server, 0)[Some(TlsQueryMatcher::ServerHelloFlight)]/MessageFlight),
                (fn_server_hello_transcript(C((server, 0)))),
                fn_true,
                fn_seq_0,  // sequence 0
                (fn_finished_get_client_random(C((server, 0)))),
                (fn_finished_get_cipher(C((server, 0)))),
                (fn_finished_get_handshake_secret(C((server, 2))))
            )
            });
        }

        if is_client {
            terms.push(term! {
                fn_decrypt_handshake_flight_with_secret(
                K((client, 0)[Some(TlsQueryMatcher::EncryptedFlight)]/MessageFlight),
                (fn_server_hello_transcript(C((client, 0)))),
                fn_false,
                fn_seq_0,
                (fn_finished_get_client_random(C((client, 0)))),
                (fn_finished_get_cipher(C((client, 0)))),
                (fn_finished_get_handshake_secret(C((client, 0))))
            )
            });
        }

        terms
    }    
```



## PUT level

If the protocol offer some customization (e.g. cipher selection, extension, ...), you have to make sure that all your PUTs share a common set of parameters. Those parameters should be provided to the PUT using fields in the agent `protocol_config`.

Puffin's differential fuzzing API provide `differential_fuzzing_uniformise_put_config` in `TLSProtocolTypes` to override the default  agents protocol configurations when generating the seeds with `--differential`.

Some of those configuration options might come as compilation flags, which can't be set at run time. You may want to create new PUT compilation presets for differential fuzzing to also keep a default configuration for standard DY fuzzing.
