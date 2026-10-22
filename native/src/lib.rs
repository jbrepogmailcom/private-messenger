//! Narrow Python binding to upstream libsignal-protocol, not a messaging engine.
//! No networking, filesystem, logging backend, cipher implementation or ratchet
//! implementation is present here. All state is returned to Python for its one
//! encrypted transaction; failures return no state transition.

use futures::executor::block_on;
use libsignal_protocol::*;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use rand::{Rng, TryRngCore};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use zeroize::Zeroize as _;

type Result<T> = std::result::Result<T, SignalProtocolError>;

// Read-only status projection of the pinned upstream pq_ratchet.proto, fields
// PqRatchetState.chain (2), Chain.current_epoch (2) and Chain.send_epoch (5).
// Unknown fields, including key material, are discarded by prost. This probe
// never drives a cryptographic operation or changes the upstream state.
#[derive(prost::Message)]
struct PqStatus {
    #[prost(message, optional, tag = "2")]
    chain: Option<ChainStatus>,
}
#[derive(prost::Message)]
struct ChainStatus {
    #[prost(uint64, tag = "2")]
    current_epoch: u64,
    #[prost(uint64, tag = "5")]
    send_epoch: u64,
}

#[derive(Clone, Serialize, Deserialize)]
struct State {
    identity: Vec<u8>,
    registration_id: u32,
    local_address: String,
    peer_address: Option<String>,
    peer_identity: Option<Vec<u8>>,
    session: Option<Vec<u8>>,
    prekey: Option<Vec<u8>>,
    signed_prekey: Option<Vec<u8>>,
    kem_prekey: Option<Vec<u8>>,
}

fn clear_secret(value: &mut Option<Vec<u8>>) {
    if let Some(mut bytes) = value.take() {
        bytes.zeroize();
    }
}

impl Drop for State {
    fn drop(&mut self) {
        self.identity.zeroize();
        clear_secret(&mut self.session);
        clear_secret(&mut self.prekey);
        clear_secret(&mut self.signed_prekey);
        clear_secret(&mut self.kem_prekey);
    }
}

#[derive(Serialize, Deserialize)]
struct Bundle {
    registration_id: u32,
    identity: Vec<u8>,
    prekey: Vec<u8>,
    signed_prekey: Vec<u8>,
    signed_signature: Vec<u8>,
    kem: Vec<u8>,
    kem_signature: Vec<u8>,
}

fn bad() -> SignalProtocolError {
    SignalProtocolError::InvalidArgument("invalid private-messenger crypto input".into())
}

fn address(name: &str) -> Result<ProtocolAddress> {
    if name.is_empty() || name.len() > 128 {
        return Err(bad());
    }
    Ok(ProtocolAddress::new(
        name.to_owned(),
        DeviceId::new(1).map_err(|_| bad())?,
    ))
}

fn load(state: &State) -> Result<InMemSignalProtocolStore> {
    let pair = IdentityKeyPair::try_from(state.identity.as_slice())?;
    let mut store = InMemSignalProtocolStore::new(pair, state.registration_id)?;
    block_on(async {
        if let Some(name) = &state.peer_address {
            let peer = address(name)?;
            if let Some(key) = &state.peer_identity {
                store
                    .save_identity(&peer, &IdentityKey::decode(key)?)
                    .await?;
            }
            if let Some(record) = &state.session {
                store
                    .store_session(&peer, &SessionRecord::deserialize(record)?)
                    .await?;
            }
        }
        if let Some(key) = &state.prekey {
            store
                .save_pre_key(1.into(), &PreKeyRecord::deserialize(key)?)
                .await?;
        }
        if let Some(key) = &state.signed_prekey {
            store
                .save_signed_pre_key(1.into(), &SignedPreKeyRecord::deserialize(key)?)
                .await?;
        }
        if let Some(key) = &state.kem_prekey {
            store
                .save_kyber_pre_key(1.into(), &KyberPreKeyRecord::deserialize(key)?)
                .await?;
        }
        Ok(store)
    })
}

fn finish(state: &mut State, store: &InMemSignalProtocolStore) -> Result<()> {
    let peer = address(state.peer_address.as_deref().ok_or_else(bad)?)?;
    block_on(async {
        let record = store.load_session(&peer).await?.ok_or_else(bad)?;
        if record.session_version()? != 4 || record.current_pq_state().is_none_or(|p| p.is_empty())
        {
            return Err(bad());
        }
        // Both endpoints must use SPQR v1; no classical-only fallback is accepted.
        match spqr::current_version(record.current_pq_state().ok_or_else(bad)?)
            .map_err(|_| bad())?
        {
            spqr::CurrentVersion::StillNegotiating {
                version: spqr::Version::V1,
                min_version: spqr::Version::V1,
            }
            | spqr::CurrentVersion::NegotiationComplete(spqr::Version::V1) => {}
            _ => return Err(bad()),
        }
        state.peer_identity = Some(record.remote_identity_key_bytes()?.ok_or_else(bad)?);
        let serialized = record.serialize()?;
        clear_secret(&mut state.session);
        state.session = Some(serialized);
        // Every application invitation is one-use, not an upstream last-resort key.
        // Delete superseded setup records instead of retaining private prekeys.
        clear_secret(&mut state.prekey);
        clear_secret(&mut state.signed_prekey);
        clear_secret(&mut state.kem_prekey);
        Ok(())
    })
}

fn generate(local_address: String) -> Result<serde_json::Value> {
    address(&local_address)?;
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let identity = IdentityKeyPair::generate(&mut rng);
    let prekey = KeyPair::generate(&mut rng);
    let signed = KeyPair::generate(&mut rng);
    let kem = kem::KeyPair::generate(kem::KeyType::MLKEM1024, &mut rng);
    let signed_signature = identity
        .private_key()
        .calculate_signature(&signed.public_key.serialize(), &mut rng)?;
    let kem_signature = identity
        .private_key()
        .calculate_signature(&kem.public_key.serialize(), &mut rng)?;
    let registration_id = rng.random_range(1..16380);
    let timestamp = Timestamp::from_epoch_millis(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| bad())?
            .as_millis() as u64,
    );
    let state = State {
        identity: identity.serialize().into_vec(),
        registration_id,
        local_address,
        peer_address: None,
        peer_identity: None,
        session: None,
        prekey: Some(PreKeyRecord::new(1.into(), &prekey).serialize()?),
        signed_prekey: Some(
            SignedPreKeyRecord::new(1.into(), timestamp, &signed, &signed_signature).serialize()?,
        ),
        kem_prekey: Some(
            KyberPreKeyRecord::new(1.into(), timestamp, &kem, &kem_signature).serialize()?,
        ),
    };
    let bundle = Bundle {
        registration_id,
        identity: identity.identity_key().serialize().into_vec(),
        prekey: prekey.public_key.serialize().into_vec(),
        signed_prekey: signed.public_key.serialize().into_vec(),
        signed_signature: signed_signature.into_vec(),
        kem: kem.public_key.serialize().into_vec(),
        kem_signature: kem_signature.into_vec(),
    };
    Ok(serde_json::json!({"state": state, "bundle": bundle}))
}

fn initiate(mut state: State, peer_address: String, bundle: Bundle) -> Result<State> {
    if state.session.is_some()
        || state.peer_address.is_some()
        || peer_address == state.local_address
    {
        return Err(bad());
    }
    let peer_key = IdentityKey::decode(&bundle.identity)?;
    let kem = kem::PublicKey::deserialize(&bundle.kem)?;
    if kem.key_type() != kem::KeyType::MLKEM1024 {
        return Err(bad());
    }
    let prekeys = PreKeyBundle::new(
        bundle.registration_id,
        DeviceId::new(1).map_err(|_| bad())?,
        Some((1.into(), PublicKey::deserialize(&bundle.prekey)?)),
        1.into(),
        PublicKey::deserialize(&bundle.signed_prekey)?,
        bundle.signed_signature,
        1.into(),
        kem,
        bundle.kem_signature,
        peer_key,
    )?;
    state.peer_address = Some(peer_address);
    state.peer_identity = Some(peer_key.serialize().into_vec());
    let mut store = load(&state)?;
    block_on(process_prekey_bundle(
        &address(state.peer_address.as_deref().ok_or_else(bad)?)?,
        &address(&state.local_address)?,
        &mut store.session_store,
        &mut store.identity_store,
        &prekeys,
        SystemTime::now(),
        &mut rand::rngs::OsRng.unwrap_err(),
    ))?;
    finish(&mut state, &store)?;
    Ok(state)
}

fn encrypt(mut state: State, plaintext: Vec<u8>) -> Result<serde_json::Value> {
    if plaintext.len() > 12000 {
        return Err(bad());
    }
    let mut store = load(&state)?;
    let peer = address(state.peer_address.as_deref().ok_or_else(bad)?)?;
    let message = block_on(message_encrypt(
        &plaintext,
        &peer,
        &address(&state.local_address)?,
        &mut store.session_store,
        &mut store.identity_store,
        SystemTime::now(),
        &mut rand::rngs::OsRng.unwrap_err(),
    ))?;
    finish(&mut state, &store)?;
    Ok(
        serde_json::json!({"state":state,"message_type": message.message_type() as u8,
        "ciphertext": message.serialize()}),
    )
}

fn decrypt(
    mut state: State,
    peer_address: String,
    message_type: u8,
    ciphertext: Vec<u8>,
) -> Result<serde_json::Value> {
    if ciphertext.len() > 16048 || peer_address == state.local_address {
        return Err(bad());
    }
    match &state.peer_address {
        Some(name) if *name != peer_address => return Err(bad()),
        None => state.peer_address = Some(peer_address),
        _ => {}
    }
    let message = match message_type {
        2 => CiphertextMessage::SignalMessage(SignalMessage::try_from(ciphertext.as_slice())?),
        3 => {
            let message = PreKeySignalMessage::try_from(ciphertext.as_slice())?;
            if state.session.is_none()
                && message
                    .kyber_ciphertext()
                    .is_none_or(|c| c.first() != Some(&0x0A))
            {
                return Err(bad());
            }
            CiphertextMessage::PreKeySignalMessage(message)
        }
        _ => return Err(bad()),
    };
    let mut store = load(&state)?;
    let plaintext = block_on(message_decrypt(
        &message,
        &address(state.peer_address.as_deref().ok_or_else(bad)?)?,
        &address(&state.local_address)?,
        &mut store.session_store,
        &mut store.identity_store,
        &mut store.pre_key_store,
        &store.signed_pre_key_store,
        &mut store.kyber_pre_key_store,
        &mut rand::rngs::OsRng.unwrap_err(),
    ))?;
    finish(&mut state, &store)?;
    Ok(serde_json::json!({"state":state,"plaintext":plaintext}))
}

fn dispatch(input: &str) -> Result<serde_json::Value> {
    if input.len() > 4 * 1024 * 1024 {
        return Err(bad());
    }
    let value: serde_json::Value = serde_json::from_str(input).map_err(|_| bad())?;
    let op = value.get("op").and_then(|v| v.as_str()).ok_or_else(bad)?;
    let string = |key: &str| -> Result<String> {
        Ok(value
            .get(key)
            .and_then(|v| v.as_str())
            .ok_or_else(bad)?
            .to_owned())
    };
    let state = || -> Result<State> {
        serde_json::from_value(value.get("state").ok_or_else(bad)?.clone()).map_err(|_| bad())
    };
    let bytes = |key: &str| -> Result<Vec<u8>> {
        serde_json::from_value(value.get(key).ok_or_else(bad)?.clone()).map_err(|_| bad())
    };
    match op {
        "metadata" => Ok(
            serde_json::json!({"initial_kem":"ML-KEM-1024", "ratchet":"Triple Ratchet",
            "pq_ratchet":"SPQR v1 / ML-KEM-768", "upstream":"b369755533ef5a3fae9b31b989114f22e074dfab"}),
        ),
        "generate" => generate(string("local_address")?),
        "initiate" => Ok(
            serde_json::json!({"state": initiate(state()?, string("peer_address")?,
            serde_json::from_value(value.get("bundle").ok_or_else(bad)?.clone()).map_err(|_| bad())?)?}),
        ),
        "encrypt" => encrypt(state()?, bytes("plaintext")?),
        "decrypt" => decrypt(
            state()?,
            string("peer_address")?,
            value
                .get("message_type")
                .and_then(|v| v.as_u64())
                .and_then(|v| u8::try_from(v).ok())
                .ok_or_else(bad)?,
            bytes("ciphertext")?,
        ),
        "sign" => {
            let pair = IdentityKeyPair::try_from(state()?.identity.as_slice())?;
            let sig = pair
                .private_key()
                .calculate_signature(&bytes("message")?, &mut rand::rngs::OsRng.unwrap_err())?;
            Ok(serde_json::json!({"signature":sig.as_ref()}))
        }
        "verify" => {
            let key = IdentityKey::decode(&bytes("identity")?)?;
            Ok(
                serde_json::json!({"valid":key.public_key().verify_signature(&bytes("message")?, &bytes("signature")?)}),
            )
        }
        "fingerprint_public" => {
            let own = IdentityKey::decode(&bytes("local_identity")?)?;
            let peer = IdentityKey::decode(&bytes("peer_identity")?)?;
            let fp = Fingerprint::new(
                2,
                5200,
                string("local_address")?.as_bytes(),
                &own,
                string("peer_address")?.as_bytes(),
                &peer,
            )
            .map_err(|_| bad())?;
            Ok(serde_json::json!({"fingerprint":fp.display_string().map_err(|_|bad())?}))
        }
        "status" => {
            use prost::Message as _;
            let state = state()?;
            let record = SessionRecord::deserialize(state.session.as_deref().ok_or_else(bad)?)?;
            let pqr = record.current_pq_state().ok_or_else(bad)?;
            let negotiated = matches!(
                spqr::current_version(pqr).map_err(|_| bad())?,
                spqr::CurrentVersion::NegotiationComplete(spqr::Version::V1)
            );
            let status = PqStatus::decode(pqr.as_slice()).map_err(|_| bad())?;
            let epoch = status.chain.map(|c| (c.current_epoch, c.send_epoch));
            Ok(
                serde_json::json!({"session_version": record.session_version()?,
                "spqr_v1_negotiated":negotiated,"pq_epoch":epoch.map(|v|v.0),
                "pq_send_epoch":epoch.map(|v|v.1)}),
            )
        }
        "fingerprint" => {
            let state = state()?;
            let own = IdentityKeyPair::try_from(state.identity.as_slice())?;
            let peer = IdentityKey::decode(state.peer_identity.as_deref().ok_or_else(bad)?)?;
            let fp = Fingerprint::new(
                2,
                5200,
                state.local_address.as_bytes(),
                own.identity_key(),
                state.peer_address.as_deref().ok_or_else(bad)?.as_bytes(),
                &peer,
            )
            .map_err(|_| bad())?;
            Ok(serde_json::json!({"fingerprint":fp.display_string().map_err(|_| bad())?}))
        }
        _ => Err(bad()),
    }
}

#[pyfunction]
fn operation(input: &str) -> PyResult<String> {
    // Never expose upstream error strings: some include identity/ratchet metadata.
    dispatch(input)
        .and_then(|v| serde_json::to_string(&v).map_err(|_| bad()))
        .map_err(|_| PyValueError::new_err("cryptographic operation failed"))
}

#[pymodule]
fn _crypto_native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(operation, module)?)?;
    module.add(
        "UPSTREAM_REVISION",
        "b369755533ef5a3fae9b31b989114f22e074dfab",
    )?;
    Ok(())
}
