//! Snapshot-compromise experiment on upstream SPQR alone (no classical DH).
//! Honest peers continue with fresh OS randomness. The attacker sees all wire
//! messages and holds a full earlier endpoint state, but does not control the
//! subsequent endpoint or network. This is a behavioral test, not a proof.

use rand::TryRngCore as _;

#[test]
fn spqr_snapshot_cannot_follow_fresh_post_quantum_epochs() {
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let mut attacker_rng = rand::rngs::OsRng.unwrap_err();
    let auth_key = [0x42u8; 32]; // Public test seed; no initial secrecy is assumed here.
    let initial = |direction| {
        spqr::initial_state(spqr::Params {
            direction,
            version: spqr::Version::V1,
            min_version: spqr::Version::V1,
            auth_key: &auth_key,
            chain_params: spqr::ChainParams::default(),
        })
        .expect("valid parameters")
    };
    let mut alice = initial(spqr::Direction::A2B);
    let mut bob = initial(spqr::Direction::B2A);
    for _ in 0..160 {
        let sent = spqr::send(&alice, &mut rng).expect("Alice sends");
        alice = sent.state;
        let recv = spqr::recv(&bob, &sent.msg).expect("Bob receives");
        assert_eq!(sent.key, recv.key);
        bob = recv.state;
        let sent = spqr::send(&bob, &mut rng).expect("Bob sends");
        bob = sent.state;
        let recv = spqr::recv(&alice, &sent.msg).expect("Alice receives");
        assert_eq!(sent.key, recv.key);
        alice = recv.state;
    }
    let mut attacker = Some(alice.clone());
    let mut readable = 0;
    let mut first_unreadable = None;
    let mut new_private_entropy_observed = false;
    for round in 0..320 {
        let sent = spqr::send(&alice, &mut rng).expect("Alice sends");
        alice = sent.state;
        if let Some(snapshot) = attacker.take() {
            let guess = spqr::send(&snapshot, &mut attacker_rng).expect("attacker follows counter");
            new_private_entropy_observed |= sent.msg != guess.msg;
            attacker = Some(guess.state);
        }
        let recv = spqr::recv(&bob, &sent.msg).expect("Bob receives");
        assert_eq!(sent.key, recv.key);
        bob = recv.state;
        let sent = spqr::send(&bob, &mut rng).expect("Bob sends");
        bob = sent.state;
        let recv = spqr::recv(&alice, &sent.msg).expect("Alice receives");
        assert_eq!(sent.key, recv.key);
        alice = recv.state;
        if let Some(snapshot) = attacker.take() {
            match spqr::recv(&snapshot, &sent.msg) {
                Ok(guess) if guess.key == sent.key => {
                    readable += 1;
                    attacker = Some(guess.state);
                }
                _ => first_unreadable = Some(round),
            }
        }
    }
    assert!(
        readable > 0,
        "snapshot initially exposes some following keys"
    );
    assert!(
        new_private_entropy_observed,
        "honest endpoint sampled fresh KEM entropy"
    );
    assert!(
        first_unreadable.is_some(),
        "snapshot must lose access after fresh PQ epochs"
    );
    assert!(attacker.is_none());
    println!(
        "Standalone SPQR: snapshot readable for {readable} replies; first unreadable round {:?}",
        first_unreadable
    );
}
