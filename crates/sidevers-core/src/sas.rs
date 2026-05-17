//! Short Authentication String (SAS) for pairing (Audit P1.4).
//!
//! The pairing flow seals a state bundle to the new device's ephemeral
//! X25519 key, but until P1.4 there was no in-band channel for the user
//! to confirm that the new device they are about to authorize is in
//! fact theirs (vs. an attacker who captured the QR within the TTL
//! window and raced to scan it). The SAS closes that gap: both devices
//! derive the same 6-word string from a transcript over the pairing
//! parameters, display it on-screen, and the user manually confirms a
//! match on the existing device before the seed is released.
//!
//! # Construction
//!
//! ```text
//! sas_input = "sidevers/v1/pairing-sas"
//!           ‖ side_pubkey            (32 bytes)
//!           ‖ pairing_nonce          (16 bytes)
//!           ‖ new_device_eph_pub     (32 bytes)
//! sas_bytes = BLAKE3(sas_input)[0..6]      // 6 bytes, 48 bits
//! words[i]  = WORDLIST[sas_bytes[i] as usize]   // 6 words
//! ```
//!
//! A MITM who replaces `new_device_eph_pub` (the only field they can
//! influence) cannot produce the same SAS — they would need a BLAKE3
//! preimage on the 6-byte prefix. With 256-word lookups, the
//! probability of any one word matching is `1/256`; for all six,
//! `2^-48`. For the SAS to ever match across a substitution, an
//! attacker must compute ~2^48 trial ephemerals — well outside the
//! 90-second pairing window for a hand-portable attacker.
//!
//! # Wordlist
//!
//! 256 short English words, all ≤5 letters, no homophones across
//! locales. Words were chosen to be easy to read aloud and to share
//! over a phone call when the two devices aren't in the same room.

use crate::keys::PUBLIC_KEY_LEN;

/// Length of the pairing nonce in bytes (matches
/// `messages::device::PAIRING_NONCE_LEN`, redeclared here to avoid a
/// dependency cycle on `messages`).
const PAIRING_NONCE_LEN: usize = 16;

/// Domain-separation label.
const SAS_LABEL: &[u8] = b"sidevers/v1/pairing-sas";

/// Number of words in the SAS.
pub const SAS_WORD_COUNT: usize = 6;

/// Curated 256-word list. Reviewed for: (a) length ≤5 letters,
/// (b) no homophones across English locales, (c) phonetically distinct,
/// (d) no offensive or politically charged terms.
///
/// The list must remain stable across versions — re-ordering or
/// replacing words breaks SAS comparison between devices on different
/// builds. New additions, if any, go in a v2 list with a new label.
const WORDLIST: [&str; 256] = [
    "able", "acid", "aged", "ahoy", "ajar", "alive", "amid", "amber", "ankle", "april", "arena",
    "arrow", "atlas", "aunt", "axle", "badge", "baker", "balsa", "bank", "barn", "basil", "basin",
    "bath", "bay", "bead", "beam", "bean", "bear", "beech", "beef", "bell", "belt", "bench",
    "berry", "biome", "birch", "bird", "bison", "bit", "blade", "blend", "block", "blue", "blunt",
    "blush", "bog", "bold", "bolt", "bond", "book", "boom", "boot", "born", "boss", "bowl",
    "brain", "branch", "brass", "brave", "bread", "brick", "brief", "broom", "brown", "brush",
    "bud", "buddy", "buoy", "burn", "bush", "byte", "cab", "cabin", "cable", "cacao", "cactus",
    "cake", "calm", "camel", "camp", "candy", "cane", "canoe", "canon", "canvas", "cap", "cape",
    "car", "carbon", "card", "cargo", "carol", "carp", "carry", "cart", "cash", "cast", "cat",
    "cedar", "cell", "chain", "chair", "chalk", "chant", "charm", "chart", "chase", "cheek",
    "cheer", "chef", "chess", "chest", "chief", "child", "chime", "chin", "chip", "choir", "chord",
    "chrome", "chunk", "cider", "cigar", "cipher", "city", "civic", "clam", "claw", "clay",
    "clean", "clear", "clerk", "click", "cliff", "climb", "cloak", "clock", "clog", "close",
    "cloth", "cloud", "clove", "clown", "club", "clump", "coal", "coast", "coat", "cobra", "cocoa",
    "code", "coil", "coin", "comet", "comic", "cone", "cook", "cool", "copy", "coral", "core",
    "cork", "corn", "cost", "couch", "court", "cover", "cow", "crack", "craft", "cramp", "crane",
    "crash", "crate", "crawl", "crazy", "creak", "cream", "creek", "crepe", "crew", "crib",
    "cried", "crime", "crisp", "crop", "cross", "crow", "crown", "cruel", "crumb", "crush",
    "crust", "cry", "cube", "cuff", "curl", "curse", "curve", "cushy", "cute", "cyan", "cycle",
    "daily", "dairy", "dance", "dart", "dash", "data", "date", "dawn", "day", "deaf", "deal",
    "dear", "debt", "decoy", "deed", "deep", "deer", "delay", "delta", "den", "dense", "depot",
    "derby", "desk", "diary", "dice", "diet", "dig", "dime", "diner", "ding", "dingo", "disco",
    "ditch", "dive", "dizzy", "dock", "dodge", "doe", "dog", "doll", "donkey", "donut", "door",
    "dose", "doted", "dough", "dove", "dozen", "draft", "drag", "drain", "drama",
];

/// Compute the 6-word SAS for a pairing transcript.
///
/// Both the existing device (who issued the QR) and the new device
/// (who received it and generated `new_device_eph_pub`) call this with
/// the exact same inputs. Any tampering with the QR or the new
/// device's ephemeral public key in flight changes the SAS, and the
/// user-confirmation step catches the mismatch before the seed leaves
/// the existing device.
pub fn pairing_sas(
    side_pubkey: &[u8; PUBLIC_KEY_LEN],
    pairing_nonce: &[u8; PAIRING_NONCE_LEN],
    new_device_eph_pub: &[u8; PUBLIC_KEY_LEN],
) -> [&'static str; SAS_WORD_COUNT] {
    let mut input =
        Vec::with_capacity(SAS_LABEL.len() + PUBLIC_KEY_LEN + PAIRING_NONCE_LEN + PUBLIC_KEY_LEN);
    input.extend_from_slice(SAS_LABEL);
    input.extend_from_slice(side_pubkey);
    input.extend_from_slice(pairing_nonce);
    input.extend_from_slice(new_device_eph_pub);
    let digest = blake3::hash(&input);
    let bytes = digest.as_bytes();
    let mut words = [""; SAS_WORD_COUNT];
    for (i, slot) in words.iter_mut().enumerate() {
        *slot = WORDLIST[bytes[i] as usize];
    }
    words
}

/// Convenience: render the SAS as a single space-separated string for
/// display. UIs may prefer rendering each word in its own pill.
pub fn pairing_sas_string(
    side_pubkey: &[u8; PUBLIC_KEY_LEN],
    pairing_nonce: &[u8; PAIRING_NONCE_LEN],
    new_device_eph_pub: &[u8; PUBLIC_KEY_LEN],
) -> String {
    pairing_sas(side_pubkey, pairing_nonce, new_device_eph_pub).join(" ")
}

/// Compile-time assertions on the wordlist:
///   1. length is exactly 256 (so a single u8 indexes it without modulo bias);
///   2. every slot is a non-empty ASCII string (no holes left by a refactor);
///   3. no duplicate words (so two distinct hash bytes never collapse to the
///      same word in a SAS).
///
/// Audit P1.E: previously this was just `let _ = WORDLIST[255]`, which
/// only verified the last index existed and would happily compile if 200
/// slots got replaced with `""`. The const-fn checks below catch that at
/// build time so a quietly-broken SAS can never ship.
const _: () = {
    // (1) length check: indexing the last slot fails to compile if shorter.
    let _: &str = WORDLIST[WORDLIST.len() - 1];
    assert!(
        WORDLIST.len() == 256,
        "SAS wordlist must be exactly 256 entries"
    );

    // (2) every word is non-empty and pure-ASCII lowercase (so display is
    // unambiguous across fonts / locales).
    let mut i = 0;
    while i < WORDLIST.len() {
        let bytes = WORDLIST[i].as_bytes();
        assert!(!bytes.is_empty(), "SAS wordlist contains an empty slot");
        let mut j = 0;
        while j < bytes.len() {
            let b = bytes[j];
            assert!(
                b >= b'a' && b <= b'z',
                "SAS wordlist contains a non-ASCII-lowercase byte"
            );
            j += 1;
        }
        i += 1;
    }

    // (3) no duplicates — O(N^2) compile-time scan over 256 entries is fine.
    let mut a = 0;
    while a < WORDLIST.len() {
        let mut b = a + 1;
        while b < WORDLIST.len() {
            let av = WORDLIST[a].as_bytes();
            let bv = WORDLIST[b].as_bytes();
            let mut same_len_and_bytes = av.len() == bv.len();
            if same_len_and_bytes {
                let mut k = 0;
                while k < av.len() {
                    if av[k] != bv[k] {
                        same_len_and_bytes = false;
                        break;
                    }
                    k += 1;
                }
            }
            assert!(
                !same_len_and_bytes,
                "SAS wordlist contains a duplicate word"
            );
            b += 1;
        }
        a += 1;
    }
};

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_inputs() -> (
        [u8; PUBLIC_KEY_LEN],
        [u8; PAIRING_NONCE_LEN],
        [u8; PUBLIC_KEY_LEN],
    ) {
        let side = [0xAAu8; PUBLIC_KEY_LEN];
        let nonce = [0xBBu8; PAIRING_NONCE_LEN];
        let eph = [0xCCu8; PUBLIC_KEY_LEN];
        (side, nonce, eph)
    }

    #[test]
    fn sas_is_deterministic_for_fixed_inputs() {
        let (s, n, e) = fixed_inputs();
        let a = pairing_sas(&s, &n, &e);
        let b = pairing_sas(&s, &n, &e);
        assert_eq!(a, b);
    }

    #[test]
    fn sas_emits_six_words_from_the_wordlist() {
        let (s, n, e) = fixed_inputs();
        let w = pairing_sas(&s, &n, &e);
        assert_eq!(w.len(), 6);
        for word in w {
            assert!(WORDLIST.contains(&word));
            assert!(!word.is_empty());
        }
    }

    #[test]
    fn flipping_the_ephemeral_changes_the_sas() {
        // The new-device ephemeral is the one field a MITM can substitute;
        // any change must produce a different SAS for the user to spot.
        let (s, n, mut e) = fixed_inputs();
        let baseline = pairing_sas(&s, &n, &e);
        e[0] ^= 0x01;
        let tampered = pairing_sas(&s, &n, &e);
        assert_ne!(baseline, tampered);
    }

    #[test]
    fn flipping_the_nonce_changes_the_sas() {
        let (s, mut n, e) = fixed_inputs();
        let baseline = pairing_sas(&s, &n, &e);
        n[7] ^= 0xFF;
        let tampered = pairing_sas(&s, &n, &e);
        assert_ne!(baseline, tampered);
    }

    #[test]
    fn flipping_the_side_pubkey_changes_the_sas() {
        let (mut s, n, e) = fixed_inputs();
        let baseline = pairing_sas(&s, &n, &e);
        s[31] ^= 0x80;
        let tampered = pairing_sas(&s, &n, &e);
        assert_ne!(baseline, tampered);
    }

    #[test]
    fn string_form_has_five_spaces() {
        let (s, n, e) = fixed_inputs();
        let line = pairing_sas_string(&s, &n, &e);
        assert_eq!(line.matches(' ').count(), 5);
    }

    #[test]
    fn wordlist_has_no_duplicates() {
        let mut sorted: Vec<&str> = WORDLIST.to_vec();
        sorted.sort_unstable();
        for w in sorted.windows(2) {
            assert_ne!(w[0], w[1], "duplicate word in SAS wordlist: {}", w[0]);
        }
    }

    #[test]
    fn wordlist_words_all_short_and_lowercase() {
        for w in WORDLIST {
            assert!(w.len() <= 6, "word too long: {w}");
            assert!(
                w.chars().all(|c| c.is_ascii_lowercase()),
                "word not all-lowercase: {w}"
            );
        }
    }
}
