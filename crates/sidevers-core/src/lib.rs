//! Sidevers protocol core.
//!
//! Implements the no-I/O layers of the Sidevers v1 protocol spec:
//! identity (§2), the signed CBOR envelope (§3), payload encryption (§3.4),
//! and linkage proofs (§2.7). No sockets, no filesystem, no async runtime.

#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod address;
pub mod cbor;
pub mod envelope;
pub mod error;
pub mod features;
pub mod keys;
pub mod keystore;
pub mod linkage;
pub mod log_id;
pub mod messages;
pub mod payload;
pub mod replay;
pub mod sas;
pub mod verse;

pub use address::{Address, AddressKind};
pub use envelope::{Envelope, MessageType, PROTOCOL_VERSION};
pub use error::{Error, Result};
pub use features::{FeatureRegistry, FeatureState, phase1_baseline};
pub use keys::{MasterKey, SideKey, SideLabel};
pub use log_id::LogId;
pub use messages::device::{
    ContactCard, DeltaOp, DeviceRevokePayload, GroupInvite, PAIRING_NONCE_LEN, PairingQr,
    PairingRequestPayload, RelationshipRecord, STATE_BUNDLE_AAD, StateBundleInner,
    StateBundlePayload, StateDeltaPayload,
};
pub use messages::profile::{ProfilePayload, capability};
pub use messages::public::{
    AnnouncementPayload, DirectoryEntryPayload, HandleAttestPayload, HandleResolvePayload,
    PageDeliverPayload, PageFetchPayload, PagePublishPayload,
};
pub use messages::retirement::SideRetirementPayload;
pub use messages::storage_prefs::StoragePreferences;
pub use sas::{SAS_WORD_COUNT, pairing_sas, pairing_sas_string};
