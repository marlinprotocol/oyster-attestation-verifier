use std::error::Error;
use std::num::TryFromIntError;

use actix_web::{error, http::StatusCode, post, web, Responder};
use ethers::types::U256;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub struct AppState {
    pub secp256k1_secret: secp256k1::SecretKey,
    pub secp256k1_public: [u8; 64],
}

#[derive(Deserialize, Serialize)]
struct RawAttestation {
    attestation: String,
}

#[derive(Deserialize, Serialize)]
struct HexAttestation {
    attestation: String,
}

#[derive(Serialize, Deserialize)]
struct VerifyAttestationResponse {
    signature: String,
    secp256k1_public: String,
    pcr0: String,
    pcr1: String,
    pcr2: String,
    timestamp: usize,
    verifier_secp256k1_public: String,
}

#[derive(Error)]
pub enum UserError {
    #[error("error while decoding attestation doc from hex")]
    AttestationDecode(#[source] hex::FromHexError),
    #[error("error while verifying attestation")]
    AttestationVerification(#[source] oyster::AttestationError),
    #[error("Message generation failed")]
    MessageGeneration(#[source] secp256k1::Error),
    #[error("invalid recovery id")]
    InvalidRecovery(#[source] TryFromIntError),
}

impl error::ResponseError for UserError {
    fn error_response(&self) -> actix_web::HttpResponse<actix_web::body::BoxBody> {
        actix_web::HttpResponse::build(self.status_code())
            .insert_header(actix_web::http::header::ContentType::plaintext())
            .body(format!("{self:?}"))
    }

    fn status_code(&self) -> actix_web::http::StatusCode {
        use UserError::*;
        match self {
            AttestationDecode(_) => StatusCode::BAD_REQUEST,
            AttestationVerification(_) => StatusCode::UNAUTHORIZED,
            MessageGeneration(_) => StatusCode::INTERNAL_SERVER_ERROR,
            InvalidRecovery(_) => StatusCode::UNAUTHORIZED,
        }
    }
}

impl std::fmt::Debug for UserError {
    // pretty print like anyhow
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)?;

        if self.source().is_some() {
            writeln!(f, "\n\nCaused by:")?;
        }

        let mut err: &dyn Error = self;
        loop {
            let Some(source) = err.source() else { break };
            writeln!(f, "\t{}", source)?;

            err = source;
        }

        Ok(())
    }
}

// keccak256(
//     abi.encode(
//         keccak256("EIP712Domain(string name,string version)"),
//         keccak256("marlin.oyster.AttestationVerifier"),
//         keccak256("1")
//     )
// )
const DOMAIN_SEPARATOR: [u8; 32] =
    hex_literal::hex!("0de834feb03c214f785e75b2828ffeceb322312d4487e2fb9640ca5fc32542c7");

// keccak256("Attestation(bytes enclavePubKey,bytes PCR0,bytes PCR1,bytes PCR2,uint256 timestampInMilliseconds)")
const ATTESTATION_TYPEHASH: [u8; 32] =
    hex_literal::hex!("6889df476ca38f3f4b417c17eb496682eb401b4f41a2259741a78acc481ea805");

fn compute_digest(
    enclave_pubkey: &[u8],
    pcr0: &[u8],
    pcr1: &[u8],
    pcr2: &[u8],
    timestamp: usize,
) -> [u8; 32] {
    let mut encoded_struct = Vec::new();
    encoded_struct.reserve_exact(32 * 6);
    encoded_struct.extend_from_slice(&ATTESTATION_TYPEHASH);
    encoded_struct.extend_from_slice(&ethers::utils::keccak256(enclave_pubkey));
    encoded_struct.extend_from_slice(&ethers::utils::keccak256(pcr0));
    encoded_struct.extend_from_slice(&ethers::utils::keccak256(pcr1));
    encoded_struct.extend_from_slice(&ethers::utils::keccak256(pcr2));
    encoded_struct.resize(32 * 6, 0);
    U256::from(timestamp).to_big_endian(&mut encoded_struct[32 * 5..32 * 6]);

    let hash_struct = ethers::utils::keccak256(encoded_struct);

    let mut encoded_message = Vec::new();
    encoded_message.reserve_exact(2 + 32 * 2);
    encoded_message.extend_from_slice(&[0x19, 0x01]);
    encoded_message.extend_from_slice(&DOMAIN_SEPARATOR);
    encoded_message.extend_from_slice(&hash_struct);

    ethers::utils::keccak256(encoded_message)
}

fn verify(
    attestation: Vec<u8>,
    secret: &secp256k1::SecretKey,
    public: &[u8; 64],
) -> actix_web::Result<impl Responder, UserError> {
    let parsed = oyster::decode_attestation(attestation.clone())
        .map_err(UserError::AttestationVerification)?;
    oyster::verify_with_timestamp(attestation, parsed.pcrs, parsed.timestamp)
        .map_err(UserError::AttestationVerification)?;

    let requester_secp256k1_public = parsed.public_key.as_slice();

    let digest = compute_digest(
        &requester_secp256k1_public,
        &parsed.pcrs[0],
        &parsed.pcrs[1],
        &parsed.pcrs[2],
        parsed.timestamp,
    );

    let response_msg =
        secp256k1::Message::from_digest_slice(&digest).map_err(UserError::MessageGeneration)?;

    let secp = secp256k1::Secp256k1::new();
    let (recid, sig) = secp
        .sign_ecdsa_recoverable(&response_msg, secret)
        .serialize_compact();

    let sig = hex::encode(sig);
    let recid: u8 = recid
        .to_i32()
        .try_into()
        .map_err(UserError::InvalidRecovery)?;
    let recid = hex::encode([recid + 27]);

    Ok(web::Json(VerifyAttestationResponse {
        signature: sig + &recid,
        secp256k1_public: hex::encode(requester_secp256k1_public),
        pcr0: hex::encode(parsed.pcrs[0]),
        pcr1: hex::encode(parsed.pcrs[1]),
        pcr2: hex::encode(parsed.pcrs[2]),
        timestamp: parsed.timestamp,
        verifier_secp256k1_public: hex::encode(public),
    }))
}

#[post("/verify/raw")]
async fn verify_raw(
    req: web::Bytes,
    state: web::Data<AppState>,
) -> actix_web::Result<impl Responder, UserError> {
    verify(
        req.to_vec(),
        &state.secp256k1_secret,
        &state.secp256k1_public,
    )
}

#[post("/verify/hex")]
async fn verify_hex(
    req: web::Bytes,
    state: web::Data<AppState>,
) -> actix_web::Result<impl Responder, UserError> {
    let attestation = hex::decode(&req).map_err(UserError::AttestationDecode)?;

    verify(
        attestation,
        &state.secp256k1_secret,
        &state.secp256k1_public,
    )
}

// Update the sample attestations in the 'test/' directory before running tests for fresh timestamp
#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App};

    #[actix_web::test]
    async fn test_raw_attestation() {
        let secp256k1_secret = std::fs::read("./src/test/secp256k1.sec").unwrap();
        let secp256k1_public = std::fs::read("./src/test/secp256k1.pub").unwrap();

        let secp256k1_secret = secp256k1::SecretKey::from_slice(&secp256k1_secret).unwrap();
        let secp256k1_public: [u8; 64] = secp256k1_public.try_into().unwrap();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(AppState {
                    secp256k1_secret,
                    secp256k1_public,
                }))
                .service(verify_raw),
        )
        .await;

        let attestation = std::fs::read("./src/test/attestation.bin").unwrap();

        let req = test::TestRequest::post()
            .uri("/verify/raw")
            .insert_header(("Content-Type", "application/octet-stream"))
            .set_payload(attestation)
            .to_request();

        let resp: VerifyAttestationResponse =
            test::try_call_and_read_body_json(&app, req).await.unwrap();

        assert_eq!(resp.signature, "80836a2534fadf0b1adef2135434207eeecfd360819907e925d469a8179eddad4ef1de22cae8398f84bc8df640feef08a5854c77982639c3a242da1c210f535c1c");
        assert_eq!(resp.secp256k1_public, "57febcf9e7f5081d3d24182817df526a1c9c3df7e46b64613acd13f9aa53b81de888a8562ba7b4a0e42c48d24d7e444ffcba311ceddb5068eca2ea899379ab50");
        assert_eq!(resp.pcr0, "5fec1b73727425848d725d68f4a062c634061a035067bd0b9a6dc73e25ed5013dfe7ccbf8a7e9857eceb0841c4cb6ae6");
        assert_eq!(resp.pcr1, "bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f");
        assert_eq!(resp.pcr2, "ae41ca22df64a32d729667160a7f218e59e31586809e121ff2c446a36dc5354ba4e0f74dce737be3298cf82c364692e7");
        assert_eq!(
            resp.verifier_secp256k1_public,
            hex::encode(secp256k1_public)
        );
        assert_eq!(resp.timestamp, 1723012689640);
    }

    #[actix_web::test]
    async fn test_hex_attestation() {
        let secp256k1_secret = std::fs::read("./src/test/secp256k1.sec").unwrap();
        let secp256k1_public = std::fs::read("./src/test/secp256k1.pub").unwrap();

        let secp256k1_secret = secp256k1::SecretKey::from_slice(&secp256k1_secret).unwrap();
        let secp256k1_public: [u8; 64] = secp256k1_public.try_into().unwrap();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(AppState {
                    secp256k1_secret,
                    secp256k1_public,
                }))
                .service(verify_hex),
        )
        .await;

        let attestation = std::fs::read_to_string("./src/test/attestation.hex").unwrap();

        let req = test::TestRequest::post()
            .uri("/verify/hex")
            .insert_header(("Content-Type", "text/plain"))
            .set_payload(attestation)
            .to_request();

        let resp: VerifyAttestationResponse =
            test::try_call_and_read_body_json(&app, req).await.unwrap();

        assert_eq!(resp.signature, "3661e773c787950fecf0242250875cf900eee87269ef9320c1b42375a1cc2c4a210d540e2fa90ad37ec81b230b4fb88648ccb868998d9ed77d72c8a8c473a7001c");
        assert_eq!(resp.secp256k1_public, "57febcf9e7f5081d3d24182817df526a1c9c3df7e46b64613acd13f9aa53b81de888a8562ba7b4a0e42c48d24d7e444ffcba311ceddb5068eca2ea899379ab50");
        assert_eq!(resp.pcr0, "5fec1b73727425848d725d68f4a062c634061a035067bd0b9a6dc73e25ed5013dfe7ccbf8a7e9857eceb0841c4cb6ae6");
        assert_eq!(resp.pcr1, "bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f");
        assert_eq!(resp.pcr2, "ae41ca22df64a32d729667160a7f218e59e31586809e121ff2c446a36dc5354ba4e0f74dce737be3298cf82c364692e7");
        assert_eq!(
            resp.verifier_secp256k1_public,
            hex::encode(secp256k1_public)
        );
        assert_eq!(resp.timestamp, 1723012992231);
    }
}
