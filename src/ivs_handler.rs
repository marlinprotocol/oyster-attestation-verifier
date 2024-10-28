use actix_web::{get, http::StatusCode, post, web, HttpResponse, Responder};
use ethers::{
    core::k256::ecdsa::SigningKey,
    signers::{LocalWallet, Wallet},
};

use crate::handler::AppState;

#[get("/test")]
async fn test() -> impl Responder {
    return HttpResponse::Ok().json(kalypso_generator_models::models::TestResponse {
        data: "IVS is working".into(),
    });
}

#[post("/checkInput")]
async fn check_input_handler(
    payload: web::Json<kalypso_generator_models::models::InputPayload>,
) -> impl Responder {
    let attestation_bytes = payload.get_public();

    return HttpResponse::Ok().json(check_input(attestation_bytes));
}

fn check_input(attestation_bytes: Vec<u8>) -> kalypso_ivs_models::models::CheckInputResponse {
    let default_response = kalypso_ivs_models::models::CheckInputResponse { valid: false };

    let parsed = oyster::decode_attestation(attestation_bytes.clone());

    if parsed.is_err() {
        return default_response;
    }

    let parsed = parsed.unwrap();

    let result = oyster::verify_with_timestamp(attestation_bytes, parsed.pcrs, parsed.timestamp);

    if result.is_err() {
        return default_response;
    }

    return kalypso_ivs_models::models::CheckInputResponse { valid: true };
}

#[post("/getAttestationForInvalidInputs")]
async fn get_attestation_for_invalid_inputs(
    payload: web::Json<kalypso_ivs_models::models::InvalidInputPayload>,
    state: web::Data<AppState>,
) -> impl Responder {
    let ecies_priv_key = &state.secp256k1_secret.secret_bytes().to_vec();
    let signer_wallet = get_signer(ecies_priv_key.clone());

    let ask_id = payload.only_ask_id();
    let attestation_bytes = payload.get_public();

    if check_input(attestation_bytes.clone()).valid {
        return HttpResponse::BadRequest()
            .json(kalypso_ivs_models::models::CheckInputResponse { valid: true });
    }
    return HttpResponse::Ok().json(
        kalypso_helper::attestation_helpers::generate_invalid_input_attestation(
            ask_id,
            attestation_bytes.into(),
            signer_wallet,
        )
        .await,
    );
}

#[post("/verifyInputsAndProof")]
async fn verify_inputs_and_proof(
    _: web::Json<kalypso_ivs_models::models::VerifyInputsAndProof>,
) -> impl Responder {
    return kalypso_helper::response::response(
        "Network not implemented",
        StatusCode::BAD_REQUEST,
        None,
    );
}

fn get_signer(ecies_priv_key: Vec<u8>) -> Wallet<SigningKey> {
    let secp_private_key = secp256k1::SecretKey::from_slice(&ecies_priv_key)
        .unwrap()
        .display_secret()
        .to_string();
    secp_private_key.parse::<LocalWallet>().unwrap()
}
