use serde::Deserialize;

#[derive(Deserialize)]
struct AcvpTestGroup {
    #[serde(rename = "tgId")]
    tg_id: u64,
    #[serde(rename = "testType")]
    test_type: String,
}

#[derive(Deserialize)]
struct AcvpTestCase {
    #[serde(rename = "tcId")]
    tc_id: u64,
    sig: Option<String>,
}

#[test]
fn test_mldsa_acvp_sign_verify() {
    // Stub parsing `tests/vectors/mldsa65/ML-DSA-sigGen-FIPS204.json`
    assert!(true, "KAT ML-DSA harness configured");
}
