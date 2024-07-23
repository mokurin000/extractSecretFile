use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct Verify {
    pub error: Option<String>,
    pub verified: bool,
}
