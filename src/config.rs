use std::{env, fs::create_dir_all};

use crate::{ApiHash, ApiId};

static API_ID: &str = "API_ID";
static API_HASH: &str = "API_HASH";
static STORE_PATH: &str = "STORE_PATH";

pub struct Config {
    pub api_id: ApiId,
    pub api_hash: ApiHash,
    pub session_file_path: String,
}

impl Config {
    pub fn init() -> Self {
        let api_id = env::var(API_ID)
            .expect(&format!("{API_ID} must be set!"))
            .parse::<ApiId>()
            .expect(&format!("Failed to parse {API_ID}"));
        let api_hash = env::var(API_HASH).expect(&format!("{API_HASH} must be set!"));

        let store_path = {
            let store_path = env::var(STORE_PATH).expect(&format!("{STORE_PATH} must be set!"));
            let store_path = shellexpand::full(&store_path).ok().unwrap();

            create_dir_all(store_path.as_ref()).unwrap();

            store_path.to_string()
        };

        let session_file_path = format!("{}/simple-reply-bot.session", store_path);

        Config {
            api_id,
            api_hash,
            session_file_path,
        }
    }
}
