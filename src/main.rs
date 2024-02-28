use std::{
    io::{self, BufRead, Write},
    matches,
    time::Duration,
};

use dotenvy::dotenv;
use grammers_client::{
    types::{Chat, Message},
    Client, Config, InitParams, SignInError, Update,
};
use grammers_session::Session;
use log::{error, info, warn};
use moka::future::Cache;

pub type ApiId = i32;
pub type ApiHash = String;

mod config;

#[derive(Clone)]
pub struct Bot {
    client: Client,
    session_file_path: String,
    replied_chat_cache: Cache<i64, ()>,
}

impl Bot {
    pub async fn init(
        api_id: ApiId,
        api_hash: ApiHash,
        session_file_path: String,
    ) -> anyhow::Result<Self> {
        let client = Client::connect(Config {
            session: Session::load_file_or_create(&session_file_path)?,
            api_id,
            api_hash,
            params: InitParams {
                catch_up: true,
                ..Default::default()
            },
        })
        .await?;

        if !client.is_authorized().await? {
            let phone = prompt("Enter your phone number (international format): ")?;
            let token = client.request_login_code(&phone).await?;
            let code = prompt("Enter the code you received: ")?;
            let signed_in = client.sign_in(&token, &code).await;
            match signed_in {
                Err(SignInError::PasswordRequired(password_token)) => {
                    let hint = password_token.hint().unwrap_or("empty");
                    let prompt_message = format!("Enter the password (hint {}): ", &hint);
                    let password = prompt(prompt_message.as_str())?;

                    client
                        .check_password(password_token, password.trim())
                        .await?;
                }
                Ok(_) => (),
                Err(e) => panic!("{}", e),
            };
            info!("Signed in!");
            match client.session().save_to_file(&session_file_path) {
                Ok(_) => {}
                Err(e) => {
                    error!("Failed to save session! Will sign out & terminate...");
                    client.sign_out().await?;
                    panic!("Failed to save session! Error: {}", e)
                }
            }
        }

        let replied_chat_cache = Cache::builder()
            .max_capacity(10_000)
            .time_to_live(Duration::from_secs(60 * 15))
            .build();

        Ok(Bot {
            client,
            session_file_path,
            replied_chat_cache,
        })
    }

    pub async fn handle_update(&self) -> anyhow::Result<()> {
        let client_handler = self.client.clone();
        while let Some(update) = client_handler.next_update().await? {
            match update {
                Update::NewMessage(message) if !message.outgoing() => {
                    match self.handle_message(&message).await {
                        Ok(_) => {}
                        Err(_err) => {}
                    };
                }
                _ => {}
            };
        }
        Ok(())
    }

    pub async fn handle_message(&self, message: &Message) -> anyhow::Result<()> {
        if matches!(message.chat(), Chat::User(_)) {
            if message.sender().is_some() {
                info!(
                    "Got a PM from user {} with id {}",
                    message.sender().unwrap().name(),
                    message.sender().unwrap().id()
                );
            } else {
                warn!(
                    "Got a PM message but sender is unknown (chat id {})",
                    message.chat().id()
                )
            }
        } else if matches!(message.chat(), Chat::Group(_)) {
            if message.sender().is_some() {
                info!(
                    "Got a message from chat '{}' with id {} from userid {}",
                    message.chat().name(),
                    message.chat().id(),
                    message.sender().unwrap().id()
                );
            } else {
                warn!(
                    "Got a message from chat '{}' with id {} but sender is unknown",
                    message.chat().name(),
                    message.chat().id()
                )
            }
            if !message.mentioned() {
                return Ok(());
            }
        } else {
            return Ok(());
        }

        if !self.replied_chat_cache.contains_key(&message.chat().id()) {
            message
                .reply(
                    "ЭТО АВТОМАТИЗИРОВАННОЕ СООБЩЕНИЕ!
Меня забрали в армию 31.10.2023, я могу быть не доступен как минимум до 30.04.2025 года!

IT'S AN AUTOMATED MESSAGE!
I was drafted into the Army on 10/31/2023, I may be unavailable until at least 04/30/2025!",
                )
                .await?;

            self.replied_chat_cache
                .insert(message.chat().id(), ())
                .await;
        }
        Ok(())
    }

    pub fn save_session(&self) -> anyhow::Result<()> {
        self.client
            .session()
            .save_to_file(&self.session_file_path)?;

        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();

    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let config = config::Config::init();
    let bot = Bot::init(config.api_id, config.api_hash, config.session_file_path).await?;

    tokio::select! {                                                      _ = tokio::signal::ctrl_c() => {
            info!("Got SIGINT; quitting early gracefully");               },
        r = bot.handle_update() => {
            match r {
                Ok(_) => info!("Work done, gracefully shutting down..."),
                Err(e) => error!("Got error, exiting... {e}")
            }
        }
    }

    bot.save_session()?;

    Ok(())
}

fn prompt(message: &str) -> anyhow::Result<String> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    stdout.write_all(message.as_bytes())?;
    stdout.flush()?;

    let stdin = io::stdin();
    let mut stdin = stdin.lock();

    let mut line = String::new();
    stdin.read_line(&mut line)?;
    Ok(line)
}
