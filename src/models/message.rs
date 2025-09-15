use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sqlx::types::Json;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)] // Make this enum an i32 for database storage
pub enum MessageType {
    Default = 0,
    RecipientAdd = 1,
    RecipientRemove = 2,
    Call = 3,
    ChannelNameChange = 4,
    ChannelIconChange = 5,
    ChannelPinnedMessage = 6,
    UserJoin = 7,
    ChannelFollowAdd = 12,
    ThreadCreated = 18,
    Reply = 19,
    ChatInputCommand = 20,
    ThreadStarterMessage = 21,
    AutoModerationAction = 24,
    PollResult = 46,
}

// Implement From/TryFrom for i32 for seamless conversion between DB and Rust
impl From<MessageType> for i32 {
    fn from(ct: MessageType) -> Self {
        ct as i32
    }
}

impl TryFrom<i32> for MessageType {
    type Error = String;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(MessageType::Default),
            1 => Ok(MessageType::RecipientAdd),
            2 => Ok(MessageType::RecipientRemove),
            3 => Ok(MessageType::Call),
            4 => Ok(MessageType::ChannelNameChange),
            5 => Ok(MessageType::ChannelIconChange),
            6 => Ok(MessageType::ChannelPinnedMessage),
            7 => Ok(MessageType::UserJoin),
            12 => Ok(MessageType::ChannelFollowAdd),
            18 => Ok(MessageType::ThreadCreated),
            19 => Ok(MessageType::Reply),
            20 => Ok(MessageType::ChatInputCommand),
            21 => Ok(MessageType::ThreadStarterMessage),
            24 => Ok(MessageType::AutoModerationAction),
            46 => Ok(MessageType::PollResult),
            _ => Err(format!("Unknown message type: {}", value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageAttachment {
    pub id: i64,
    pub filename: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub content_type: Option<String>,
    pub size: i32, // bytes
    pub url: String,
    pub proxy_url: String,
    pub width: Option<i32>,
    pub height: Option<i32>,
    pub duration_secs: Option<i32>,
    pub waveform: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageEmbedThumbnail {
    pub url: String,
    pub proxy_url: Option<String>,
    pub height: Option<i32>,
    pub width: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageEmbedVideo {
    pub url: Option<String>,
    pub proxy_url: Option<String>,
    pub height: Option<i32>,
    pub width: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageEmbedImage {
    pub url: String,
    pub proxy_url: Option<String>,
    pub height: Option<i32>,
    pub width: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageEmbedProvider {
    pub name: Option<String>,
    pub url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageEmbedAuthor {
    pub name: String,
    pub url: Option<String>,
    pub icon_url: Option<String>,
    pub proxy_icon_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageEmbedFooter {
    pub text: String,
    pub icon_url: Option<String>,
    pub proxy_icon_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageEmbedField {
    pub name: String,
    pub value: String,
    pub inline: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageEmbed {
    pub title: Option<String>,
    pub description: Option<String>,
    pub url: Option<String>,
    pub timestamp: Option<DateTime<chrono::Utc>>,
    pub color: Option<i32>,
    pub image: Option<MessageEmbedImage>,
    pub video: Option<MessageEmbedVideo>,
    pub thumbnail: Option<MessageEmbedThumbnail>,
    pub author: Option<MessageEmbedAuthor>,
    pub provider: Option<MessageEmbedProvider>,
    pub footer: Option<MessageEmbedFooter>,
    pub fields: Option<Vec<MessageEmbedField>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessagePollAnswer {
    pub answer_id: i32,
    pub text: Option<String>,
    pub emoji_id: Option<i64>,
    pub emoji_name: Option<String>,
}

//#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
//pub struct MessagePollResults {
//    pub is_finalized: bool,
//    pub answer_counts: Vec<MessagePollAnswerCount>,
//}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessagePoll {
    pub id: i64,
    pub question: String,
    pub answers: Vec<MessagePollAnswer>,
    pub expiry: DateTime<chrono::Utc>,
    pub allow_multiselect: bool,
    //pub results: Option<MessagePollResults>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageCall {
    pub participants: Vec<i64>,
    pub ended_timestamp: Option<DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow)]
pub struct Message {
    pub id: i64,
    pub r#type: MessageType,
    pub content: Option<String>,
    pub attachments: Json<Vec<MessageAttachment>>,
    pub embeds: Json<Vec<MessageEmbed>>,
    pub components: Json<serde_json::Value>,
    pub poll: Json<Option<MessagePoll>>,
    pub call: Json<Option<MessageCall>>,
    pub edited: Option<DateTime<chrono::Utc>>,
    pub pinned: Option<DateTime<chrono::Utc>>,
    pub reference_id: Option<i64>,
    pub mention_everyone: bool,
    pub author_id: i64,
    pub channel_id: i64,
    pub webhook_id: Option<i64>,
    pub nonce: Option<String>,
    pub created_at: DateTime<chrono::Utc>,
}
