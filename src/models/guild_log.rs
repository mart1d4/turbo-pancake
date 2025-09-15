use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, types::Json};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)]
pub enum GuildLogAction {
    GuildUpdate = 1,
    ChannelCreate = 10,
    ChannelUpdate = 11,
    ChannelDelete = 12,
    ChannelOverwriteCreate = 13,
    ChannelOverwriteUpdate = 14,
    ChannelOverwriteDelete = 15,
    MemberKick = 20,
    MemberPrune = 21,
    MemberBanAdd = 22,
    MemberBanRemove = 23,
    MemberUpdate = 24,
    MemberRoleUpdate = 25,
    MemberMove = 26,
    MemberDisconnect = 27,
    BotAdd = 28,
    RoleCreate = 30,
    RoleUpdate = 31,
    RoleDelete = 32,
    InviteCreate = 40,
    InviteUpdate = 41,
    InviteDelete = 42,
    WebhookCreate = 50,
    WebhookUpdate = 51,
    WebhookDelete = 52,
    EmojiCreate = 60,
    EmojiUpdate = 61,
    EmojiDelete = 62,
    MessageDelete = 72,
    MessageBulkDelete = 73,
    MessagePin = 74,
    MessageUnpin = 75,
    StageInstanceCreate = 83,
    StageInstanceUpdate = 84,
    StageInstanceDelete = 85,
    GuildScheduledEventCreate = 100,
    GuildScheduledEventUpdate = 101,
    GuildScheduledEventDelete = 102,
    ThreadCreate = 110,
    ThreadUpdate = 111,
    ThreadDelete = 112,
    SoundboardSoundCreate = 130,
    SoundboardSoundUpdate = 131,
    SoundboardSoundDelete = 132,
    AutoModerationRuleCreate = 140,
    AutoModerationRuleUpdate = 141,
    AutoModerationRuleDelete = 142,
    AutoModerationBlockMessage = 143,
    AutoModerationFlagToChannel = 144,
    AutoModerationUserCommunicationDisabled = 145,
    AutoModerationQuarantineUser = 146,
}

// Implement From/TryFrom for i32 for seamless conversion between DB and Rust
impl From<GuildLogAction> for i32 {
    fn from(ct: GuildLogAction) -> Self {
        ct as i32
    }
}

impl TryFrom<i32> for GuildLogAction {
    type Error = String;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(GuildLogAction::GuildUpdate),
            10 => Ok(GuildLogAction::ChannelCreate),
            11 => Ok(GuildLogAction::ChannelUpdate),
            12 => Ok(GuildLogAction::ChannelDelete),
            13 => Ok(GuildLogAction::ChannelOverwriteCreate),
            14 => Ok(GuildLogAction::ChannelOverwriteUpdate),
            15 => Ok(GuildLogAction::ChannelOverwriteDelete),
            20 => Ok(GuildLogAction::MemberKick),
            21 => Ok(GuildLogAction::MemberPrune),
            22 => Ok(GuildLogAction::MemberBanAdd),
            23 => Ok(GuildLogAction::MemberBanRemove),
            24 => Ok(GuildLogAction::MemberUpdate),
            25 => Ok(GuildLogAction::MemberRoleUpdate),
            26 => Ok(GuildLogAction::MemberMove),
            27 => Ok(GuildLogAction::MemberDisconnect),
            28 => Ok(GuildLogAction::BotAdd),
            30 => Ok(GuildLogAction::RoleCreate),
            31 => Ok(GuildLogAction::RoleUpdate),
            32 => Ok(GuildLogAction::RoleDelete),
            40 => Ok(GuildLogAction::InviteCreate),
            41 => Ok(GuildLogAction::InviteUpdate),
            42 => Ok(GuildLogAction::InviteDelete),
            50 => Ok(GuildLogAction::WebhookCreate),
            51 => Ok(GuildLogAction::WebhookUpdate),
            52 => Ok(GuildLogAction::WebhookDelete),
            60 => Ok(GuildLogAction::EmojiCreate),
            61 => Ok(GuildLogAction::EmojiUpdate),
            62 => Ok(GuildLogAction::EmojiDelete),
            72 => Ok(GuildLogAction::MessageDelete),
            73 => Ok(GuildLogAction::MessageBulkDelete),
            74 => Ok(GuildLogAction::MessagePin),
            75 => Ok(GuildLogAction::MessageUnpin),
            83 => Ok(GuildLogAction::StageInstanceCreate),
            84 => Ok(GuildLogAction::StageInstanceUpdate),
            85 => Ok(GuildLogAction::StageInstanceDelete),
            100 => Ok(GuildLogAction::GuildScheduledEventCreate),
            101 => Ok(GuildLogAction::GuildScheduledEventUpdate),
            102 => Ok(GuildLogAction::GuildScheduledEventDelete),
            110 => Ok(GuildLogAction::ThreadCreate),
            111 => Ok(GuildLogAction::ThreadUpdate),
            112 => Ok(GuildLogAction::ThreadDelete),
            130 => Ok(GuildLogAction::SoundboardSoundCreate),
            131 => Ok(GuildLogAction::SoundboardSoundUpdate),
            132 => Ok(GuildLogAction::SoundboardSoundDelete),
            140 => Ok(GuildLogAction::AutoModerationRuleCreate),
            141 => Ok(GuildLogAction::AutoModerationRuleUpdate),
            142 => Ok(GuildLogAction::AutoModerationRuleDelete),
            143 => Ok(GuildLogAction::AutoModerationBlockMessage),
            144 => Ok(GuildLogAction::AutoModerationFlagToChannel),
            145 => Ok(GuildLogAction::AutoModerationUserCommunicationDisabled),
            146 => Ok(GuildLogAction::AutoModerationQuarantineUser),
            _ => Err(format!("Unknown log action: {}", value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuildLogChange {
    pub key: String,
    pub old_value: serde_json::Value,
    pub new_value: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, FromRow)]
pub struct GuildLog {
    pub id: i64,
    pub user_id: Option<i64>,
    pub target_id: Option<i64>,
    pub action_type: GuildLogAction,
    pub reason: Option<String>,
    pub changes: Json<Vec<GuildLogChange>>,
    pub options: Json<serde_json::Value>,
    pub created_at: DateTime<chrono::Utc>,
}
