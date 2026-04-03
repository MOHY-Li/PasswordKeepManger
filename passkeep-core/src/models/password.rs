//! Password generation models

use serde::{Serialize, Deserialize};

/// 密码生成器配置
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PasswordGeneratorConfig {
    pub length: u8,
    pub character_sets: CharacterSets,
    pub exclude_similar: bool,
    pub exclude_ambiguous: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CharacterSets {
    pub uppercase: bool,
    pub lowercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub custom: String,
}

impl Default for PasswordGeneratorConfig {
    fn default() -> Self {
        Self {
            length: 20,
            character_sets: CharacterSets::default(),
            exclude_similar: true,
            exclude_ambiguous: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_generator_config_default() {
        let config = PasswordGeneratorConfig::default();
        assert_eq!(config.length, 20);
        assert_eq!(config.exclude_similar, true);
        assert_eq!(config.exclude_ambiguous, false);
    }

    #[test]
    fn test_password_generator_config_serialization() {
        let config = PasswordGeneratorConfig {
            length: 16,
            character_sets: CharacterSets {
                uppercase: true,
                lowercase: true,
                digits: true,
                symbols: false,
                custom: String::new(),
            },
            exclude_similar: false,
            exclude_ambiguous: true,
        };

        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("16"));

        let de: PasswordGeneratorConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(de.length, 16);
        assert_eq!(de.exclude_similar, false);
    }
}
