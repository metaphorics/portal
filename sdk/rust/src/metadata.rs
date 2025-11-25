use serde::{Deserialize, Serialize};

/// Metadata for a lease registration
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Metadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub hide: Option<bool>,
}

impl Metadata {
    /// Convert metadata to JSON string
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Check if metadata is empty
    pub fn is_empty(&self) -> bool {
        self.description.is_none()
            && self.tags.is_none()
            && self.thumbnail.is_none()
            && self.owner.is_none()
            && self.hide.is_none()
    }
}

/// Builder for creating Metadata
pub struct MetadataBuilder {
    metadata: Metadata,
}

impl MetadataBuilder {
    /// Create a new MetadataBuilder
    pub fn new() -> Self {
        Self {
            metadata: Metadata::default(),
        }
    }

    /// Set description
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.metadata.description = Some(desc.into());
        self
    }

    /// Set tags
    pub fn tags(mut self, tags: Vec<String>) -> Self {
        self.metadata.tags = Some(tags);
        self
    }

    /// Set thumbnail URL
    pub fn thumbnail(mut self, thumbnail: impl Into<String>) -> Self {
        self.metadata.thumbnail = Some(thumbnail.into());
        self
    }

    /// Set owner
    pub fn owner(mut self, owner: impl Into<String>) -> Self {
        self.metadata.owner = Some(owner.into());
        self
    }

    /// Set hide flag
    pub fn hide(mut self, hide: bool) -> Self {
        self.metadata.hide = Some(hide);
        self
    }

    /// Build the Metadata
    pub fn build(self) -> Metadata {
        self.metadata
    }
}

impl Default for MetadataBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_builder() {
        let metadata = MetadataBuilder::new()
            .description("Test description")
            .tags(vec!["tag1".to_string(), "tag2".to_string()])
            .owner("Test Owner")
            .hide(false)
            .build();

        assert_eq!(metadata.description, Some("Test description".to_string()));
        assert_eq!(metadata.tags, Some(vec!["tag1".to_string(), "tag2".to_string()]));
        assert_eq!(metadata.owner, Some("Test Owner".to_string()));
        assert_eq!(metadata.hide, Some(false));
    }

    #[test]
    fn test_metadata_to_json() {
        let metadata = MetadataBuilder::new()
            .description("Test")
            .build();

        let json = metadata.to_json();
        assert!(json.contains("Test"));
    }

    #[test]
    fn test_metadata_is_empty() {
        let empty = Metadata::default();
        assert!(empty.is_empty());

        let not_empty = MetadataBuilder::new()
            .description("Not empty")
            .build();
        assert!(!not_empty.is_empty());
    }
}
