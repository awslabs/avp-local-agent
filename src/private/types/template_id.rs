//! Represents a wrapper for typing a `TemplateId` String
use std::fmt;
use std::fmt::Formatter;

/// A wrapper for typing a `TemplateId` string
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct TemplateId(pub String);

// Enables an easy way to call `to_string` on `TemplateId`.
impl fmt::Display for TemplateId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod test {
    use crate::private::types::template_id::TemplateId;
    use std::collections::HashMap;

    #[test]
    fn template_id_formats_as_expected() {
        let id = TemplateId("template-id".to_string());
        assert_eq!(id.to_string(), "template-id");
    }

    #[test]
    fn template_id_empty_string() {
        let id = TemplateId(String::new());
        assert_eq!(id.to_string(), "");
    }

    #[test]
    fn template_id_can_be_inserted_into_map() {
        let mut map: HashMap<TemplateId, i32> = HashMap::new();
        assert_eq!(map.insert(TemplateId("templateId".to_string()), 10), None);
        assert_eq!(map.get(&TemplateId("templateId".to_string())), Some(&10));
    }

    #[test]
    fn template_id_is_cloneable() {
        let key = TemplateId("templateId".to_string());
        assert_eq!(key.clone(), key);
    }

    #[test]
    fn template_id_is_equal() {
        assert_eq!(
            TemplateId("templateId".to_string()),
            TemplateId("templateId".to_string())
        );
    }

    #[test]
    fn template_id_is_not_equal() {
        assert_ne!(
            TemplateId("templateId".to_string()),
            TemplateId("templateId2".to_string())
        );
    }
}
