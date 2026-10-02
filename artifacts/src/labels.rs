//! A name and a description for something the store addresses by digest.
//!
//! The store's contract is that a digest is the only name content has. That is
//! the right contract and this does not change it — but it leaves a person
//! looking at a dashboard with a column of 64-hex strings and no way to tell a
//! rootfs from last Tuesday's CI tarball. A label is the answer: mutable
//! metadata *about* content, kept beside it rather than in it.
//!
//! ## Why this is not part of the content
//!
//! Neither obvious alternative works.
//!
//! **A blob has nowhere to put a name.** Its bytes are an ext4 image or a
//! tarball; there is no header the store is allowed to invent, and prefixing one
//! would mean the digest no longer covers what the file actually is.
//!
//! **A manifest has somewhere, and it is still the wrong place.** A manifest is
//! addressed by the hash of its own JSON, so a `name` field inside it makes
//! renaming a *fork*: the manifest gets a new digest, every tag pointing at the
//! old one still points at the old one, and the store now holds two manifests
//! describing one thing. The same argument [`crate::manifest`] makes for
//! refusing a timestamp field applies here with more force, because unlike a
//! timestamp a description is something people expect to edit.
//!
//! So a label is keyed by digest and stored outside the object:
//!
//! ```text
//! labels/<aa>/<64-hex>   canonical JSON, mutable, replaced by rename
//! ```
//!
//! Three properties follow, and all three are what somebody labelling a store
//! actually wants:
//!
//! * **Renaming does not move anything.** The digest is unchanged, so every tag,
//!   manifest entry and materialization still resolves.
//! * **One label serves both kinds.** Blobs and manifests are addressed the same
//!   way, so there is one mechanism rather than two that drift.
//! * **A label is never load-bearing.** Nothing resolves *through* a label —
//!   [`crate::tags`] is still the only mutable pointer — so a missing or
//!   corrupt one costs a column in a table and nothing else.
//!
//! ## Labels and tags answer different questions
//!
//! A tag is an address: `art get web-v2` has to work, so a tag is unique, is
//! restricted to a path-safe charset, and moving one changes what a name
//! resolves to. A label is a description: it is not unique, it holds spaces and
//! punctuation, and editing one changes nothing about what resolves where. Both
//! are shown together in the dashboard because between them they answer "what is
//! this?" — the tag says what to type, the label says what it is.

use crate::digest::Digest;
use serde::{Deserialize, Serialize};

/// Longest name a label may carry.
///
/// Sized for a table column rather than for storage: a name is rendered beside a
/// digest in a fixed-width row, and one long enough to wrap turns a scannable
/// list into a wall. Anything longer is a description.
pub const MAX_NAME: usize = 80;

/// Longest description. A paragraph, not a document — this is the "what is this
/// and why is it here" a person writes when they store something, and a store
/// that accepted a README would be asked to render one.
pub const MAX_DESCRIPTION: usize = 2000;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LabelError {
    #[error("a name may be at most {MAX_NAME} characters")]
    NameTooLong,
    #[error("a description may be at most {MAX_DESCRIPTION} characters")]
    DescriptionTooLong,
    #[error("a name may not contain control characters or line breaks")]
    NameControl,
    #[error("a description may not contain control characters other than newline and tab")]
    DescriptionControl,
    #[error("a label with neither a name nor a description says nothing; remove it instead")]
    Empty,
}

/// What a person calls a digest.
///
/// Both fields are optional and at least one must be set — a label carrying
/// neither is a file that says nothing, and writing one would leave a record
/// that reads as "somebody labelled this" when nobody did. Removing the label is
/// the way to say nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Label {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl Label {
    pub fn new(name: Option<String>, description: Option<String>) -> Result<Label, LabelError> {
        let label = Label {
            name: name.map(|n| n.trim().to_string()).filter(|n| !n.is_empty()),
            description: description
                .map(|d| d.trim().to_string())
                .filter(|d| !d.is_empty()),
        };
        label.validate()?;
        Ok(label)
    }

    pub fn is_empty(&self) -> bool {
        self.name.is_none() && self.description.is_none()
    }

    /// The name, or the first line of the description, or nothing.
    ///
    /// What a table column shows. A description-only label still has *something*
    /// worth putting in the name column — the alternative is an empty cell next
    /// to a populated detail page, which reads as "no label" and is wrong.
    pub fn display_name(&self) -> Option<&str> {
        if let Some(name) = &self.name {
            return Some(name);
        }
        self.description
            .as_deref()
            .and_then(|d| d.lines().next())
            .map(str::trim)
            .filter(|l| !l.is_empty())
    }

    pub fn validate(&self) -> Result<(), LabelError> {
        if self.is_empty() {
            return Err(LabelError::Empty);
        }
        if let Some(name) = &self.name {
            if name.chars().count() > MAX_NAME {
                return Err(LabelError::NameTooLong);
            }
            // A name is rendered inline — in a table cell, in `art ls` output,
            // in a log line. A newline or an escape sequence in it would break
            // whichever of those it reached, so it is refused at the door rather
            // than escaped at each of the several places it is displayed.
            if name.chars().any(|c| c.is_control()) {
                return Err(LabelError::NameControl);
            }
        }
        if let Some(description) = &self.description {
            if description.chars().count() > MAX_DESCRIPTION {
                return Err(LabelError::DescriptionTooLong);
            }
            // A description is rendered as a block, so line breaks are the
            // point. Everything else that is a control character is not.
            if description
                .chars()
                .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
            {
                return Err(LabelError::DescriptionControl);
            }
        }
        Ok(())
    }

    /// The bytes written to disk: pretty JSON with a trailing newline.
    ///
    /// Pretty rather than canonical, unlike a manifest, and the difference is
    /// the point: a manifest's bytes *are* its identity so they must be
    /// reproducible, while a label is mutable metadata whose file somebody will
    /// eventually read with `cat`.
    pub fn to_json(&self) -> Vec<u8> {
        let mut v = serde_json::to_vec_pretty(self).unwrap_or_else(|_| b"{}".to_vec());
        v.push(b'\n');
        v
    }
}

/// A label together with the digest it describes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Labelled {
    pub digest: Digest,
    pub label: Label,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_label_needs_to_say_something() {
        assert_eq!(Label::new(None, None), Err(LabelError::Empty));
        // Whitespace is not something. A name of spaces would render as an
        // empty cell that claims to be a label.
        assert_eq!(
            Label::new(Some("   ".into()), Some("\n\t".into())),
            Err(LabelError::Empty),
        );
        // Either one alone is enough.
        assert!(Label::new(Some("rootfs".into()), None).is_ok());
        assert!(Label::new(None, Some("the debian base image".into())).is_ok());
    }

    #[test]
    fn surrounding_whitespace_is_trimmed_rather_than_stored() {
        let l = Label::new(Some("  rootfs  ".into()), Some("  base image\n".into())).unwrap();
        assert_eq!(l.name.as_deref(), Some("rootfs"));
        assert_eq!(l.description.as_deref(), Some("base image"));
    }

    /// A name is rendered inline — a table cell, an `art ls` row, a log field —
    /// so anything that would break a line breaks all three.
    #[test]
    fn a_name_may_not_carry_control_characters() {
        for bad in ["two\nlines", "tab\there", "esc\u{1b}[31m", "nul\0"] {
            assert_eq!(
                Label::new(Some(bad.into()), None),
                Err(LabelError::NameControl),
                "{bad:?} was accepted as a name",
            );
        }
    }

    /// A description is rendered as a block, so line breaks are the point —
    /// but an escape sequence still is not.
    #[test]
    fn a_description_keeps_its_line_breaks_and_nothing_else() {
        let l = Label::new(None, Some("what it is\n\nwhy it is here".into())).unwrap();
        assert_eq!(
            l.description.as_deref(),
            Some("what it is\n\nwhy it is here")
        );
        assert!(Label::new(None, Some("colour\u{1b}[31m".into())).is_err());
        assert!(Label::new(None, Some("bell\u{7}".into())).is_err());
    }

    #[test]
    fn the_limits_are_enforced_in_characters_not_bytes() {
        // Multi-byte characters count once: a name of 80 emoji is 80
        // characters and 320 bytes, and it is the rendered width that matters.
        let name: String = "é".repeat(MAX_NAME);
        assert!(Label::new(Some(name), None).is_ok());
        let name: String = "é".repeat(MAX_NAME + 1);
        assert_eq!(Label::new(Some(name), None), Err(LabelError::NameTooLong));

        let long: String = "x".repeat(MAX_DESCRIPTION + 1);
        assert_eq!(
            Label::new(None, Some(long)),
            Err(LabelError::DescriptionTooLong),
        );
    }

    /// A description-only label still has something to put in a name column.
    #[test]
    fn the_display_name_falls_back_to_the_first_line() {
        let l = Label::new(None, Some("the debian base\nbuilt 2026-08".into())).unwrap();
        assert_eq!(l.display_name(), Some("the debian base"));

        let l = Label::new(Some("rootfs".into()), Some("anything".into())).unwrap();
        assert_eq!(
            l.display_name(),
            Some("rootfs"),
            "a name wins over a description"
        );

        assert_eq!(Label::default().display_name(), None);
    }

    /// The file is written for a person to `cat`, and an absent field is absent
    /// rather than `null` — the store's own JSON convention everywhere else.
    #[test]
    fn the_json_is_readable_and_round_trips() {
        let l = Label::new(Some("rootfs".into()), None).unwrap();
        let json = String::from_utf8(l.to_json()).unwrap();
        assert!(json.ends_with('\n'), "{json:?}");
        assert!(json.contains('\n'), "pretty, not a single line: {json:?}");
        assert!(
            !json.contains("description"),
            "an absent field is omitted: {json}"
        );
        assert_eq!(serde_json::from_str::<Label>(&json).unwrap(), l);
    }
}
