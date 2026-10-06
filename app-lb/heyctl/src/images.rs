//! heyvm's image catalog, through app-lb: `/images`.
//!
//! Images are named by content (`img-<digest>`), so one is shared by every
//! deployment that pulls the same bytes. app-lb records what holds each one
//! and offloads what nothing has used in a while — after proving the store it
//! came from still has it. These calls read that inventory and act on single
//! images; all of them need fleet scope.

use crate::api::{Client, seg};
use crate::error::Result;
use crate::transport::{Method, Request};
use crate::types::{ImageEntry, ImageInventory, ImageSweep};
use serde_json::json;

impl Client {
    /// `GET /images`.
    pub async fn images(&self) -> Result<ImageInventory> {
        self.read(Request::new(Method::Get, "/images"), "image", "")
            .await
    }

    /// `POST /images/sweep` — one offload pass now.
    pub async fn sweep_images(&self) -> Result<ImageSweep> {
        self.read(Request::new(Method::Post, "/images/sweep"), "image", "")
            .await
    }

    /// `POST /images/:name/offload` — verify the remote copy, then delete the
    /// image from heyvm. Refused (409) for a referenced or pinned image.
    pub async fn offload_image(&self, name: &str) -> Result<ImageEntry> {
        self.read(
            Request::new(Method::Post, format!("/images/{}/offload", seg(name))),
            "image",
            name,
        )
        .await
    }

    /// `DELETE /images/:name` — remove an unreferenced image outright.
    pub async fn delete_image(&self, name: &str) -> Result<()> {
        self.unit(
            Request::new(Method::Delete, format!("/images/{}", seg(name))),
            "image",
            name,
        )
        .await
    }

    /// `PATCH /images/:name {pinned}` — a pinned image is never offloaded.
    pub async fn pin_image(&self, name: &str, pinned: bool) -> Result<ImageEntry> {
        self.read(
            Request::new(Method::Patch, format!("/images/{}", seg(name)))
                .json(json!({ "pinned": pinned })),
            "image",
            name,
        )
        .await
    }
}
