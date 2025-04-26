// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Serde-specific utilties

use core::fmt;

use serde::{Deserializer, Serializer};

/// Serde "module" for (de)serilizing `bool` parameters as ints
pub struct Flag;

impl Flag {
    pub fn serialize<S>(value: &bool, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_i8((*value).into())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<bool, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_i8(FlagVisitor)
    }
}

/// [`Visitor`][serde::de::Visitor] for parsing boolean flags
struct FlagVisitor;

impl serde::de::Visitor<'_> for FlagVisitor {
    type Value = bool;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "either 0 or 1")
    }

    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match v {
            0 => Ok(false),
            1 => Ok(true),
            v => Err(E::invalid_value(
                serde::de::Unexpected::Signed(v),
                &"0 or 1",
            )),
        }
    }
}
