//! Storage backends supported by aries-askar

#[cfg(feature = "any")]
#[cfg_attr(docsrs, doc(cfg(feature = "any")))]
/// Generic backend (from URI) support
pub mod any;

#[cfg(any(feature = "postgres", feature = "sqlite"))]
mod db_utils;

#[cfg(feature = "postgres")]
#[cfg_attr(docsrs, doc(cfg(feature = "postgres")))]
/// Postgres database support
pub mod postgres;

#[cfg(feature = "sqlite")]
#[cfg_attr(docsrs, doc(cfg(feature = "sqlite")))]
/// Sqlite database support
pub mod sqlite;
