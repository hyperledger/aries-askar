use std::fmt::{self, Display};
use std::marker::PhantomData;
use std::str::FromStr;

use indy_utils::base58;

use serde::{de::Visitor, Deserializer, Serializer};

use super::types::SecretBytes;

macro_rules! serde_as_str_impl {
    ($t:ident) => {
        impl serde::Serialize for $t {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                $crate::serde_utils::as_str::serialize(self, serializer)
            }
        }

        impl<'de> serde::Deserialize<'de> for $t {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                $crate::serde_utils::as_str::deserialize(deserializer)
            }
        }
    };
}

pub mod as_str {
    use super::*;

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: FromStr,
        T::Err: Display,
    {
        deserializer.deserialize_str(FromStrVisitor { _pd: PhantomData })
    }

    pub fn serialize<S, T>(inst: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: AsRef<str>,
    {
        serializer.serialize_str(inst.as_ref())
    }

    struct FromStrVisitor<T: FromStr> {
        _pd: PhantomData<T>,
    }

    impl<'de, T: FromStr> Visitor<'de> for FromStrVisitor<T>
    where
        T::Err: Display,
    {
        type Value = T;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a valid string value")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            T::from_str(v).map_err(E::custom)
        }
    }
}

// structure borrowed from serde_bytes crate:

pub mod as_base58 {
    use super::*;

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de>,
    {
        Deserialize::deserialize(deserializer)
    }

    pub fn serialize<S, T>(inst: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: Serialize,
    {
        Serialize::serialize(inst, serializer)
    }

    pub trait Serialize {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer;
    }

    impl Serialize for Vec<u8> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(&base58::encode(self))
        }
    }

    impl Serialize for SecretBytes {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(&base58::encode(self))
        }
    }

    impl<'a, T> Serialize for &'a T
    where
        T: ?Sized + Serialize,
    {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            (**self).serialize(serializer)
        }
    }

    impl<T> Serialize for Option<T>
    where
        T: Serialize,
    {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            struct Wrap<T>(T);

            impl<T> serde::Serialize for Wrap<T>
            where
                T: Serialize,
            {
                fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where
                    S: Serializer,
                {
                    self.0.serialize(serializer)
                }
            }

            match self {
                Some(val) => serializer.serialize_some(&Wrap(val)),
                None => serializer.serialize_none(),
            }
        }
    }

    pub trait Deserialize<'de>: Sized {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>;
    }

    impl<'de> Deserialize<'de> for Vec<u8> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            struct FromBase58Visitor;

            impl<'de> Visitor<'de> for FromBase58Visitor {
                type Value = Vec<u8>;

                fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    formatter.write_str("a valid base58 string")
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    base58::decode(v).map_err(E::custom)
                }
            }

            deserializer.deserialize_any(FromBase58Visitor)
        }
    }

    impl<'de> Deserialize<'de> for SecretBytes {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let result = <Vec<u8> as Deserialize>::deserialize(deserializer)?;
            Ok(Self::from(result))
        }
    }

    impl<'de, T> Deserialize<'de> for Option<T>
    where
        T: Deserialize<'de>,
    {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            struct FromBase58Visitor<T> {
                pd: PhantomData<T>,
            }

            impl<'de, T> Visitor<'de> for FromBase58Visitor<T>
            where
                T: Deserialize<'de>,
            {
                type Value = Option<T>;

                fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    formatter.write_str("an optional base58 string")
                }

                fn visit_none<E>(self) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Ok(None)
                }

                fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
                where
                    D: Deserializer<'de>,
                {
                    T::deserialize(deserializer).map(Some)
                }
            }

            deserializer.deserialize_option(FromBase58Visitor { pd: PhantomData })
        }
    }
}
