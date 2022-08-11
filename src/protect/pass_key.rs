use zeroize::Zeroize;

use std::{
    borrow::Cow,
    fmt::{self, Debug, Formatter},
    ops::Deref,
};

/// A possibly-empty password or key used to derive a store key
#[derive(Clone, Default)]
pub struct PassKey<'a>(Option<Cow<'a, str>>);

impl PassKey<'_> {
    /// Create a scoped reference to the passkey
    pub fn as_ref(&self) -> PassKey<'_> {
        PassKey(Some(Cow::Borrowed(&**self)))
    }

    /// Access the passkey as a str
    pub fn as_str(&self) -> &str {
        match self.0.as_deref() {
            None => "",
            Some(s) => s,
        }
    }

    /// Create an empty passkey
    pub fn empty() -> PassKey<'static> {
        PassKey(None)
    }

    pub(crate) fn is_none(&self) -> bool {
        self.0.is_none()
    }

    pub(crate) fn into_owned(mut self) -> PassKey<'static> {
        PassKey(self.0.take().map(|s| Cow::Owned(s.into_owned())))
    }

    pub(crate) fn into_string(mut self) -> String {
        match self.0.take() {
            None => String::new(),
            Some(s) => s.into_owned(),
        }
    }
}

impl Debug for PassKey<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if cfg!(test) {
            f.debug_tuple("PassKey").field(&*self).finish()
        } else {
            f.debug_tuple("PassKey").field(&"<secret>").finish()
        }
    }
}

impl Deref for PassKey<'_> {
    type Target = str;

    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl Drop for PassKey<'_> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<'a> From<&'a str> for PassKey<'a> {
    fn from(inner: &'a str) -> Self {
        Self(Some(Cow::Borrowed(inner)))
    }
}

impl From<String> for PassKey<'_> {
    fn from(inner: String) -> Self {
        Self(Some(Cow::Owned(inner)))
    }
}

impl<'a> From<Option<&'a str>> for PassKey<'a> {
    fn from(inner: Option<&'a str>) -> Self {
        Self(inner.map(Cow::Borrowed))
    }
}

impl<'a, 'b> PartialEq<PassKey<'b>> for PassKey<'a> {
    fn eq(&self, other: &PassKey<'b>) -> bool {
        **self == **other
    }
}
impl Eq for PassKey<'_> {}

impl Zeroize for PassKey<'_> {
    fn zeroize(&mut self) {
        if let Some(Cow::Owned(mut s)) = self.0.take() {
            s.zeroize();
        }
    }
}
