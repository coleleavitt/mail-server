/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Borrow;
use std::hash::Hash;
use std::sync::Arc;

use ahash::AHashMap;

#[derive(Debug)]
#[repr(transparent)]
struct StringRef<T: IdBimapItem>(Arc<T>);

#[derive(Debug, Default)]
pub struct IdBimap<T: IdBimapItem> {
    // Keyed by the id itself: a wrapper key hashed via `Hash` does not match
    // ahash's specialized `u32` hashing used by lookups, so `by_id` never hit.
    id_to_name: AHashMap<u32, Arc<T>>,
    name_to_id: AHashMap<StringRef<T>, Arc<T>>,
}

impl<T: IdBimapItem> IdBimap<T> {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            id_to_name: AHashMap::with_capacity(capacity),
            name_to_id: AHashMap::with_capacity(capacity),
        }
    }

    pub fn insert(&mut self, item: T) {
        let item = Arc::new(item);
        self.id_to_name.insert(*item.id(), item.clone());
        self.name_to_id.insert(StringRef(item.clone()), item);
    }

    pub fn by_name(&self, name: &str) -> Option<&T> {
        self.name_to_id.get(name).map(|v| v.as_ref())
    }

    pub fn by_id(&self, id: u32) -> Option<&T> {
        self.id_to_name.get(&id).map(|v| v.as_ref())
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.name_to_id.values().map(|v| v.as_ref())
    }

    pub fn is_empty(&self) -> bool {
        self.name_to_id.is_empty()
    }
}

// No manual Send/Sync impls: Arc<T> makes the map Send + Sync exactly when T
// is Send + Sync, which the compiler checks.

pub trait IdBimapItem: std::fmt::Debug {
    fn id(&self) -> &u32;
    fn name(&self) -> &str;
}

impl<T: IdBimapItem> Borrow<str> for StringRef<T> {
    fn borrow(&self) -> &str {
        self.0.name()
    }
}

impl<T: IdBimapItem> PartialEq for StringRef<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0.name() == other.0.name()
    }
}

impl<T: IdBimapItem> Eq for StringRef<T> {}

impl<T: IdBimapItem> Hash for StringRef<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.name().hash(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Item(u32, String);

    impl IdBimapItem for Item {
        fn id(&self) -> &u32 {
            &self.0
        }
        fn name(&self) -> &str {
            &self.1
        }
    }

    #[test]
    fn thread_safe_and_lookups_work() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<IdBimap<Item>>();

        let mut map = IdBimap::with_capacity(1);
        map.insert(Item(7, "seven".into()));
        assert_eq!(map.by_id(7).map(|i| i.name()), Some("seven"));
        assert_eq!(map.by_name("seven").map(|i| *i.id()), Some(7));
    }
}
