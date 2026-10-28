use super::*;

pub(super) struct SortedStore<K>(Vec<(K, Counter)>);

impl<K> Default for SortedStore<K> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<K: Copy + Ord + Hash> StatsMap<K> for SortedStore<K> {
    const SORTED: bool = true;
    fn len(&self) -> usize {
        self.0.len()
    }
    fn into_pairs(self) -> impl Iterator<Item = (K, Counter)> {
        self.0.into_iter()
    }
    fn update(&mut self, key: K, outbound: bool, bytes: u64) {
        let index = match self.0.binary_search_by_key(&key, |entry| entry.0) {
            Ok(index) => index,
            Err(index) => {
                self.0.insert(index, (key, Counter::default()));
                index
            }
        };
        self.0[index].1.add(outbound, bytes);
    }
    fn snapshot(&self) -> Summary {
        let mut summary = Summary::default();
        for (key, value) in &self.0 {
            summary.add(key, value);
        }
        summary
    }
    fn capacity(&self) -> usize {
        self.0.capacity()
    }
}

pub(super) struct DenseStore<K> {
    index: HashBrownMap<K, usize, FastBuildHasher>,
    values: Vec<(K, Counter)>,
}

impl<K> Default for DenseStore<K> {
    fn default() -> Self {
        Self {
            index: HashBrownMap::with_hasher(FastBuildHasher::default()),
            values: Vec::new(),
        }
    }
}

impl<K: Copy + Eq + Hash> StatsMap<K> for DenseStore<K> {
    fn len(&self) -> usize {
        self.values.len()
    }
    fn into_pairs(self) -> impl Iterator<Item = (K, Counter)> {
        drop(self.index);
        self.values.into_iter()
    }
    fn update(&mut self, key: K, outbound: bool, bytes: u64) {
        let index = *self.index.entry(key).or_insert_with(|| {
            let index = self.values.len();
            self.values.push((key, Counter::default()));
            index
        });
        self.values[index].1.add(outbound, bytes);
    }
    fn snapshot(&self) -> Summary {
        let mut summary = Summary::default();
        for (key, value) in &self.values {
            summary.add(key, value);
        }
        summary
    }
    fn capacity(&self) -> usize {
        self.index.capacity()
    }
}
