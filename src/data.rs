use std::{borrow::Cow, ops::Range, ptr, sync::Arc};

#[derive(Clone, Default)]
pub struct Data {
    parts: Vec<Part>,
}

#[derive(Clone)]
struct Part {
    offset: usize,
    data: Arc<Vec<u8>>,
    range: Range<usize>,
}

impl From<Arc<Vec<u8>>> for Data {
    fn from(data: Arc<Vec<u8>>) -> Self {
        let mut result = Self::default();
        let size = data.len();
        result.push(data, 0..size);
        result
    }
}

impl Data {
    pub fn len(&self) -> usize {
        self.parts
            .last()
            .map_or(0, |part| part.offset + part.range.len())
    }

    pub fn push(&mut self, data: Arc<Vec<u8>>, range: Range<usize>) {
        if range.is_empty() {
            return;
        }
        if let Some(last) = self.parts.last_mut()
            && Arc::ptr_eq(&last.data, &data)
            && last.range.end == range.start
        {
            last.range.end = range.end;
            return;
        }
        self.parts.push(Part {
            offset: self.len(),
            data,
            range,
        });
    }

    pub fn chunks(&self) -> impl Iterator<Item = &[u8]> {
        self.parts.iter().map(|part| &part.data[part.range.clone()])
    }

    fn slices(&self, range: Range<usize>) -> impl Iterator<Item = &[u8]> {
        let first = self
            .parts
            .partition_point(|part| part.offset + part.range.len() <= range.start);
        self.parts[first..]
            .iter()
            .take_while(move |part| part.offset < range.end)
            .map(move |part| {
                let start = range.start.saturating_sub(part.offset);
                let end = (range.end - part.offset).min(part.range.len());
                &part.data[part.range.start + start..part.range.start + end]
            })
    }

    pub fn get(&self, range: Range<usize>) -> Option<Cow<'_, [u8]>> {
        if range.start > range.end || range.end > self.len() {
            return None;
        }
        let size = range.len();
        let mut slices = self.slices(range);
        let first = slices.next().unwrap_or_default();
        if first.len() == size {
            return Some(Cow::Borrowed(first));
        }
        let mut bytes = Vec::with_capacity(size);
        bytes.extend_from_slice(first);
        for part in slices {
            bytes.extend_from_slice(part);
        }
        Some(Cow::Owned(bytes))
    }

    pub fn matches(&self, offset: usize, bytes: &[u8]) -> Option<bool> {
        let end = offset.checked_add(bytes.len())?;
        if end > self.len() {
            return None;
        }
        let mut position = 0;
        for part in self.slices(offset..end) {
            let expected = &bytes[position..position + part.len()];
            if !ptr::eq(part, expected) && part != expected {
                return Some(false);
            }
            position += part.len();
        }
        Some(true)
    }

    pub fn difference(&self, other: &Self) -> Option<usize> {
        let mut left = self.chunks();
        let mut right = other.chunks();
        let mut a = &[][..];
        let mut b = &[][..];
        let mut offset = 0;
        loop {
            if a.is_empty() {
                a = left.next().unwrap_or_default();
            }
            if b.is_empty() {
                b = right.next().unwrap_or_default();
            }
            if a.is_empty() || b.is_empty() {
                return (a.len() != b.len()).then_some(offset);
            }
            let size = a.len().min(b.len());
            if !ptr::eq(&a[..size], &b[..size]) && a[..size] != b[..size] {
                return a[..size]
                    .iter()
                    .zip(&b[..size])
                    .position(|(left, right)| left != right)
                    .map(|index| offset + index);
            }
            a = &a[size..];
            b = &b[size..];
            offset += size;
        }
    }
}

impl PartialEq for Data {
    fn eq(&self, other: &Self) -> bool {
        self.difference(other).is_none()
    }
}

impl Eq for Data {}
