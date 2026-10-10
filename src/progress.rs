use std::{
    io::{Error, ErrorKind},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use crate::Result;

pub const FRAME: Duration = Duration::from_nanos(1_000_000_000 / 120);

#[derive(Clone)]
pub struct Step {
    pub group: Option<String>,
    pub name: String,
    pub total: u64,
    pub unit: &'static str,
    completed: Arc<AtomicU64>,
    text: Arc<Mutex<Text>>,
}

#[derive(Clone, Default)]
pub struct Text {
    pub detail: String,
    pub result: Option<String>,
}

impl Step {
    pub fn set(&self, completed: u64) {
        self.completed.store(completed, Ordering::Relaxed);
    }

    pub fn completed(&self) -> u64 {
        self.completed.load(Ordering::Relaxed)
    }

    pub fn detail(&self, detail: impl Into<String>) {
        self.text.lock().expect("progress lock poisoned").detail = detail.into();
    }

    pub fn finish(&self, result: impl Into<String>) {
        self.set(self.total);
        self.text.lock().expect("progress lock poisoned").result = Some(result.into());
    }

    pub fn text(&self) -> Text {
        self.text.lock().expect("progress lock poisoned").clone()
    }
}

#[derive(Clone, Default)]
pub struct Progress {
    group: Option<String>,
    steps: Arc<Mutex<Vec<Step>>>,
    cancelled: Arc<AtomicBool>,
}

impl Progress {
    pub fn group(&self, name: impl Into<String>) -> Self {
        Self {
            group: Some(name.into()),
            ..self.clone()
        }
    }

    pub fn start(&self, name: impl Into<String>, total: u64, unit: &'static str) -> Step {
        let step = Step {
            group: self.group.clone(),
            name: name.into(),
            total,
            unit,
            completed: Arc::default(),
            text: Arc::default(),
        };
        self.steps
            .lock()
            .expect("progress lock poisoned")
            .push(step.clone());
        step
    }

    pub fn activity(&self, name: impl Into<String>) -> Step {
        self.start(name, 0, "")
    }

    pub fn steps(&self) -> Vec<Step> {
        self.steps.lock().expect("progress lock poisoned").clone()
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    pub fn check(&self) -> Result<()> {
        if self.cancelled.load(Ordering::Relaxed) {
            return Err(Error::new(ErrorKind::Interrupted, "已取消").into());
        }
        Ok(())
    }
}
