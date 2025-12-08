//! Streaming Response Support
//!
//! Provides streaming capabilities for AI responses, allowing
//! real-time display of explanations as they are generated.

use std::pin::Pin;

use futures::Stream;
use tokio::sync::mpsc;

/// A chunk of streamed response content
#[derive(Debug, Clone)]
pub enum StreamChunk {
    /// Text content being streamed
    Text(String),
    /// Partial JSON being accumulated
    PartialJson(String),
    /// Token usage update
    TokenUpdate { input: u32, output: u32 },
    /// Stream completed successfully
    Done,
    /// Error occurred during streaming
    Error(String),
}

impl StreamChunk {
    /// Create a text chunk
    pub fn text(s: impl Into<String>) -> Self {
        StreamChunk::Text(s.into())
    }

    /// Create an error chunk
    pub fn error(s: impl Into<String>) -> Self {
        StreamChunk::Error(s.into())
    }

    /// Check if this is a terminal chunk (Done or Error)
    pub fn is_terminal(&self) -> bool {
        matches!(self, StreamChunk::Done | StreamChunk::Error(_))
    }

    /// Get the text content if this is a Text chunk
    pub fn as_text(&self) -> Option<&str> {
        match self {
            StreamChunk::Text(s) => Some(s),
            _ => None,
        }
    }
}

/// Type alias for a boxed stream of chunks
pub type ChunkStream = Pin<Box<dyn Stream<Item = StreamChunk> + Send>>;

/// Sender for streaming chunks
pub type ChunkSender = mpsc::Sender<StreamChunk>;

/// Receiver for streaming chunks
pub type ChunkReceiver = mpsc::Receiver<StreamChunk>;

/// Create a channel for streaming chunks
pub fn stream_channel(buffer_size: usize) -> (ChunkSender, ChunkReceiver) {
    mpsc::channel(buffer_size)
}

/// Accumulator for building complete response from stream
#[derive(Debug, Default)]
pub struct StreamAccumulator {
    /// Accumulated text content
    pub content: String,
    /// Total input tokens
    pub input_tokens: u32,
    /// Total output tokens
    pub output_tokens: u32,
    /// Whether the stream completed successfully
    pub completed: bool,
    /// Error message if stream failed
    pub error: Option<String>,
}

impl StreamAccumulator {
    /// Create a new accumulator
    pub fn new() -> Self {
        Self::default()
    }

    /// Process a chunk and update state
    pub fn process(&mut self, chunk: StreamChunk) {
        match chunk {
            StreamChunk::Text(text) => {
                self.content.push_str(&text);
            }
            StreamChunk::PartialJson(json) => {
                self.content = json;
            }
            StreamChunk::TokenUpdate { input, output } => {
                self.input_tokens = input;
                self.output_tokens = output;
            }
            StreamChunk::Done => {
                self.completed = true;
            }
            StreamChunk::Error(msg) => {
                self.error = Some(msg);
            }
        }
    }

    /// Get total tokens used
    pub fn total_tokens(&self) -> u32 {
        self.input_tokens + self.output_tokens
    }

    /// Check if there was an error
    pub fn has_error(&self) -> bool {
        self.error.is_some()
    }
}

/// Callback for handling stream events
pub trait StreamCallback: Send + Sync {
    /// Called when new text is received
    fn on_text(&mut self, text: &str);

    /// Called when token count is updated
    fn on_tokens(&mut self, _input: u32, _output: u32) {}

    /// Called when stream completes
    fn on_done(&mut self) {}

    /// Called when an error occurs
    fn on_error(&mut self, error: &str);
}

/// A simple callback that prints to stdout
pub struct PrintCallback {
    /// Whether to print immediately (no buffering)
    pub immediate: bool,
}

impl PrintCallback {
    pub fn new(immediate: bool) -> Self {
        Self { immediate }
    }
}

impl StreamCallback for PrintCallback {
    fn on_text(&mut self, text: &str) {
        if self.immediate {
            print!("{}", text);
            use std::io::Write;
            let _ = std::io::stdout().flush();
        }
    }

    fn on_done(&mut self) {
        if self.immediate {
            println!();
        }
    }

    fn on_error(&mut self, error: &str) {
        eprintln!("\nError: {}", error);
    }
}

/// A callback that collects all text into a string
pub struct CollectCallback {
    content: String,
}

impl CollectCallback {
    pub fn new() -> Self {
        Self {
            content: String::new(),
        }
    }

    pub fn into_content(self) -> String {
        self.content
    }
}

impl Default for CollectCallback {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamCallback for CollectCallback {
    fn on_text(&mut self, text: &str) {
        self.content.push_str(text);
    }

    fn on_error(&mut self, _error: &str) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_chunk_creation() {
        let text = StreamChunk::text("hello");
        assert!(matches!(text, StreamChunk::Text(_)));
        assert_eq!(text.as_text(), Some("hello"));

        let error = StreamChunk::error("failed");
        assert!(error.is_terminal());
    }

    #[test]
    fn accumulator_processes_chunks() {
        let mut acc = StreamAccumulator::new();

        acc.process(StreamChunk::Text("Hello ".to_string()));
        acc.process(StreamChunk::Text("world".to_string()));
        acc.process(StreamChunk::TokenUpdate {
            input: 10,
            output: 20,
        });
        acc.process(StreamChunk::Done);

        assert_eq!(acc.content, "Hello world");
        assert_eq!(acc.total_tokens(), 30);
        assert!(acc.completed);
        assert!(!acc.has_error());
    }

    #[test]
    fn accumulator_handles_error() {
        let mut acc = StreamAccumulator::new();

        acc.process(StreamChunk::Text("partial".to_string()));
        acc.process(StreamChunk::Error("connection lost".to_string()));

        assert_eq!(acc.content, "partial");
        assert!(acc.has_error());
        assert_eq!(acc.error, Some("connection lost".to_string()));
    }

    #[test]
    fn collect_callback() {
        let mut callback = CollectCallback::new();

        callback.on_text("Hello ");
        callback.on_text("world");
        callback.on_done();

        assert_eq!(callback.into_content(), "Hello world");
    }
}
