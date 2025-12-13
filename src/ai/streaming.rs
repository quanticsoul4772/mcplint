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

    #[test]
    fn stream_chunk_is_terminal() {
        let text = StreamChunk::Text("content".to_string());
        assert!(!text.is_terminal());

        let partial = StreamChunk::PartialJson("{}".to_string());
        assert!(!partial.is_terminal());

        let token_update = StreamChunk::TokenUpdate {
            input: 5,
            output: 10,
        };
        assert!(!token_update.is_terminal());

        let done = StreamChunk::Done;
        assert!(done.is_terminal());

        let error = StreamChunk::Error("fail".to_string());
        assert!(error.is_terminal());
    }

    #[test]
    fn stream_chunk_as_text() {
        let text = StreamChunk::Text("hello".to_string());
        assert_eq!(text.as_text(), Some("hello"));

        let partial = StreamChunk::PartialJson("{}".to_string());
        assert_eq!(partial.as_text(), None);

        let token_update = StreamChunk::TokenUpdate {
            input: 5,
            output: 10,
        };
        assert_eq!(token_update.as_text(), None);

        let done = StreamChunk::Done;
        assert_eq!(done.as_text(), None);

        let error = StreamChunk::Error("fail".to_string());
        assert_eq!(error.as_text(), None);
    }

    #[test]
    fn stream_channel_creation() {
        let (sender, mut receiver) = stream_channel(10);
        assert!(sender.try_send(StreamChunk::Done).is_ok());
        assert!(receiver.try_recv().is_ok());
    }

    #[test]
    fn accumulator_partial_json() {
        let mut acc = StreamAccumulator::new();

        acc.process(StreamChunk::PartialJson(r#"{"key":"#.to_string()));
        assert_eq!(acc.content, r#"{"key":"#);

        // PartialJson replaces content, not appends
        acc.process(StreamChunk::PartialJson(r#"{"key":"value"}"#.to_string()));
        assert_eq!(acc.content, r#"{"key":"value"}"#);
    }

    #[test]
    fn accumulator_empty_chunks() {
        let mut acc = StreamAccumulator::new();

        acc.process(StreamChunk::Text("".to_string()));
        assert_eq!(acc.content, "");

        acc.process(StreamChunk::Text("content".to_string()));
        acc.process(StreamChunk::Text("".to_string()));
        assert_eq!(acc.content, "content");
    }

    #[test]
    fn accumulator_large_chunks() {
        let mut acc = StreamAccumulator::new();

        let large_text = "x".repeat(10_000);
        acc.process(StreamChunk::Text(large_text.clone()));
        assert_eq!(acc.content.len(), 10_000);
        assert_eq!(acc.content, large_text);
    }

    #[test]
    fn accumulator_multiple_token_updates() {
        let mut acc = StreamAccumulator::new();

        acc.process(StreamChunk::TokenUpdate {
            input: 10,
            output: 20,
        });
        assert_eq!(acc.input_tokens, 10);
        assert_eq!(acc.output_tokens, 20);
        assert_eq!(acc.total_tokens(), 30);

        // Later update replaces previous values
        acc.process(StreamChunk::TokenUpdate {
            input: 15,
            output: 25,
        });
        assert_eq!(acc.input_tokens, 15);
        assert_eq!(acc.output_tokens, 25);
        assert_eq!(acc.total_tokens(), 40);
    }

    #[test]
    fn accumulator_completion_without_error() {
        let mut acc = StreamAccumulator::new();

        acc.process(StreamChunk::Text("content".to_string()));
        acc.process(StreamChunk::Done);

        assert!(acc.completed);
        assert!(!acc.has_error());
        assert_eq!(acc.error, None);
    }

    #[test]
    fn accumulator_error_after_content() {
        let mut acc = StreamAccumulator::new();

        acc.process(StreamChunk::Text("partial content".to_string()));
        acc.process(StreamChunk::TokenUpdate {
            input: 5,
            output: 10,
        });
        acc.process(StreamChunk::Error("network error".to_string()));

        assert_eq!(acc.content, "partial content");
        assert_eq!(acc.input_tokens, 5);
        assert_eq!(acc.output_tokens, 10);
        assert!(acc.has_error());
        assert_eq!(acc.error, Some("network error".to_string()));
        assert!(!acc.completed);
    }

    #[test]
    fn accumulator_default_state() {
        let acc = StreamAccumulator::new();

        assert_eq!(acc.content, "");
        assert_eq!(acc.input_tokens, 0);
        assert_eq!(acc.output_tokens, 0);
        assert_eq!(acc.total_tokens(), 0);
        assert!(!acc.completed);
        assert!(!acc.has_error());
        assert_eq!(acc.error, None);
    }

    #[test]
    fn accumulator_mixed_chunk_sequence() {
        let mut acc = StreamAccumulator::new();

        acc.process(StreamChunk::Text("Start ".to_string()));
        acc.process(StreamChunk::TokenUpdate {
            input: 5,
            output: 0,
        });
        acc.process(StreamChunk::Text("middle ".to_string()));
        acc.process(StreamChunk::TokenUpdate {
            input: 5,
            output: 10,
        });
        acc.process(StreamChunk::Text("end".to_string()));
        acc.process(StreamChunk::Done);

        assert_eq!(acc.content, "Start middle end");
        assert_eq!(acc.input_tokens, 5);
        assert_eq!(acc.output_tokens, 10);
        assert_eq!(acc.total_tokens(), 15);
        assert!(acc.completed);
        assert!(!acc.has_error());
    }

    #[test]
    fn print_callback_creation() {
        let callback_immediate = PrintCallback::new(true);
        assert!(callback_immediate.immediate);

        let callback_buffered = PrintCallback::new(false);
        assert!(!callback_buffered.immediate);
    }

    #[test]
    fn print_callback_handles_text() {
        let mut callback = PrintCallback::new(false);
        // Should not panic when immediate is false
        callback.on_text("test text");
        callback.on_done();
        callback.on_error("error message");
    }

    #[test]
    fn collect_callback_default() {
        let callback = CollectCallback::default();
        assert_eq!(callback.content, "");
    }

    #[test]
    fn collect_callback_empty_text() {
        let mut callback = CollectCallback::new();
        callback.on_text("");
        callback.on_text("content");
        callback.on_text("");

        assert_eq!(callback.into_content(), "content");
    }

    #[test]
    fn collect_callback_ignores_errors() {
        let mut callback = CollectCallback::new();
        callback.on_text("before error");
        callback.on_error("something went wrong");
        callback.on_text(" after error");

        assert_eq!(callback.into_content(), "before error after error");
    }

    #[test]
    fn collect_callback_multiple_done() {
        let mut callback = CollectCallback::new();
        callback.on_text("text");
        callback.on_done();
        callback.on_done();
        callback.on_text(" more");

        assert_eq!(callback.into_content(), "text more");
    }

    #[test]
    fn collect_callback_large_content() {
        let mut callback = CollectCallback::new();
        let large_text = "x".repeat(10_000);
        callback.on_text(&large_text);

        assert_eq!(callback.into_content().len(), 10_000);
    }

    #[test]
    fn stream_chunk_text_from_string() {
        let chunk = StreamChunk::text(String::from("owned"));
        assert_eq!(chunk.as_text(), Some("owned"));
    }

    #[test]
    fn stream_chunk_text_from_str() {
        let chunk = StreamChunk::text("borrowed");
        assert_eq!(chunk.as_text(), Some("borrowed"));
    }

    #[test]
    fn stream_chunk_error_from_string() {
        let chunk = StreamChunk::error(String::from("owned error"));
        assert!(chunk.is_terminal());
        assert_eq!(chunk.as_text(), None);
    }

    #[test]
    fn stream_chunk_error_from_str() {
        let chunk = StreamChunk::error("borrowed error");
        assert!(chunk.is_terminal());
    }

    #[test]
    fn print_callback_on_tokens() {
        let mut callback = PrintCallback::new(true);
        // Default implementation does nothing, should not panic
        callback.on_tokens(10, 20);
    }

    #[test]
    fn collect_callback_on_tokens() {
        let mut callback = CollectCallback::new();
        // Default implementation does nothing, should not panic
        callback.on_tokens(10, 20);
        callback.on_text("text");
        assert_eq!(callback.into_content(), "text");
    }

    #[tokio::test]
    async fn stream_channel_buffer_overflow() {
        let (sender, mut receiver) = stream_channel(2);

        // Fill buffer
        sender
            .send(StreamChunk::Text("1".to_string()))
            .await
            .unwrap();
        sender
            .send(StreamChunk::Text("2".to_string()))
            .await
            .unwrap();

        // Receive one to make room
        assert!(receiver.recv().await.is_some());

        // Can send again
        sender.send(StreamChunk::Done).await.unwrap();
    }

    #[tokio::test]
    async fn stream_channel_sender_dropped() {
        let (sender, mut receiver) = stream_channel(10);

        sender
            .send(StreamChunk::Text("before drop".to_string()))
            .await
            .unwrap();
        drop(sender);

        // Can still receive sent message
        assert!(receiver.recv().await.is_some());
        // Next receive returns None because sender was dropped
        assert!(receiver.recv().await.is_none());
    }
}
