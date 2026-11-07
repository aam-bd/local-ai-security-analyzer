"""
Tokenizer service providing token counting aligned with model tokenizers (e.g. Qwen / cl100k BPE).
Enforces the 2,048 token budget per model call.
"""
from typing import List, Optional
import tiktoken

class TokenizerService:
    def __init__(self, model_name: str = "qwen"):
        self.model_name = model_name
        try:
            # cl100k_base matches modern byte-pair encoding vocabularies (e.g., Qwen/GPT-4) with high fidelity
            self.encoding = tiktoken.get_encoding("cl100k_base")
        except Exception:
            self.encoding = None

    def count_tokens(self, text: str) -> int:
        """Count exact tokens in a text string."""
        if not text:
            return 0
        if self.encoding:
            return len(self.encoding.encode(text, disallowed_special=()))
        # Fallback conservative token estimation (1 token ~= 3.6 chars for code/JSON)
        return max(1, int(len(text) / 3.6))

    def count_lines_tokens(self, lines: List[str]) -> int:
        """Count total tokens across a list of log lines."""
        return sum(self.count_tokens(line) for line in lines)

    def truncate_to_tokens(self, text: str, max_tokens: int) -> str:
        """Truncate text to fit within max_tokens."""
        if self.count_tokens(text) <= max_tokens:
            return text
        if self.encoding:
            tokens = self.encoding.encode(text, disallowed_special=())[:max_tokens]
            return self.encoding.decode(tokens)
        return text[: int(max_tokens * 3.6)]

# Global singleton
tokenizer = TokenizerService()

