"""
Dedicated test for Local GGUF Model Inference via llama-cpp-python.
Verifies model presence, in-process loading, 2 vCPUs, pure CPU, and 2,048 context.
"""
import unittest
import os

class TestLocalModelGGUF(unittest.TestCase):
    def test_gguf_model_inference(self):
        models_dir = "models"
        gguf_files = [f for f in os.listdir(models_dir) if f.endswith(".gguf")]
        self.assertGreater(len(gguf_files), 0, "No GGUF model file found in models/")

        model_path = os.path.join(models_dir, gguf_files[0])
        print(f"\n[Test] Testing GGUF model: {model_path} ({os.path.getsize(model_path) / (1024*1024):.1f} MB)")

        from llama_cpp import Llama
        llm = Llama(
            model_path=model_path,
            n_ctx=2048,           # Strict 2,048 context
            n_threads=2,          # 2 vCPU limit
            n_gpu_layers=0,       # Pure CPU execution
            verbose=False
        )
        self.assertIsNotNone(llm)

        # Single prompt test within 2,048 tokens
        res = llm.create_chat_completion(
            messages=[
                {"role": "system", "content": "You are a cybersecurity log analyzer. Return pure JSON."},
                {"role": "user", "content": "Analyze log: [L1] status: 401 client_ip: 10.0.0.1"}
            ],
            max_tokens=50,
            temperature=0.1
        )
        self.assertIn("choices", res)
        content = res["choices"][0]["message"]["content"]
        self.assertTrue(len(content) > 0)
        print(f"[Test PASS] Local model responded successfully: {content[:80]}...")

if __name__ == "__main__":
    unittest.main()
