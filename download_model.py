"""
Model Downloader Utility.
Downloads compact, CPU-optimized GGUF models (Qwen2.5) for local offline execution.
Fits well within the 4 GB RAM ceiling (uses ~400 MB to 1.2 GB RAM).
"""
import os
import sys
import argparse
from huggingface_hub import hf_hub_download

MODELS = {
    "qwen-1.5b": {
        "repo_id": "Qwen/Qwen2.5-1.5B-Instruct-GGUF",
        "filename": "qwen2.5-1.5b-instruct-q4_k_m.gguf",
        "description": "Recommended for high-accuracy reasoning & JSON output (~0.98 GB, ~1.2 GB RAM footprint)"
    },
    "qwen-0.5b": {
        "repo_id": "Qwen/Qwen2.5-0.5B-Instruct-GGUF",
        "filename": "qwen2.5-0.5b-instruct-q4_k_m.gguf",
        "description": "Ultra-lightweight option for low-resource environments (~390 MB, ~400 MB RAM footprint)"
    }
}

def download_model(model_key: str = "qwen-1.5b", target_dir: str = "models"):
    if model_key not in MODELS:
        print(f"Unknown model key '{model_key}'. Available: {list(MODELS.keys())}")
        sys.exit(1)

    os.makedirs(target_dir, exist_ok=True)
    info = MODELS[model_key]
    print(f"[*] Downloading {model_key} from {info['repo_id']}...")
    print(f"    Description: {info['description']}")

    target_path = os.path.join(target_dir, info["filename"])
    if os.path.exists(target_path):
        print(f"[+] Model already exists at: {target_path}")
        return target_path

    try:
        downloaded = hf_hub_download(
            repo_id=info["repo_id"],
            filename=info["filename"],
            local_dir=target_dir,
            local_dir_use_symlinks=False
        )
        print(f"[+] Successfully downloaded model to: {downloaded}")
        return downloaded
    except Exception as e:
        print(f"[-] Error downloading model: {e}")
        print("    Note: The application will run in High-Fidelity Simulation Mode if no GGUF file is present.")
        return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download local GGUF models")
    parser.add_argument("--model", choices=list(MODELS.keys()), default="qwen-1.5b", help="Model to download")
    parser.add_argument("--dir", default="models", help="Destination directory")
    args = parser.parse_args()

    download_model(args.model, args.dir)
