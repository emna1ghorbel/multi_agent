import json
import re
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig, pipeline
from core.config import LLM_MODEL

# ── Singletons: loaded once, reused on every call ────────────────────────────
_llm_instance = None
_tokenizer_instance = None

def get_llm():
    global _llm_instance, _tokenizer_instance

    if _llm_instance is None:  # Only load on first call — expensive operation

        # ── Tokenizer ────────────────────────────────────────────────────────
        _tokenizer_instance = AutoTokenizer.from_pretrained(
            LLM_MODEL,
            trust_remote_code=True  # Qwen has custom code in its repo; this allows it to run
        )

        # ── 4-bit Quantization Config ─────────────────────────────────────────
        quantization_config = BitsAndBytesConfig(
            load_in_4bit=True,               # Compress weights to 4-bit → ~4GB VRAM instead of 14GB
            bnb_4bit_compute_dtype=torch.bfloat16,  # Do the math in bfloat16 internally for stability
                                                     # (weights stay 4-bit, compute is higher precision)
            bnb_4bit_use_double_quant=True,  # Quantize the quantization constants too → saves ~0.4 extra bits/param
            bnb_4bit_quant_type="nf4"        # NormalFloat4: best quality 4-bit format for LLMs,
                                             # designed specifically for normally-distributed neural net weights
        )

        # ── Model Loading ─────────────────────────────────────────────────────
        model = AutoModelForCausalLM.from_pretrained(
            LLM_MODEL,
            quantization_config=quantization_config,  # Apply the 4-bit config above
            device_map="balanced",   # Split layers evenly across both T4 GPUs (vs "auto" which fills GPU 0 first)
            trust_remote_code=True,  # Same as tokenizer — needed for Qwen custom architecture
            low_cpu_mem_usage=True,  # Stream weights from disk instead of loading all into RAM first
                                     # Critical for 7B models to avoid CPU RAM spike during load
        )

        # ── Inference Pipeline ────────────────────────────────────────────────
        _llm_instance = pipeline(
            "text-generation",
            model=model,
            tokenizer=_tokenizer_instance,
            max_new_tokens=2048,       # Max tokens the model can generate per call
                                      # (doesn't count the input prompt, only the output)
            return_full_text=False,   # Return only the generated reply, not prompt + reply
            do_sample=False,          # Greedy decoding: always pick the highest-probability token
                                      # → deterministic, best for structured JSON output
            pad_token_id=_tokenizer_instance.eos_token_id,  # Tells the model what token to use for padding
                                                             # Qwen doesn't define a pad token by default → this silences the warning
            repetition_penalty=1.1,   # Penalize tokens that already appeared in the output
                                      # 1.0 = no penalty, >1.0 = discourages repetition
                                      # 1.1 is a safe value — prevents Qwen 7B from looping
        )

    return _llm_instance, _tokenizer_instance


def extract_json(text: str) -> str:
    # Find the first {...} block in the model output using regex
    # re.DOTALL makes '.' match newlines too — needed for multi-line JSON
    match = re.search(r"(\{.*\})", text, re.DOTALL)
    return match.group(1) if match else text  # Return JSON block if found, else return raw text


def llm_analyze(system_prompt: str, user_content: str) -> dict:
    llm, tokenizer = get_llm()

    # Build the chat message structure Qwen expects
    messages = [
        {"role": "system", "content": system_prompt},  # Instructions / persona for the model
        {"role": "user", "content": user_content}       # The actual input to analyze
    ]

    # Convert messages to a single string using Qwen's chat template
    # add_generation_prompt=True appends the "<|im_start|>assistant" token
    # so the model knows it should start generating a reply
    prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)

    try:
        results = llm(prompt)
        output = results[0]["generated_text"].strip()

        print(f"\n--- QWEN RESPONSE ---\n{output}\n-------------------")

        # Extract JSON from output and parse it into a Python dict
        return json.loads(extract_json(output))

    except Exception as e:
        # If anything fails (bad JSON, model error, etc.), return a safe fallback dict
        return {"error": str(e), "llm_failed": True}
