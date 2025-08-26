"""Simple and clean LLM model interface supporting both cloud and local models"""

import time
from typing import Any, Dict, Optional

from google import genai
from openai import OpenAI

from global_config import global_config, logger

try:
    import anthropic

    ANTHROPIC_AVAILABLE = True
except ImportError:
    anthropic = None
    ANTHROPIC_AVAILABLE = False

# Global clients
clients: Dict[str, Any] = {}
model_config = {
    "model": "gpt-4o",
    "temperature": 1.0,
    "max_tokens": 16000,
}


def init_llm():
    """Initialize LLM clients from configuration"""
    keys = global_config.get_key_config()

    # Initialize OpenAI client (or compatible)
    if "openai_key" in keys:
        clients["openai"] = OpenAI(api_key=keys["openai_key"])

    # Initialize local/custom OpenAI-compatible client
    if "base_url" in keys:
        clients["local"] = OpenAI(
            base_url=keys["base_url"], api_key=keys.get("api_key", "dummy")
        )

    # Initialize Claude client
    if "claude_key" in keys and ANTHROPIC_AVAILABLE:
        clients["claude"] = anthropic.Anthropic(api_key=keys["claude_key"])

    # Initialize Google client
    if "google_key" in keys:
        clients["google"] = genai.Client(api_key=keys["google_key"])

    # Initialize DeepSeek client
    if "deepseek_key" in keys:
        clients["deepseek"] = OpenAI(
            api_key=keys["deepseek_key"], base_url="https://api.deepseek.com/v1"
        )

    # Initialize custom providers
    providers = keys.get("providers", {})
    for name, config in providers.items():
        clients[name] = OpenAI(
            base_url=config["base_url"], api_key=config.get("api_key", "dummy")
        )

    # Set model configuration from config.yaml
    model_config["model"] = global_config.get("model", "gpt-4o")
    model_config["temperature"] = global_config.get("temperature", 1.0)
    model_config["max_tokens"] = global_config.get("max_tokens", 16000)

    logger.info(f"Init LLM with model: {model_config['model']}")

    if not clients:
        raise ValueError("No LLM clients configured")


def get_client_and_model(model_name: str) -> tuple:
    """Determine which client to use and actual model name"""

    # Model to client mapping
    model_mapping = {
        # OpenAI models
        "gpt-4o": ("openai", "gpt-4o"),
        "o1": ("openai", "o1"),
        "o3-mini": ("openai", "o3-mini"),
        "o4-mini": ("openai", "o4-mini"),
        "o1-preview": ("openai", "o1-preview"),
        "gpt-5": ("openai", "gpt-5"),
        # Claude models
        "claude": ("claude", "claude-3-5-sonnet-20241022"),
        "claude-3-5-sonnet": ("claude", "claude-3-5-sonnet-20241022"),
        "claude-3-5-haiku": ("claude", "claude-3-5-haiku-20241022"),
        "claude-3-opus": ("claude", "claude-3-opus-20240229"),
        # Google models
        "google": ("google", "gemini-2.0-flash-exp"),
        "gemini": ("google", "gemini-2.0-flash-exp"),
        # DeepSeek models
        "deepseek-reasoner": ("deepseek", "deepseek-reasoner"),
        "deepseek-chat": ("deepseek", "deepseek-chat"),
    }

    # Check if it's a known model
    if model_name in model_mapping:
        client_name, actual_model = model_mapping[model_name]
        if client_name in clients:
            return clients[client_name], actual_model

    # Check if it's a local model (format: local:model_name)
    if model_name.startswith("local:") and "local" in clients:
        actual_model = model_name[6:]  # Remove "local:" prefix
        return clients["local"], actual_model

    # Check custom providers (format: provider:model_name)
    if ":" in model_name:
        provider, actual_model = model_name.split(":", 1)
        if provider in clients:
            return clients[provider], actual_model

    # Default to local client if available
    if "local" in clients:
        return clients["local"], model_name

    # Fallback to OpenAI if available
    if "openai" in clients:
        return clients["openai"], model_name

    raise ValueError(f"No client available for model {model_name}")


def invoke_llm(
    prompt: str,
    temperature: Optional[float] = None,
    model: Optional[str] = None,
    max_tokens: Optional[int] = None,
) -> Optional[str]:
    """Invoke LLM with the given prompt"""

    model = model or model_config["model"]
    temperature = (
        temperature if temperature is not None else model_config["temperature"]
    )
    max_tokens = max_tokens or model_config["max_tokens"]

    logger.info(f"Start LLM process: {model}")

    # Simple token check
    if len(prompt) > 400000:  # ~100k tokens
        logger.warning("Prompt too long, skipping")
        return None

    # Get client and actual model name
    try:
        client, actual_model = get_client_and_model(model)
    except ValueError as e:
        logger.error(f"Error getting client and model for  {model}")
        logger.error(str(e))
        return None

    # Retry logic
    for attempt in range(6):
        try:
            # Handle different client types
            if isinstance(
                client, anthropic.Anthropic if ANTHROPIC_AVAILABLE else type(None)
            ):
                # Claude API
                response = client.messages.create(
                    model=actual_model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=max_tokens,
                    temperature=temperature,
                )
                answer = response.content[0].text

            elif isinstance(client, genai.Client):
                response = client.models.generate_content(
                    model=actual_model,
                    contents=prompt,
                )
                answer = response.text

            else:  # OpenAI or compatible
                kwargs = {
                    "model": actual_model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_completion_tokens": max_tokens,
                }

                # Only add temperature for models that support it
                no_temp_models = ["o1", "o3-mini", "o4-mini", "o1-preview", "gpt-5"]
                if not any(m in actual_model for m in no_temp_models):
                    kwargs["temperature"] = temperature

                response = client.chat.completions.create(**kwargs)
                answer = response.choices[0].message.content

            logger.info("Finish LLM process")

            # Remove think tags if present
            if answer and "<think>" in answer:
                answer = answer.split("</think>")[-1].strip()

            return answer

        except Exception as e:
            logger.error(f"Error attempt {attempt + 1}: {e}")
            if attempt >= 5:
                logger.error("Failed too many times")
                raise e
            time.sleep(2)

    return None


def get_embeddings(text: str) -> list:
    """Get embeddings using OpenAI API"""
    if "openai" not in clients:
        raise ValueError("OpenAI client required for embeddings")

    response = clients["openai"].embeddings.create(
        input=text, model="text-embedding-ada-002"
    )
    return response.data[0].embedding


# Backwards compatibility
def num_tokens_from_string(string: str) -> int:
    """Simple token approximation"""
    return len(string) // 4
