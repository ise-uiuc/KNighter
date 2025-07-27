import time

import tiktoken
from azure.ai.inference import ChatCompletionsClient
from azure.core.credentials import AzureKeyCredential
from google import genai
from openai import OpenAI

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    anthropic = None
    ANTHROPIC_AVAILABLE = False

from global_config import global_config, logger

azure_deepseek_client = None
deepseek_client = None
nv_client = None
openai_client = None
google_client = None
claude_client = None

local_deepseek_client = OpenAI(
    base_url="http://localhost:30000/v1",
    api_key="123",
)


model_config = {
    "model": "o3-mini",
    "openai_model": "gpt-4o",
    "local_deepseek_model": "deepseek-ai/DeepSeek-R1-Distill-Qwen-32B",
    "deepseek_model": "deepseek-reasoner",
    "model_o1": "o1-preview-2024-09-12",
    "claude_model": "claude-4-sonnet-20250514",
    "temperature": 0.7,
    "max_tokens": 16000,
}

encoding = tiktoken.encoding_for_model("gpt-4o")


def init_llm():
    key_config = global_config.get_key_config()
    global azure_deepseek_client, deepseek_client, nv_client, openai_client, google_client, claude_client, model_config

    if "azure_key" in key_config:
        azure_deepseek_client = ChatCompletionsClient(
            endpoint="XXXX", credential=AzureKeyCredential(key_config["azure_key"])
        )
    if "deepseek_key" in key_config:
        deepseek_client = OpenAI(
            api_key=key_config["deepseek_key"], base_url="https://api.deepseek.com/v1"
        )
    if "nv_key" in key_config:
        nv_client = OpenAI(
            base_url="https://integrate.api.nvidia.com/v1", api_key=key_config["nv_key"]
        )
    if "openai_key" in key_config:
        openai_client = OpenAI(api_key=key_config["openai_key"])

    if "google_key" in key_config:
        google_client = genai.Client(api_key=key_config["google_key"])
    
    if "claude_key" in key_config:
        if ANTHROPIC_AVAILABLE:
            claude_client = anthropic.Anthropic(api_key=key_config["claude_key"])
            logger.info("Claude client initialized successfully")
        else:
            logger.warning("Claude API key provided but anthropic library not available. Install with: pip install anthropic")

    if not any(
        [
            azure_deepseek_client,
            deepseek_client,
            nv_client,
            openai_client,
            google_client,
            claude_client,
        ]
    ):
        raise ValueError("No API key provided")

    model_config["model"] = key_config["model"]
    logger.info(f"Init LLM with model: {model_config['model']}")


def num_tokens_from_string(string: str) -> int:
    """Returns the number of tokens in a text string."""
    # For Claude models, we use an approximation since tiktoken is OpenAI-specific
    # Claude roughly uses 1 token per 4 characters for English text
    if model_config.get("model", "").startswith("claude"):
        return len(string) // 4
    
    num_tokens = len(encoding.encode(string))
    return num_tokens


def invoke_llm(
    prompt,
    temperature=model_config["temperature"],
    model=model_config["model"],
    max_tokens=model_config["max_tokens"],
) -> str:
    """Invoke the LLM model with the given prompt."""
    model = model_config["model"]

    if model == "gpt-4o" and model_config["model"] in [
        "google",
        "nv-deepseek",
        "deepseek-reasoner",
        "o3-mini",
        "local-deepseek",
        "claude",
        "claude-3-5-sonnet",
        "claude-3-5-haiku", 
        "claude-3-opus",
        "claude-4-sonnet",
    ]:
        model = model_config["model"]

    logger.info(f"start LLM process: {model}")
    num_tokens = num_tokens_from_string(prompt)
    logger.info("Token counts: {}".format(num_tokens))
    if num_tokens > 100000:
        logger.warning("Token counts exceed the limit. Skip.")
        return None

    failed_count = 0
    while True:
        try:
            if model in ["gpt-4o", "o1", "o3-mini", "o1-mini", "o1-preview", "o4-mini", "gpt-4.1"]:
                client = openai_client
            elif model == "deepseek-reasoner":
                client = deepseek_client
            elif model == "local-deepseek":
                client = local_deepseek_client
                model = model_config["local_deepseek_model"]
            elif model == "azure-deepseek":
                client = azure_deepseek_client
            elif model == "nv-deepseek":
                client = nv_client
            elif model == "google":
                client = google_client
            elif model in ["claude", "claude-3-5-sonnet", "claude-3-5-haiku", "claude-3-opus", "claude-4-sonnet"]:
                if not claude_client:
                    raise ValueError(f"Claude model {model} requested but Claude client not initialized. Check your claude_key configuration.")
                client = claude_client
            else:
                raise ValueError(f"Model {model} not supported")

            if model == "azure-deepseek":
                payload = {
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                }
                response = client.complete(payload)
            elif model in ["o1-preview", "o1-mini", "o1", "o3-mini", "o4-mini"]:
                response = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                )
            elif model == "nv-deepseek":
                response = client.chat.completions.create(
                    model="deepseek-ai/deepseek-r1",
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=max_tokens,
                    temperature=temperature,
                )
            elif model == "deepseek-reasoner":
                response = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=8192,
                )
            elif model == "google":
                response = client.models.generate_content(
                    model="gemini-2.0-flash",
                    contents=prompt,
                )
            elif model in ["claude", "claude-3-5-sonnet", "claude-3-5-haiku", "claude-3-opus", "claude-4-sonnet"]:
                # Map model names to actual Claude model identifiers
                claude_model_map = {
                    "claude": "claude-4-sonnet-20250514",  # Default to Claude 4 Sonnet
                    "claude-3-5-sonnet": "claude-3-5-sonnet-20241022", 
                    "claude-3-5-haiku": "claude-3-5-haiku-20241022",
                    "claude-3-opus": "claude-3-opus-20240229",
                    "claude-4-sonnet": "claude-4-sonnet-20250514"
                }
                actual_model = claude_model_map.get(model, model_config["claude_model"])
                
                response = client.messages.create(
                    model=actual_model,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    messages=[
                        {"role": "user", "content": prompt}
                    ]
                )
            else:
                response = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=temperature,
                    n=1,
                    max_tokens=max_tokens,
                )

        except Exception as e:
            logger.error("Error: {}".format(e))
            failed_count += 1
            if failed_count > 5:
                logger.error("Failed too many times. Skip.")
                raise e
            time.sleep(2)
        else:
            logger.info("finish LLM process")

            if isinstance(response, str):
                logger.warning("Response is a string")
                failed_count += 1
                if failed_count > 5:
                    logger.error("Failed too many times. Skip.")
                    return None
                time.sleep(2)
                continue
            if model == "google":
                return response.text
            elif model in ["claude", "claude-3-5-sonnet", "claude-3-5-haiku", "claude-3-opus", "claude-4-sonnet"]:
                # Claude returns a different response format
                answer = response.content[0].text
                if "<think>" in answer or "</think>" in answer:
                    # Delete the content between <think> and </think> tags
                    answer = answer.split("</think>")[-1].strip()
                return answer
            else:
                answer = response.choices[0].message.content
                if "<think>" in answer or "</think>" in answer:
                    # Delete the content between <think> and </think> tags
                    answer = answer.split("</think>")[-1].strip()
                return answer


def get_embeddings(text: str):
    """Get embeddings for the given text."""
    response = openai_client.embeddings.create(
        input=text, model="text-embedding-ada-002"
    )
    return response.data[0].embedding


def list_available_models() -> dict:
    """
    List all available models based on initialized clients.
    
    Returns:
        dict: Available models by provider
    """
    available = {
        "openai": [] if not openai_client else ["gpt-4o", "o1", "o3-mini", "o1-mini", "o1-preview"],
        "deepseek": [] if not deepseek_client else ["deepseek-reasoner"],
        "google": [] if not google_client else ["google"],
        "nvidia": [] if not nv_client else ["nv-deepseek"],
        "azure": [] if not azure_deepseek_client else ["azure-deepseek"],
        "local": ["local-deepseek"],  # Always available
        "claude": [] if not claude_client else ["claude", "claude-3-5-sonnet", "claude-3-5-haiku", "claude-3-opus", "claude-4-sonnet"]
    }
    
    # Filter out empty providers
    return {k: v for k, v in available.items() if v}


def get_model_info(model_name: str) -> dict:
    """
    Get information about a specific model.
    
    Args:
        model_name: Name of the model
        
    Returns:
        dict: Model information including provider, capabilities, etc.
    """
    model_info = {
        # OpenAI models
        "gpt-4o": {"provider": "OpenAI", "type": "chat", "max_tokens": 128000, "capabilities": ["reasoning", "coding"]},
        "o1": {"provider": "OpenAI", "type": "reasoning", "max_tokens": 65536, "capabilities": ["advanced_reasoning"]},
        "o3-mini": {"provider": "OpenAI", "type": "reasoning", "max_tokens": 65536, "capabilities": ["reasoning", "efficiency"]},
        
        # Claude models
        "claude": {"provider": "Anthropic", "type": "chat", "max_tokens": 200000, "capabilities": ["reasoning", "coding", "analysis"], "actual_model": "claude-4-sonnet-20250514"},
        "claude-3-5-sonnet": {"provider": "Anthropic", "type": "chat", "max_tokens": 200000, "capabilities": ["reasoning", "coding", "analysis"]},
        "claude-3-5-haiku": {"provider": "Anthropic", "type": "chat", "max_tokens": 200000, "capabilities": ["fast_response", "cost_effective"]},
        "claude-3-opus": {"provider": "Anthropic", "type": "chat", "max_tokens": 200000, "capabilities": ["advanced_reasoning", "complex_tasks"]},
        "claude-4-sonnet": {"provider": "Anthropic", "type": "chat", "max_tokens": 200000, "capabilities": ["latest_model", "enhanced_reasoning", "improved_coding"]},
        
        # Other models
        "deepseek-reasoner": {"provider": "DeepSeek", "type": "reasoning", "max_tokens": 8192, "capabilities": ["reasoning", "coding"]},
        "google": {"provider": "Google", "type": "chat", "max_tokens": 2097152, "capabilities": ["multimodal", "reasoning"]},
    }
    
    return model_info.get(model_name, {"provider": "Unknown", "type": "unknown", "capabilities": []})
