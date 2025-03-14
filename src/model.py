import time

import tiktoken
from azure.ai.inference import ChatCompletionsClient
from azure.core.credentials import AzureKeyCredential
from google import genai
from openai import OpenAI

from local_config import get_key_config, logger

azure_deepseek_client = None
deepseek_client = None
nv_client = None
openai_client = None
google_client = None
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
    "temperature": 0.7,
    "max_tokens": 16000,
}

encoding = tiktoken.encoding_for_model("gpt-4o")


def init_llm():
    key_config = get_key_config()
    global azure_deepseek_client, deepseek_client, nv_client, openai_client, google_client, model_config

    azure_deepseek_client = ChatCompletionsClient(
        endpoint="XXXX", credential=AzureKeyCredential(key_config["azure_key"])
    )
    deepseek_client = OpenAI(
        api_key=key_config["deepseek_key"], base_url="https://api.deepseek.com/v1"
    )
    nv_client = OpenAI(
        base_url="https://integrate.api.nvidia.com/v1", api_key=key_config["nv_key"]
    )
    openai_client = OpenAI(api_key=key_config["openai_key"])
    google_client = genai.Client(api_key=key_config["google_key"])

    model_config["model"] = key_config["model"]
    logger.info(f"Init LLM with model: {model_config['model']}")


def num_tokens_from_string(string: str) -> int:
    """Returns the number of tokens in a text string."""
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

    # if model == "gpt-4o" and model_config["model"] in ["o1", "o3-mini", "o1-mini", "o1-preview"]:
    #     model = "o1-mini"
    if model == "gpt-4o" and model_config["model"] in [
        "google",
        "nv-deepseek",
        "deepseek-reasoner",
        "o3-mini",
        "local-deepseek",
    ]:
        model = model_config["model"]
        # model = "local-deepseek"

    logger.info(f"start LLM process: {model}")
    num_tokens = num_tokens_from_string(prompt)
    logger.info("Token counts: {}".format(num_tokens))
    if num_tokens > 100000:
        logger.warning("Token counts exceed the limit. Skip.")
        return None

    failed_count = 0
    while True:
        try:
            if model in ["gpt-4o", "o1", "o3-mini", "o1-mini", "o1-preview"]:
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
            else:
                raise ValueError(f"Model {model} not supported")

            if model == "azure-deepseek":
                payload = {
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                }
                response = client.complete(payload)
            elif model in ["o1-preview", "o1-mini", "o1", "o3-mini"]:
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

            answer = response.choices[0].message.content
            if "<think>" in answer:
                # Delete the content between <think> and </think> tags
                answer = answer.split("</think>")[-1]
            return answer
