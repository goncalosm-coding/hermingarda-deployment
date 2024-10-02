import argparse
from langchain_chroma import Chroma
from langchain_core.prompts import ChatPromptTemplate
from embedding_function import get_embedding_function
from openai import OpenAI

CHROMA_PATH = "chroma"
PROMPT_TEMPLATE = """
You are an assistant designed to provide detailed answers based on medical research documents. 

1. When given a medical-related question, please provide a detailed and thorough answer using only the information contained in the provided context.

2. Do not include any external knowledge or generalizations in these cases; rely solely on the content from the documents. Use specific medical terminology, explanations, and examples where applicable to ensure the response is suitable for a medical exam context.

3. For casual conversations or general questions (e.g., "How are you?", "Tell me a joke"), feel free to respond in a friendly manner and provide an appropriate answer without relying on the medical documents.

Context:

{context}

---

Question: {question}

Please ensure that your answer fully addresses the question using the appropriate guidelines above.
"""

def main():
    # Create CLI.
    parser = argparse.ArgumentParser()
    parser.add_argument("query_text", type=str, help="The query text.")
    parser.add_argument("api_key", type=str, help="User's OpenAI API key.")
    args = parser.parse_args()
    query_text = args.query_text
    api_key = args.api_key
    query_rag(query_text, api_key)

def log_gpt4_usage(response):
    total_tokens = response.usage.total_tokens
    prompt_tokens = response.usage.prompt_tokens
    completion_tokens = response.usage.completion_tokens
    
    # Example GPT-4 pricing: adjust based on your model and currency (€0.03 per 1k tokens)
    cost_per_1k_tokens = 5.00 / 1000000  # Cost per token in euros
    total_cost = total_tokens * cost_per_1k_tokens
    
    print(f"Total tokens used: {total_tokens} (Prompt: {prompt_tokens}, Completion: {completion_tokens})")
    print(f"Cost for this query: €{total_cost:.4f}")
    return total_cost

def query_rag(query_text: str, api_key: str):
    # Create OpenAI client with the user's API key
    client = OpenAI(api_key=api_key)

    embedding_function = get_embedding_function()

    # Load the existing database.
    db = Chroma(
        collection_name="medicine-research",
        embedding_function=embedding_function,
        persist_directory=CHROMA_PATH,  # Where to save data locally, remove if not necessary
    )

    # Search the DB.
    results = db.similarity_search_with_score(query_text, k=5)

    context_text = "\n\n---\n\n".join([doc.page_content for doc, _score in results])
    prompt_template = ChatPromptTemplate.from_template(PROMPT_TEMPLATE)
    prompt = prompt_template.format(context=context_text, question=query_text)

    # Use GPT-4 model
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "user", "content": prompt}
        ],
    )

    # Log GPT-4 token usage and calculate cost
    log_gpt4_usage(response)
    response_text = response.choices[0].message.content

    sources = [doc.metadata.get("id", None) for doc, _score in results]
    formatted_response = f"Response: {response_text}\nSources: {sources}"
    print(formatted_response)
    return response_text

if __name__ == "__main__":
    main()