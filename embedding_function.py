from langchain_openai import OpenAIEmbeddings

def get_embedding_function(api_key):
    
    embeddings = OpenAIEmbeddings(
        openai_api_key = api_key,
        model="text-embedding-3-large"
    )
    return embeddings