from langchain_community.embeddings import OllamaEmbeddings

def get_embeddings():
    return OllamaEmbeddings(model="deepseek-coder:6.7b")
