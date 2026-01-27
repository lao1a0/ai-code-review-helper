"""
LLM Service for code review
"""
import json
import logging
from typing import Optional, Dict, Any
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from config.settings import LLM_CONFIG

logger = logging.getLogger(__name__)

class LLMService:
    """Unified LLM service for code review"""
    
    def __init__(self):
        self._chat_model = None
        self._initialize_model()
    
    def _initialize_model(self):
        """Initialize the LLM model"""
        try:
            self._chat_model = ChatOpenAI(
                model=LLM_CONFIG['OPENAI_MODEL'],
                temperature=LLM_CONFIG['OPENAI_TEMPERATURE'],
                api_key=LLM_CONFIG['OPENAI_API_KEY']
            )
            logger.info(f"LLM model initialized: {LLM_CONFIG['OPENAI_MODEL']}")
        except Exception as e:
            logger.error(f"Failed to initialize LLM model: {e}")
            raise
    
    def get_detailed_review(self, file_data: Dict[str, Any]) -> list:
        """
        Get detailed code review with structured JSON output
        """
        if not file_data:
            logger.info("No file data provided for detailed review")
            return []
        
        try:
            user_prompt = json.dumps(file_data, ensure_ascii=False, indent=2)
            
            system_prompt = self._get_prompt('detailed_review')
            if not system_prompt:
                logger.error("Failed to load detailed review prompt")
                return []
            
            if not self._chat_model:
                logger.error("Chat model not initialized")
                return []
            
            prompt = ChatPromptTemplate.from_messages([
                ("system", system_prompt),
                ("human", user_prompt)
            ])
            
            chain = prompt | self._chat_model | JsonOutputParser()
            result = chain.invoke({})
            
            logger.info(f"Detailed review completed for {file_data.get('file_meta', {}).get('path', 'unknown')}")
            return result if isinstance(result, list) else []
            
        except Exception as e:
            logger.error(f"Error during detailed review: {e}")
            return []
    
    def get_general_review(self, file_data: Dict[str, Any]) -> str:
        """
        Get general code review with markdown output
        """
        if not file_data:
            logger.info("No file data provided for general review")
            return ""
        
        try:
            user_prompt = json.dumps(file_data, ensure_ascii=False, indent=2)
            
            system_prompt = self._get_prompt('general_review')
            if not system_prompt:
                logger.error("Failed to load general review prompt")
                return ""
            
            if not self._chat_model:
                logger.error("Chat model not initialized")
                return ""
            
            prompt = ChatPromptTemplate.from_messages([
                ("system", system_prompt),
                ("human", user_prompt)
            ])
            
            chain = prompt | self._chat_model
            result = chain.invoke({})
            
            logger.info(f"General review completed for {file_data.get('file_path', 'unknown')}")
            return str(result.content) if hasattr(result, 'content') else str(result)
            
        except Exception as e:
            logger.error(f"Error during general review: {e}")
            return f"Error during review: {e}"
    
    def _get_prompt(self, prompt_type: str) -> str:
        """Get prompt from configuration"""
        try:
            import yaml
            with open('config/prompts.yml', 'r', encoding='utf-8') as f:
                prompts = yaml.safe_load(f)
                return prompts.get(prompt_type, {}).get('system_prompt', '')
        except Exception as e:
            logger.error(f"Failed to load prompts: {e}")
            return ""

# Global instance
_llm_service = None

def get_llm_service() -> LLMService:
    """Get global LLM service instance"""
    global _llm_service
    if _llm_service is None:
        _llm_service = LLMService()
    return _llm_service
