import os
import re
import time
import json
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

# --- NEW IMPORTS FROM PHASE 1 ---
import requests
import phonenumbers
import dns.resolver
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_analyzer.predefined_recognizers import PhoneRecognizer
from presidio_analyzer.nlp_engine import NlpEngineProvider

# --- AI & RAG IMPORTS ---
import google.generativeai as genai
from langchain_community.utilities import GoogleSearchAPIWrapper
from langchain_community.retrievers import WikipediaRetriever, ArxivRetriever
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.prompts import PromptTemplate
from langchain_core.messages import SystemMessage

load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GOOGLE_CSE_ID = os.getenv("GOOGLE_CSE_ID")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# --- GLOBAL STORAGE (For Phase 2 Dashboard) ---
SCAN_LOGS = []
STATS = {
    "total_scans": 0,
    "pii_blocked": 0,
    "hallucinations_found": 0,
    "verified_safe": 0
}

# --- CONFIGURATION ---
BASE_RISK_ADJUSTMENTS = {
    "DATE_TIME": -0.45,
    "NRP": -0.35,
}
PUBLIC_DATA_EXCEPTIONS = ["DATE_TIME", "NRP", "LOCATION", "ADDRESS"]

CLASSIFIER_SYSTEM_PROMPT = SystemMessage(
    content="You are a system that classifies user queries. Respond with ONLY ONE word: 'FACTUAL' if the query requires external knowledge retrieval (e.g., questions about history, science, specific people, or concepts), or 'CONVERSATIONAL' if it is a simple greeting, short command, compliment, or small talk."
)

# --- SETUP ENGINES ---
if not GEMINI_API_KEY:
    print("CRITICAL WARNING: GEMINI_API_KEY is missing in .env")
else:
    genai.configure(api_key=GEMINI_API_KEY)

# Models (Phase 1 Specs)
chat_model = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0.7, google_api_key=GEMINI_API_KEY)
analysis_model = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0.2, google_api_key=GEMINI_API_KEY)
correction_model = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0.4, google_api_key=GEMINI_API_KEY)
intent_classifier_model = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0.1, google_api_key=GEMINI_API_KEY)

# Retrievers
try:
    wiki_retriever = WikipediaRetriever(top_k_results=5, doc_content_chars_max=8000)
    arxiv_retriever = ArxivRetriever(top_k_results=3, doc_content_chars_max=8000)
    
    if GOOGLE_CSE_ID and GOOGLE_API_KEY:
        google_search_wrapper = GoogleSearchAPIWrapper(k=5)
        print("✅ Multi-source RAG (Wiki, ArXiv, Google) Initialized.")
    else:
        google_search_wrapper = None
        print("⚠️ Google Search Keys missing. Public Figure check will fail.")
        
except Exception as e:
    print(f"⚠️ Retriever Init Error: {e}")
    wiki_retriever = None
    arxiv_retriever = None
    google_search_wrapper = None

# PII Engine
provider = NlpEngineProvider(nlp_configuration={'nlp_engine_name': 'spacy', 'models': [{'lang_code': 'en', 'model_name': 'en_core_web_lg'}]})
nlp_engine = provider.create_engine()
phone_recognizer = PhoneRecognizer(context=["phone", "number", "contact", "call"])
analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
analyzer.registry.add_recognizer(phone_recognizer)
anonymizer = AnonymizerEngine()


# --- HELPER FUNCTIONS (Phase 1 Logic) ---

def invoke_with_retry(model, prompt, max_retries=3, tools=None):
    for attempt in range(max_retries):
        try:
            if tools: return model.invoke(prompt, tools=tools)
            else: return model.invoke(prompt)
        except Exception as e:
            if attempt + 1 == max_retries: raise
            time.sleep(2 ** attempt)

def check_url_validity(url):
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        if 200 <= response.status_code < 400: return "VALID"
        elif response.status_code >= 400: return f"INVALID (Status: {response.status_code})"
        else: return "INVALID (Unknown Status)"
    except requests.RequestException as e:
        return f"INVALID (Request Failed: {type(e).__name__})"

def extract_links(text):
    url_pattern = re.compile(r'https?:\/\/[^\s\/\.]+[^\s]+')
    return url_pattern.findall(text)

def check_wikipedia_for_public_figure(name):
    if not google_search_wrapper: return False
    name_parts = name.split()
    search_terms = [name]
    if len(name_parts) > 1: search_terms.append(name_parts[-1])
    
    for term in search_terms:
        try:
            results = google_search_wrapper.results(f'"{term}" wikipedia', num_results=3)
            for result in results:
                if 'wikipedia.org' in result.get('link', '').lower():
                    if term.lower() in result.get('title', '').lower():
                        return True
        except: pass
    return False

def verify_pii_entity(text, entity, analysis_model):
    ent_text = text[entity.start:entity.end]
    ent_type = entity.entity_type
    signals = {}

    if len(ent_text.split()) == 1 and len(ent_text) < 4: return None

    # 1. External Checks
    if ent_type == "PHONE_NUMBER":
        try:
            pn = phonenumbers.parse(ent_text, "IN")
            signals["phone_is_valid"] = phonenumbers.is_valid_number(pn)
        except: signals["phone_is_valid"] = False

    if ent_type == "EMAIL_ADDRESS":
        try:
            domain = ent_text.split("@")[-1]
            dns.resolver.resolve(domain, "MX")
            signals["domain_check_mx"] = True
        except: signals["domain_check_mx"] = False

    if ent_type == "PERSON":
        signals["public_figure"] = check_wikipedia_for_public_figure(ent_text)

    # 2. Contextual LLM Check
    try:
        context = text[max(0, entity.start-50):min(len(text), entity.end+50)]
        llm_prompt = f"Is '{ent_text}' in '...{context}...' Personally Identifiable Information (PII)? YES or NO."
        llm_resp = invoke_with_retry(analysis_model, llm_prompt).content
        signals["llm_confirmed_pii"] = "yes" in llm_resp.lower()
    except: signals["llm_confirmed_pii"] = False

    # 3. Score Calculation
    score = entity.score + BASE_RISK_ADJUSTMENTS.get(ent_type, 0)
    if signals.get("phone_is_valid"): score += 0.15
    if signals.get("domain_check_mx"): score += 0.10
    if signals.get("llm_confirmed_pii"): score += 0.25
    if signals.get("public_figure") and ent_type == "PERSON": score -= 0.25

    final_score = min(max(score, 0), 1)
    verdict = "HIGH" if final_score > 0.7 else ("MEDIUM" if final_score > 0.4 else "LOW")

    return {
        "entity": ent_text, "type": ent_type, "risk_score": f"{final_score:.2f}",
        "verdict": verdict, "signals": signals,
        "start_index": entity.start, "end_index": entity.end
    }

def custom_redact_pii(text, pii_details, start_offset):
    sorted_details = sorted(pii_details, key=lambda x: x['start_index'], reverse=True)
    modified_text = list(text)

    for detail in sorted_details:
        is_public_figure = detail['signals'].get('public_figure') and detail['type'] == 'PERSON'
        is_high_risk = detail['verdict'] == 'HIGH'
        is_public_data = detail['type'] in PUBLIC_DATA_EXCEPTIONS

        if is_high_risk or (not is_public_figure and not is_public_data):
            replacement = f"<{detail['type']}>"
            modified_text[detail['start_index']:detail['end_index']] = list(replacement)
    
    return "".join(modified_text)[start_offset:].strip()

# --- LOGGING HELPER ---
def log_activity(text, source, status, risk_type):
    global STATS
    STATS["total_scans"] += 1
    if status == "Risk":
        if "PII" in risk_type: STATS["pii_blocked"] += 1
        if "Hallucination" in risk_type: STATS["hallucinations_found"] += 1
    else:
        STATS["verified_safe"] += 1

    log_entry = {
        "id": len(SCAN_LOGS) + 1,
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "source": source,
        "snippet": text[:50] + "...",
        "status": status,
        "risk": risk_type
    }
    SCAN_LOGS.insert(0, log_entry)
    if len(SCAN_LOGS) > 50: SCAN_LOGS.pop()


# --- ROUTES ---

@app.route('/api/chat', methods=['POST'])
def internal_chat():
    data = request.get_json()
    user_msg = data.get('message', '')
    
    # 1. Intent Classification
    try:
        classification = invoke_with_retry(intent_classifier_model, [CLASSIFIER_SYSTEM_PROMPT, user_msg]).content.strip().upper()
    except: classification = "CONVERSATIONAL"
    
    # 2. Chat Response
    system_instruction = "You are a helpful assistant. Use Google Search for facts."
    prompt = [SystemMessage(content=system_instruction), user_msg]
    
    try:
        response = invoke_with_retry(chat_model, prompt).content.strip()
        log_activity(user_msg, "Internal Chat", "Safe", f"Response ({classification})")
        return jsonify({"response": response})
    except Exception as e:
        return jsonify({"response": f"Error: {str(e)}"})


@app.route('/analyze', methods=['POST'])
def analyze():
    # FULL PHASE 1 LOGIC
    data = request.get_json()
    text_to_analyze = data.get('text')
    original_user_query = data.get('user_query', '')
    
    analysis_results = {
        "hallucination_info": {"detected": False, "reason": "N/A", "correction": "N/A"},
        "pii_info": {"detected": False, "details": [], "refined_text": text_to_analyze}
    }

    # 1. Intent
    try:
        cls = invoke_with_retry(intent_classifier_model, [CLASSIFIER_SYSTEM_PROMPT, original_user_query]).content.strip().upper()
        is_factual = (cls == "FACTUAL")
    except: is_factual = True

    # 2. PII Detection (Combined Text)
    combined_text = f"{original_user_query} |::SEPARATOR::| {text_to_analyze}" if original_user_query else text_to_analyze
    sep_index = combined_text.find(" |::SEPARATOR::| ")
    start_index = sep_index + len(" |::SEPARATOR::| ") if sep_index != -1 else 0

    pii_hits = analyzer.analyze(text=combined_text, language="en", score_threshold=0.6)
    verified_pii = []
    high_risk_detected = False

    for hit in pii_hits:
        data = verify_pii_entity(combined_text, hit, analysis_model)
        if data:
            verified_pii.append(data)
            if data['verdict'] == 'HIGH': high_risk_detected = True

    analysis_results["pii_info"]["details"] = verified_pii
    if verified_pii:
        analysis_results["pii_info"]["detected"] = True
        analysis_results["pii_info"]["refined_text"] = custom_redact_pii(combined_text, verified_pii, start_index)
        
        if high_risk_detected:
            analysis_results["hallucination_info"]["detected"] = True
            analysis_results["hallucination_info"]["reason"] = "Policy Violation: High Risk PII Detected."
            analysis_results["hallucination_info"]["correction"] = analysis_results["pii_info"]["refined_text"]
            log_activity(text_to_analyze, "Internal Chat", "Risk", "Output PII")
            return jsonify(analysis_results)

    # 3. RAG Hallucination Check
    if is_factual:
        search_query = original_user_query
        context = ""
        
        # Build Context (Google + Wiki + ArXiv)
        if google_search_wrapper:
            try:
                res = google_search_wrapper.results(search_query, num_results=5)
                context += "--- GOOGLE ---\n" + "\n".join([r.get('snippet', '') for r in res]) + "\n"
            except: pass
        if wiki_retriever:
            try:
                docs = wiki_retriever.invoke(search_query)
                context += "--- WIKI ---\n" + "\n".join([d.page_content for d in docs]) + "\n"
            except: pass
        if arxiv_retriever:
            try:
                docs = arxiv_retriever.invoke(search_query)
                context += "--- ARXIV ---\n" + "\n".join([d.page_content for d in docs]) + "\n"
            except: pass

        # URL Validation
        links = extract_links(text_to_analyze)
        if links:
            context += "\n--- URL CHECK ---\n"
            for link in links: context += f"{link}: {check_url_validity(link)}\n"

        if context.strip():
            verify_prompt = f"""
            Context: {context}
            Statement: "{text_to_analyze}"
            
            1. Verify facts against context.
            2. Check URL validity from context.
            
            Format:
            Verification: [Supported/Contradicted/Not Mentioned]
            Reasoning: ...
            Correction/Refinement: [Corrected text or N/A]
            """
            try:
                resp = invoke_with_retry(analysis_model, verify_prompt).content
                if "Contradicted" in resp or "Not Mentioned" in resp:
                    analysis_results["hallucination_info"]["detected"] = True
                    analysis_results["hallucination_info"]["reason"] = resp
                    
                    # Extract Correction
                    match = re.search(r"Correction/Refinement:\s*(.+)", resp, re.DOTALL)
                    if match: 
                        analysis_results["hallucination_info"]["correction"] = match.group(1).strip()
                    
                    # Fallback Correction
                    if analysis_results["hallucination_info"]["correction"] in ["N/A", "None"]:
                        corr_resp = invoke_with_retry(correction_model, [SystemMessage(content="Provide the correct fact."), f"Correct: {text_to_analyze}"], tools=[{"google_search": {}}])
                        analysis_results["hallucination_info"]["correction"] = corr_resp.content.strip()
                        
                    log_activity(text_to_analyze, "Internal Chat", "Risk", "Hallucination")
                else:
                    log_activity(text_to_analyze, "Internal Chat", "Safe", "Verified Fact")
            except Exception as e:
                print(f"Verification Error: {e}")

    return jsonify(analysis_results)


@app.route('/scan', methods=['POST'])
def scan_text():
    data = request.get_json()
    text = data.get('text', '')
    local_pii = data.get('local_pii_detected', False)
    
    # Simple check for extension visual feedback
    if local_pii or ("@" in text and "." in text):
        log_activity(text, "Extension", "Risk", "PII Detected")
        return jsonify({"pii_detected": True})
    
    log_activity(text, "Extension", "Safe", "None")
    return jsonify({"pii_detected": False})

@app.route('/stats', methods=['GET'])
def get_stats():
    return jsonify({"stats": STATS, "logs": SCAN_LOGS})

if __name__ == '__main__':
    print("--- Phase 2 Backend (Phase 1 Logic Integrated) Running ---")
    app.run(host='127.0.0.1', port=5000, debug=True)