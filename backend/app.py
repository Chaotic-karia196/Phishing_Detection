import os
import requests
from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from bs4 import BeautifulSoup, Comment
import re
import google.generativeai as genai
import json

# Load environment variables
load_dotenv()

HF_API_TOKEN = os.getenv("API_TOKEN")  # from your .env

# Configure the API with your API key
genai.configure(api_key=HF_API_TOKEN)  # Replace with your actual API key

# Set the model you want to use (e.g., Gemini 1.5 Flash)
model = genai.GenerativeModel("gemini-1.5-flash")

app = FastAPI()

# Enable CORS (for frontend use)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins (you can restrict in production)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def length_token(text: str) -> int:
    return len(text.split())

# Simplify HTML email content
def simplify_html(input_html: str) -> str:
    input_html = str(input_html)  # Ensure input is a string
    soup = BeautifulSoup(input_html, "html.parser")

    # Remove <style>, <script>, and comments
    for tag in soup(["style", "script"]):
        tag.decompose()
    for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
        comment.extract()

    processed_html = str(soup)

    # If short enough, return
    if length_token(processed_html) < 3000:
        return processed_html

    # Unwrap all tags except important ones
    important_tags = {"p", "a", "img", "strong", "em", "h1", "h2", "h3"}
    for tag in soup.find_all():
        if tag.name not in important_tags:
            tag.unwrap()
    processed_html = str(soup)

    # Remove empty tags
    for tag in soup.find_all():
        if not tag.get_text(strip=True):
            tag.decompose()
    processed_html = str(soup)

    # Simplify href/src
    for a in soup.find_all("a", href=True):
        a["href"] = re.sub(r"(http[s]?://)?(www\.)?", "", a["href"]).split('/')[0]
    for img in soup.find_all("img", src=True):
        img["src"] = re.sub(r"(http[s]?://)?(www\.)?", "", img["src"]).split('/')[0]
    processed_html = str(soup)

    # If still too long, trim tags
    while length_token(processed_html) > 3000:
        tags = soup.find_all()
        if not tags:
            break
        midpoint = len(tags) // 2
        tags[midpoint].decompose()
        processed_html = str(soup)

    return processed_html

# Generate phishing detection prompt
def generate_phishing_detection_prompt(email_content: str) -> str:
    prompt = f"""
    I want you to act as a spam detector to determine whether a given email is a phishing email or a legitimate email. Your analysis should be thorough and evidence-based. Phishing emails often impersonate legitimate brands and use social engineering techniques to deceive users. These techniques include, but are not limited to: fake rewards, fake warnings about account problems, and creating a sense of urgency or interest. Spoofing the sender address and embedding deceptive HTML links are also common tactics. Analyze the email by following these steps:
    
    1. Identify any impersonation of well-known brands.
    2. Examine the email header for spoofing signs, such as discrepancies in the sender name or email address.
    3. Evaluate the subject line for typical phishing characteristics (e.g., urgency, promise of reward). Note that the To address has been replaced with a dummy address.
    4. Analyze the email body for social engineering tactics designed to induce clicks on hyperlinks. Inspect URLs to determine if they are misleading or lead to suspicious websites.
    5. Provide a comprehensive evaluation of the email, highlighting specific elements that support your conclusion. Include a detailed explanation of any phishing or legitimacy indicators found in the email.
    6. Summarize your findings and provide your final verdict on the legitimacy of the email, supported by the evidence you gathered.

    Your output should be JSON-formatted text with the following keys:
    - is_phishing: a boolean value indicating whether the email is phishing (true) or legitimate (false)
    - phishing_score: phishing risk confidence score as an integer on a scale from 0 to 10
    - brand_impersonated: brand name associated with the email, if applicable
    - rationales: detailed rationales for the determination, up to 500 words
    - brief_reason: brief reason for the determination
    
    Email:
    '''{email_content}'''
    """
    return prompt

# API endpoint: classify a single email file
@app.post("/classify")
async def classify_email(file: UploadFile = File(...)):
    try:
        # Read email content
        raw_content = await file.read()
        email_content = raw_content.decode("utf-8", errors="ignore")

        # Simplify HTML
        simplified_content = simplify_html(email_content)

        # Create prompt
        prompt = generate_phishing_detection_prompt(simplified_content)

        # Call API
        response = model.generate_content(prompt)
        response_text = response.text

        try:
            response_json = json.loads(response_text)
        except json.JSONDecodeError:
            response_json = {
                "is_phishing": False,
                "phishing_score": 0,
                "brand_impersonated": None,
                "rationales": response_text,
                "brief_reason": "Parsing error"
            }

        return {"result": response_json}

    except Exception as e:
        return {"error": str(e)}