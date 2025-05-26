from fastapi import FastAPI
from pydantic import BaseModel
import pickle
from fastapi.middleware.cors import CORSMiddleware

class EmailInput(BaseModel):
    email: str

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],  
    allow_headers=["*"],  
)

with open('model.pkl', 'rb') as model_file:
    model = pickle.load(model_file)

with open('vectorizer.pkl', 'rb') as vectorizer_file:
    vectorizer = pickle.load(vectorizer_file)

@app.post("/predict")
async def predict(email: EmailInput):
    email_text = email.email
    email_vector = vectorizer.transform([email_text])

    prediction = model.predict(email_vector)[0]
    prediction_proba = model.predict_proba(email_vector)[0]
    confidence = prediction_proba[1] if prediction == 1 else prediction_proba[0]
    prediction_label = "Safe Email" if prediction == 0 else "Phishing Email"

    return {
        "prediction": prediction_label,
        "confidence": float(confidence)
    }
