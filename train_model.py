import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import accuracy_score, classification_report
import pickle

df = pd.read_csv('data/email_fixed.csv', encoding='utf-8')  

df['Email Text'] = df['Email Text'].fillna('')  
df['Email Type'] = df['Email Type'].fillna('Safe').astype(str)

X = df['Email Text']
y = df['Email Type'].map({'Safe': 0, 'Phishing': 1})  

vectorizer = TfidfVectorizer(stop_words='english', max_features=5000)
X_vectorized = vectorizer.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(X_vectorized, y, test_size=0.3, random_state=42)

model = GradientBoostingClassifier(random_state=42)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print("Classification Report:\n", classification_report(y_test, y_pred))

with open('models/artifacts/model.pkl', 'wb') as model_file:
    pickle.dump(model, model_file)

with open('models/artifacts/vectorizer.pkl', 'wb') as vectorizer_file:
    pickle.dump(vectorizer, vectorizer_file)

print("Model and vectorizer saved!")
