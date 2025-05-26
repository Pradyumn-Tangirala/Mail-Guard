# Phishing Email Detection System

## Project Overview

This project is designed to detect phishing emails using machine learning techniques. Phishing attacks are a common method used by cybercriminals to deceive individuals into revealing sensitive information. The system analyzes the textual content of emails (specifically, the subject line and body) and classifies them as either **phishing** or **legitimate**. By implementing this tool, the project aims to improve email security for users and reduce the likelihood of falling victim to phishing scams.

---

## Key Features

- **Accurate Phishing Detection**  
  Utilizes machine learning algorithms to identify phishing patterns in email text with high accuracy.

- **User-Friendly Interface**  
  Provides a clean and intuitive interface that allows users to easily input and analyze email content.

- **Real-Time Feedback**  
  Delivers immediate classification results, along with insights into the prediction process.

---

## Technologies Used

### Languages and Frameworks
- **Python**: Backend logic, machine learning model development, and API handling.
- **JavaScript**: Frontend interactivity.
- **HTML/CSS**: Structure and styling of the frontend interface.
- **FastAPI**: Modern web framework for building REST APIs.

### Libraries and Tools
- **Scikit-learn**: For building and training classification models.
- **TfidfVectorizer**: Converts raw email text into numerical features.
- **Uvicorn**: ASGI server for serving the FastAPI backend.
- **Nginx (optional)**: For production deployment (static files and reverse proxying).
- **Git/GitHub**: Version control and collaborative development.

---

## Project Scope

The system focuses exclusively on **textual analysis**, including:
- Subject line
- Email body

> **Note**: It does **not** analyze:
> - Attachments  
> - Embedded images  
> - Clickable links or URLs  

This limited scope is intentional, providing a lightweight and focused solution for initial phishing detection based solely on message content.

---

## Expected Outcomes

- A fully functional email analysis system capable of classifying emails as phishing or legitimate.
- A scalable and easy-to-integrate solution that can be used in larger email platforms or cybersecurity tools.
- Enhanced awareness and proactive defense mechanisms for users against email-based threats.
