import openai

def calculate_risk(likelihood, impact):
    return likelihood * impact

def refine_risk_with_llm(threat, likelihood, impact):
    prompt = f"""
    Given the following threat assessment:
    Threat: {threat}
    Likelihood: {likelihood}/5
    Impact: {impact}/5
    Provide a refined risk score between 1-25 and a brief justification.
    """
    
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "system", "content": "You are a cybersecurity risk analyst."},
                  {"role": "user", "content": prompt}]
    )
    
    return response["choices"][0]["message"]["content"].strip()

# Example threats
threats = [
    {"threat": "SQL Injection", "likelihood": 4, "impact": 5},
    {"threat": "Phishing Attack", "likelihood": 5, "impact": 3},
]

for threat in threats:
    base_risk = calculate_risk(threat["likelihood"], threat["impact"])
    refined_risk = refine_risk_with_llm(threat["threat"], threat["likelihood"], threat["impact"])
    print(f"Threat: {threat['threat']}, Base Risk Score: {base_risk}, Refined Risk: {refined_risk}")
