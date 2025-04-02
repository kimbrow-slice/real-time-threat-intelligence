"""
Dynamic Risk Prioritization Model
This module provides functionality to prioritize security risks based on multiple factors
and their weighted importance.

Name: Hashim Abdulla
Due date: 4/1/2025
"""

def calculate_weighted_score(threat):
    """
    Calculate a weighted risk score based on multiple risk factors.
    
    Each threat should contain:
    - impact: The potential damage if exploited (1-10)
    - likelihood: The probability of occurrence (1-10)
    - exploitability: How easy it is to exploit (1-10)
    - remediation_cost: Cost to fix (1-10, higher means more expensive)
    
    Weights can be adjusted based on organizational priorities.
    """
    weights = {
        'impact': 0.4,
        'likelihood': 0.3,
        'exploitability': 0.2,
        'remediation_cost': 0.1
    }
    
    score = 0
    for factor, weight in weights.items():
        if factor in threat:
            score += threat[factor] * weight
    
    # If the threat already has a pre-calculated risk_score, incorporate it
    if 'risk_score' in threat:
        # Blend the pre-calculated score (30%) with our weighted calculation (70%)
        score = (score * 0.7) + (threat['risk_score'] * 0.3)
    
    return score

def prioritize_risks(threats, threshold=None):
    """
    Prioritize security threats based on their risk scores.
    
    Args:
        threats: List of threat dictionaries containing risk factors
        threshold: Optional minimum risk score to include in results
        
    Returns:
        List of threats sorted by calculated risk score in descending order
    """
    # Calculate weighted scores for each threat
    for threat in threats:
        threat['calculated_score'] = calculate_weighted_score(threat)
    
    # Sort threats by calculated score
    sorted_threats = sorted(threats, key=lambda x: x['calculated_score'], reverse=True)
    
    # Filter by threshold if provided
    if threshold is not None:
        sorted_threats = [t for t in sorted_threats if t['calculated_score'] >= threshold]
    
    return sorted_threats

def get_risk_level(score):
    """
    Convert numerical risk score to categorical risk level.
    
    Args:
        score: Calculated risk score
        
    Returns:
        String representing risk level: Critical, High, Medium, or Low
    """
    if score >= 8:
        return "Critical"
    elif score >= 6:
        return "High"
    elif score >= 4:
        return "Medium"
    else:
        return "Low"

def generate_risk_report(threats, top_n=None):
    """
    Generate a detailed risk report for the top threats.
    
    Args:
        threats: List of prioritized threats
        top_n: Optional number of top threats to include
        
    Returns:
        List of threat dictionaries with additional risk level information
    """
    prioritized = prioritize_risks(threats)
    
    if top_n:
        prioritized = prioritized[:top_n]
    
    # Add risk level category to each threat
    for threat in prioritized:
        threat['risk_level'] = get_risk_level(threat['calculated_score'])
    
    return prioritized


# Example usage in order to showcase functionality better for task 3 assignment purposes 
if __name__ == "__main__":
    # Sample threat data
    threats = [
        {
            "name": "SQL Injection", 
            "risk_score": 20,
            "impact": 8,
            "likelihood": 6,
            "exploitability": 9,
            "remediation_cost": 5
        },
        {
            "name": "Phishing", 
            "risk_score": 30,
            "impact": 7,
            "likelihood": 9,
            "exploitability": 7,
            "remediation_cost": 6
        },
        {
            "name": "DDoS", 
            "risk_score": 25,
            "impact": 9,
            "likelihood": 5,
            "exploitability": 4,
            "remediation_cost": 7
        },
        {
            "name": "Unpatched Software",
            "risk_score": 15,
            "impact": 7,
            "likelihood": 8,
            "exploitability": 8,
            "remediation_cost": 3
        }
    ]
    
    # Generate a report of the top 3 risks
    risk_report = generate_risk_report(threats, top_n=3)
    
    # Display the report
    print("RISK PRIORITIZATION REPORT")
    print("==========================")
    for i, threat in enumerate(risk_report, 1):
        print(f"{i}. {threat['name']} - {threat['risk_level']} Risk")
        print(f"   Score: {threat['calculated_score']:.2f}")
        print(f"   Impact: {threat['impact']}/10")
        print(f"   Likelihood: {threat['likelihood']}/10")
        print(f"   Exploitability: {threat['exploitability']}/10")
        print(f"   Remediation Cost: {threat['remediation_cost']}/10")
        print()
