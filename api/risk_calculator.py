import datetime

# Define a minimum risk score
MIN_RISK_SCORE = 1.0

def calculate_risk(likelihood, impact, last_seen):

    days_since_last_seen = (datetime.datetime.now() - last_seen).days
    decay_factor = max(0.1, 1 - (0.05 * days_since_last_seen))  # Decay factor over time
    risk_score = round((likelihood * impact) * decay_factor, 2)
    
    # Ensure the risk score is not below the minimum
    return max(risk_score, MIN_RISK_SCORE)


def get_risk_label(score):
    if score >= 4.0:
        return "Critical Risk"
    elif score >= 3.0:
        return "High Risk"
    elif score >= 2.0:
        return "Moderate Risk"
    elif score >= 1.0:
        return "Low Risk"
    else:
        return "No Risk"