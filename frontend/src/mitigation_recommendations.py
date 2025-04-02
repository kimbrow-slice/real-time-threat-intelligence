"""
Automated Risk Mitigation Recommendations Module
Name: Hashim Abdulla/ Mohamed Elgasim
Due Date: 4/1/2025

This module provides functionality to automatically generate security mitigation 
recommendations based on detected threat types. It offers both general and specific
recommendations for common security threats. (Keep in mind, when putting in threat names, the function is case-sensitive.)
"""

# Dictionary of our chosen (currently supported) threats and their mitigation recommendations
MITIGATION_DATABASE = {
    "SQL Injection": {
        "description": "Attackers insert malicious SQL code to manipulate databases",
        "recommendations": [
            "Implement parameterized queries/prepared statements",
            "Use an ORM (Object-Relational Mapping) framework",
            "Apply input validation and sanitization",
            "Deploy a Web Application Firewall (WAF)",
            "Follow the principle of least privilege for database accounts"
        ],
        "resources": [
            "OWASP SQL Injection Prevention Cheat Sheet"
        ]
    },
    "Phishing": {
        "description": "Deceptive attempts to steal sensitive information",
        "recommendations": [
            "Implement email filtering and spam protection",
            "Enforce multi-factor authentication (MFA)",
            "Conduct regular employee security awareness training",
            "Deploy anti-phishing toolbars/plugins",
            "Establish a process for reporting suspicious emails"
        ],
        "resources": [
            "SANS Phishing Prevention Guidelines"
        ]
    },
    "DDoS": {
        "description": "Distributed Denial of Service attacks that overwhelm systems",
        "recommendations": [
            "Implement rate limiting and traffic filtering",
            "Use cloud-based DDoS protection services",
            "Increase bandwidth capacity (over-provisioning)",
            "Configure network hardware against DDoS attacks",
            "Develop and test a DDoS response plan"
        ],
        "resources": [
            "US-CERT DDoS Mitigation Guidelines"
        ]
    },
    "Unpatched Software": {
        "description": "Software with known vulnerabilities that haven't been updated",
        "recommendations": [
            "Implement an automated patch management system",
            "Maintain a complete software inventory",
            "Set up a vulnerability scanning schedule",
            "Prioritize patches based on criticality",
            "Test patches before deployment to production"
        ],
        "resources": [
            "NIST Patch Management Guidelines"
        ]
    },
    "Weak Passwords": {
        "description": "Easily guessable credentials that can be compromised",
        "recommendations": [
            "Enforce strong password policies",
            "Implement multi-factor authentication",
            "Use a password manager",
            "Set up account lockout policies",
            "Conduct regular password audits"
        ],
        "resources": [
            "NIST Password Guidelines"
        ]
    },
    "Insider Threat": {
        "description": "Malicious actions from current or former employees",
        "recommendations": [
            "Implement the principle of least privilege",
            "Use monitoring and behavior analytics",
            "Enforce account termination procedures",
            "Conduct regular access reviews",
            "Develop an insider threat program"
        ],
        "resources": [
            "CERT Insider Threat Guidelines"
        ]
    },
    "Malware": {
        "description": "Malicious software designed to damage or infiltrate systems",
        "recommendations": [
            "Deploy and maintain updated anti-malware solutions",
            "Implement application whitelisting",
            "Conduct regular system scans",
            "Use email and web filtering",
            "Segment networks to contain potential infections"
        ],
        "resources": [
            "CISA Malware Prevention Guidelines"
        ]
    }
}

# General recommendations that apply to most security threats
GENERAL_RECOMMENDATIONS = [
    "Implement defense-in-depth strategies",
    "Maintain regular security training for all staff",
    "Follow the principle of least privilege",
    "Perform regular security assessments",
    "Keep all systems and software updated"
]


def recommend_mitigation(threat_name):
    """
    Retrieve mitigation recommendations for a specific threat.
    
    Args:
        threat_name: Name of the threat to get recommendations for
        
    Returns:
        Dictionary containing description, specific recommendations, and resources
    """
    # Check if we have specific recommendations for this threat
    if threat_name in MITIGATION_DATABASE:
        return MITIGATION_DATABASE[threat_name]
    else:
        # Return general recommendations if no specific ones are available
        return {
            "description": "Unclassified security threat",
            "recommendations": GENERAL_RECOMMENDATIONS,
            "resources": ["NIST Cybersecurity Framework", "OWASP Top 10"]
        }


def get_mitigation_for_threat_list(threats):
    """
    Get mitigation recommendations for a list of threats.
    
    Args:
        threats: List of threat dictionaries (each with a 'name' field)
        
    Returns:
        Dictionary mapping each threat name to its mitigation recommendations
    """
    recommendations = {}
    
    for threat in threats:
        threat_name = threat["name"]
        recommendations[threat_name] = recommend_mitigation(threat_name)
    
    return recommendations


def format_recommendation_report(threat_name):
    """
    Create a formatted string report for mitigation recommendations.
    
    Args:
        threat_name: Name of the threat to generate recommendations for
        
    Returns:
        Formatted string with recommendations
    """
    mitigation = recommend_mitigation(threat_name)
    
    report = f"MITIGATION RECOMMENDATIONS FOR: {threat_name}\n"
    report += "=" * (len(report) - 1) + "\n\n"
    
    report += f"Description: {mitigation['description']}\n\n"
    
    report += "Recommended Actions:\n"
    for i, action in enumerate(mitigation['recommendations'], 1):
        report += f"{i}. {action}\n"
    
    report += "\nAdditional Resources:\n"
    for resource in mitigation['resources']:
        report += f"• {resource}\n"
        
    return report


# Example usage to better showcase the recommendation system for the assignment's purposes
if __name__ == "__main__":
    # Example of getting a recommendation for a specific threat
    print(format_recommendation_report("Phishing"))
    print("\n" + "-" * 50 + "\n")
    
    # Example of processing multiple threats
    sample_threats = [
        {"name": "SQL Injection", "risk_score": 20},
        {"name": "Unpatched Software", "risk_score": 15},
        {"name": "Unknown Threat", "risk_score": 10}
    ]
    
    # Get recommendations for all threats
    all_recommendations = get_mitigation_for_threat_list(sample_threats)
    
    # Display the top recommendation for each threat
    print("TOP RECOMMENDATIONS SUMMARY:")
    for threat_name, mitigation in all_recommendations.items():
        print(f"• {threat_name}: {mitigation['recommendations'][0]}")
