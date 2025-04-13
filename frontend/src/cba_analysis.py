"""
Cost-Benefit Analysis (CBA) for Risk Treatment
Hashim Abdulla
due date: 4/5/2025
This module implements automated CBA calculations for risk mitigation decisions
by comparing Annual Loss Expectancy (ALE) before and after applying security controls.
"""

class CostBenefitAnalysis:
    """Class for performing Cost-Benefit Analysis on security controls."""

    def calculate_cba(self, ale_prior, ale_post, acs):
        """
        Calculate the Cost-Benefit Analysis for a security control.
        
        Args:
            ale_prior: Estimated annual financial loss before mitigation
            ale_post: Expected annual loss after mitigation
            acs: Annual cost of security measures
            
        Returns:
            float: The CBA result (positive is beneficial)
        """
        return ale_prior - ale_post - acs
    
    def analyze_control(self, control_name, ale_prior, ale_post, acs):
        """
        Analyze a single security control and print results.
        
        Args:
            control_name: Name of the security control
            ale_prior: Estimated annual financial loss before mitigation
            ale_post: Expected annual loss after mitigation
            acs: Annual cost of security measures
        """
        cba = self.calculate_cba(ale_prior, ale_post, acs)
        risk_reduction = ale_prior - ale_post
        risk_reduction_percentage = (risk_reduction / ale_prior * 100) if ale_prior > 0 else 0
        
        print(f"\nControl: {control_name}")
        print("-" * 40)
        print(f"Prior ALE: ${ale_prior:,.2f}")
        print(f"Post ALE: ${ale_post:,.2f}")
        print(f"Annual Control Cost: ${acs:,.2f}")
        print(f"Risk Reduction: ${risk_reduction:,.2f} ({risk_reduction_percentage:.2f}%)")
        print(f"CBA Result: ${cba:,.2f}")
        
        if cba > 0:
            print("Recommendation: Implement (Positive CBA)")
        else:
            print("Recommendation: Do not implement (Negative CBA)")


def main():
    """Main function to demonstrate CBA calculation."""
    analyzer = CostBenefitAnalysis()
    
    # Example 1 - from the assignment
    print("EXAMPLE 1 - FROM ASSIGNMENT")
    ale_prior = 50000  # $50,000 loss expected before mitigation
    ale_post = 10000   # $10,000 loss expected after mitigation
    acs = 15000        # $15,000 annual cost of security control
    
    cba_result = analyzer.calculate_cba(ale_prior, ale_post, acs)
    print(f"Cost-Benefit Analysis Result: ${cba_result}")
    
    # Example 2 - Full analysis of the same control
    print("\nEXAMPLE 2 - DETAILED ANALYSIS")
    analyzer.analyze_control(
        "Network Firewall Upgrade",
        ale_prior,
        ale_post,
        acs
    )
    
    # Example 3 - Analysis of a control with negative CBA
    print("\nEXAMPLE 3 - CONTROL WITH NEGATIVE CBA")
    analyzer.analyze_control(
        "Expensive Security Solution",
        30000,  # Prior ALE
        20000,  # Post ALE
        15000   # Annual cost
    )
    
    # Example 4 - Analysis of a control with positive CBA
    print("\nEXAMPLE 4 - CONTROL WITH POSITIVE CBA")
    analyzer.analyze_control(
        "Security Awareness Training",
        35000,  # Prior ALE
        15000,  # Post ALE
        5000    # Annual cost
    )


if __name__ == "__main__":
    main()
