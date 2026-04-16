import pandas as pd
import sys

AI_OUTPUT = "ai_results.csv"
RULE_OUTPUT = "rule_results.csv"
HYBRID_OUTPUT = "hybrid_results.csv"

def main(ai_output=AI_OUTPUT, rule_output=RULE_OUTPUT, hybrid_output=HYBRID_OUTPUT):
    print("[LANGuard HYBRID] Starting hybrid detection...")
    try:
        ai_results = pd.read_csv(ai_output)
    except FileNotFoundError:
        print(f"[LANGuard HYBRID] AI results not found")
        sys.exit(1)

    try:
        rule_results = pd.read_csv(rule_output)
    except FileNotFoundError:
        rule_results = pd.DataFrame(columns=['Date', 'Alert_Name', 'Severity'])

    hybrid_df = ai_results.copy()
    for _, rule_row in rule_results.iterrows():
        matching_rows = hybrid_df[
            (hybrid_df['window_start'].astype(str) >= rule_row['Date']) &
            (hybrid_df['window_start'].astype(str) <= rule_row['Date'])
        ]
        if not matching_rows.empty:
            hybrid_df.loc[matching_rows.index, 'ai_status'] = 'ANOMALY'

    hybrid_df.to_csv(hybrid_output, index=False)
    print(f"[LANGuard HYBRID] Hybrid results saved to {hybrid_output}")
    return hybrid_df

if __name__ == "__main__":
    main()