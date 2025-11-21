# main.py
import time
import json
from Scanner import SolanaTokenScanner
try:
    from config import ARKHAM_API_KEY
except ImportError:
    print("Error: config.py not found. Please create config.py and set ARKHAM_API_KEY.")
    exit(1)

if __name__ == "__main__":
    # List of Token Addresses to scan
    token_list = [
        "9DjLxqbtcBts43ZBafukyD7yY48AQu6p8ndMN5Lxpump", 
        "BNso1VUJnh4zcfpZa6986Ea66P6TCp59hvtNJ8b1X85",
        "C2omVhcvt3DDY77S2KZzawFJQeETZofgZ4eNWWkXpump",
        "8J69rbLTzWWgUJziFY8jeu5tDwEPBwUz4pKBMr5rpump",
        "Guo2AZPNQZ8z9juiJmzGUZwELncFCJLifgPdEUuypump",
        "FZACBfky96auikzegVAnP5boc24NnYHCJPzy4h8opump",
        "7Y2TPeq3hqw21LRTCi4wBWoivDngCpNNJsN1hzhZpump"
    ]
    
    print(f"Starting scan for {len(token_list)} tokens...\n")
    scanner = SolanaTokenScanner(ARKHAM_API_KEY)
    
    results = []
    for token in token_list:
        try:
            res = scanner.assess_token_risk(token)
            results.append(res)
        except Exception as e:
            print(f"Error processing {token}: {e}")
            results.append({"token": token, "error": str(e)})
        
        # Sleep to avoid Rate Limits
        time.sleep(1)
        
    # Output Results
    print("\n=== Scan Results ===\n")
    print(json.dumps(results, indent=2, ensure_ascii=False, default=str))