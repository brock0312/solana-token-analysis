# Solana Token Risk Scanner (with Arkham Intelligence API)

This is a Solana token risk assessment tool powered by the [Arkham Intelligence API](https://docs.intel.arkm.com/). 
This tool focuses on **Fund Flow Analysis** and **On-chain Archaeology** to detect potential Rug Pull risks based on entity behavior and funding sources.

##  Key Features

1.  **Recursive Funding Tracing**:
    *   Automatically traces the Deployer's funding source upstream for up to 3 hops.
    *   Identifies if funds originate from trusted entities (CEX in this demo) or suspicious chains of burner wallets.

2.  **Wallet Age Analysis**:
    *   Scores risk based on the creation date of the Deployer and its funding sources.
    *   High Risk Indicator: Both the Deployer and its funding sources are fresh wallets created very recently (e.g., < 30 days).

3.  **Dispersion Pattern Detection**:
    *   Detects if a funding source behaves like a "Distributor", namely sending funds to many unique addresses with low transaction counts, which is often a sign of wash trading or Sybil attacks.

4.  **Smart Filtering**:
    *   Pre-checks the Arkham Database to identify known assets or verified projects, preventing false positives on established tokens.

##  Risk Scoring Logic

Score Range: **0 - 100** (Higher score = Higher risk).

*   **HIGH (70-100)**: Deployer is a fresh wallet, funding source is untraceable or another fresh wallet. High probability of a Rug Pull.
*   **MEDIUM (30-69)**: Some risk factors present (e.g., Deployer is new, but funding source is established).
*   **LOW (0-30)**: Funds traceable to a known CEX (Binance, Coinbase) or a long-standing active wallet.

##  Installation & Usage

### Prerequisites
*   Python 3.8+
*   Arkham Intelligence API Key

### 1. Install Dependencies
```bash
pip install -r requirements.txt