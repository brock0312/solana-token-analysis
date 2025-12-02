import requests
import time
from datetime import datetime, timedelta

class SolanaTokenScanner:
    def __init__(self, api_key):
        self.base_url = "https://api.arkm.com"
        self.headers = {"API-Key": api_key}
        # Hardcoded keywords for CEXs as whitelist
        self.cex_keywords = ["binance", "coinbase", "kraken", "okx", "bybit", "kucoin", "gate.io", "htx", "bitget", "upbit","crypto.com"]
        
    def _get(self, endpoint, params=None):
        # API query method
        try:
            for _ in range(3):
                response = requests.get(f"{self.base_url}{endpoint}", headers=self.headers, params=params)
                if response.status_code == 200:
                    return response.json()
                time.sleep(1)
            response.raise_for_status()
        except Exception as e:
            print(f"API Error: {e}")
            return None

    def _normalize_transfers_list(self, data):
        # Standardizes API response into a list format
        if not data: return []
        if isinstance(data, list): return data
        if isinstance(data, dict): return data.get('transfers', [])
        return []

    def check_database_status(self, token_address):
        # Pre-check the token address via the Arkham intelligence database, filter the existing tokens     
        data = self._get(f"/intelligence/address/{token_address}")
        
        if not data: 
            return None 

        entity = data.get('arkhamEntity')
        label = data.get('arkhamLabel')
        
        # If no entity/label info exists, then continue deep scan
        if not entity and not label:
            return None

        entity_name = entity.get('name', "Unknown") if entity else "Unknown"
        label_name = label.get('name', "Unknown") if label else "Unknown"
        full_name = (entity_name + " " + label_name).lower()

        # Check for high-risk labels(keywords were simply selected for possible existance)
        bad_keywords = ["scam","phish", "phishing", "rug","rugpull", "exploit", "hack", "heist"]
        if any(bad in full_name for bad in bad_keywords):
            return {
                "status": "KNOWN",
                "risk_score": 100,
                "label": "HIGH",
                "flags": [f"Arkham Database Flagged: {entity_name or label_name}"],
                "details": {"entity": entity_name, "reason": "Database Blacklist"}
            }

        # Check for trusted entities (use CEXs as whitelist in this demo)
        if any(good in full_name for good in self.cex_keywords):
            return {
                "status": "KNOWN",
                "risk_score": 0,
                "label": "LOW",
                "flags": [f"Trusted Entity Verified: {entity_name}"],
                "details": {"entity": entity_name, "reason": "Trusted Issuer"}
            }

        # Check for other established projects (e.g., Raydium, Jupiter)
        if entity:
            return {
                "status": "KNOWN",
                "risk_score": 0,
                "label": "LOW",
                "flags": [f"Established Project: {entity_name}"],
                "details": {"entity": entity_name, "reason": "Known Entity"}
            }

        return None

    def get_address_details(self, address):
        """
        Retrieves address creation time and funding source, 
        the basic idea is to find out if the deployer and the source addresses are fresh addresses.
        
        Note: It's easier to use GET/ intelligence/contract/address endpoint to find the deployer directly if accessible.
        """
        if not address: return None

        # Query incoming transfers only, limit 100 for example
        params = {
            "to": address,
            "chain": "solana",
            "limit": 100,
            "sortKey": "time",
            "sortDir": "asc"
            }
        
        tx_data = self._get("/transfers", params)
        tx_list = self._normalize_transfers_list(tx_data)
        
        # If no incoming tx found, query 'base' (all txs)
        if not tx_list:
            params = {
                "base": address, 
                "chain": "solana", 
                "limit": 100, 
                "sortKey": "time", 
                "sortDir": "asc"
                }
            tx_data = self._get("/transfers", params)
            tx_list = self._normalize_transfers_list(tx_data)

        if not tx_list:
            return {"address": address, "creation_time": None, "funder": None}

        # Sort by timestamp to ensure we always get the first transaction
        valid_txs = [t for t in tx_list if t.get('blockTimestamp')]
        if not valid_txs:
             return {"address": address, "creation_time": None, "funder": None}

        sorted_txs = sorted(valid_txs, key=lambda x: x['blockTimestamp'])
        first_tx = sorted_txs[0]
        
        ts = first_tx.get('blockTimestamp')
        creation_time = None
        if ts:
            creation_time = datetime.fromisoformat(ts.replace('Z', '+00:00')).replace(tzinfo=None)
            
        funder_address = None
        
        from_data = first_tx.get('fromAddress') or {}
        to_data = first_tx.get('toAddress') or {}
        
        from_addr = from_data.get('address')
        to_addr = to_data.get('address')
        
        from_addr = first_tx.get('fromAddress', {}).get('address')
        to_addr = first_tx.get('toAddress', {}).get('address')
        
        # Identify the funder address
        if to_addr == address and from_addr:
            funder_address = from_addr
        
        if funder_address == address: funder_address = None

        return {
            "address": address,
            "creation_time": creation_time,
            "funder": funder_address
        }

    def check_is_known_entity(self, address):
        """
        Since everytime we'll conduct the search for funder address multiple times,
        we need to check if a funder address belongs to a known entity (CEX for example) to prevent wrong scoring
        """
        data = self._get(f"/intelligence/address/{address}")
        if data:
            entity = data.get('arkhamEntity')
            if entity:
                name = entity.get('name', '').lower()
                if any(k in name for k in self.cex_keywords):
                    return True, entity.get('name')
        return False, None

    def analyze_dispersion_pattern(self, address):
        """
        Scammers and rugpuller usually use burner wallets to conduct the crimes, 
        which shows the 'distributor' or 'dispersion' patterns.
        If a funder address is related to multiple unique addresses with low frequency tx, considered sus.

        Logic: High ratio of unique receivers suggests a script funding multiple wallets.
        """
        if not address: return False
        params = {"from": address, "chain": "solana", "limit": 100}
        data = self._get("/transfers", params)
        tx_list = self._normalize_transfers_list(data)
        if not tx_list or len(tx_list) < 20: return False # Threshhold 20 tx
        
        receivers = set()
        for tx in tx_list:
            to_addr = tx.get('toAddress', {}).get('address')
            if to_addr: receivers.add(to_addr)
            
        unique_ratio = len(receivers) / len(tx_list)
        # Threshold: Over 50% unique receivers and more than 20 receivers
        if unique_ratio > 0.5 and len(receivers) > 20:
            return True
        return False

    def trace_funding_source(self, start_address, max_depth=3):
        # Recursive function to trace funding sources up to 3 hops from deployer address.
        # The higher the score, the higher the risk.
        chain_info = []
        current_addr = start_address
        trace_risk_score = 20 #It's always with risk as long as the contract is not deployed by trusted entity
        trace_stop_reason = "Max depth reached"
        
        for depth in range(max_depth + 1):
            details = self.get_address_details(current_addr)
            if not details: break
                
            creation_time = details['creation_time']
            funder = details['funder']
            
            age_days = -1
            if creation_time:
                age_days = (datetime.now() - creation_time).days
            
            layer_info = {
                "layer": depth,
                "address": current_addr,
                "age_days": age_days,
                "is_cex": False,
                "is_distributor": False,
                "risk_contribution": 0
            }

            # Check if the funder is known entity (skip for deployer)
            # Showing only CEX as demo
            if depth > 0:
                is_known, entity_name = self.check_is_known_entity(current_addr)
                if is_known:
                    layer_info['is_cex'] = True 
                    layer_info['entity_name'] = entity_name
                    layer_info['risk_contribution'] = -10 # Risk reduction should be designed depending on entity category.
                    trace_risk_score -= 10 
                    chain_info.append(layer_info)
                    trace_stop_reason = f"Found Trusted Entity: {entity_name}"
                    break

            # Wallet age scoring (newer wallets are higher risk)
            age_risk = 0
            if age_days != -1:
                if depth == 0: # Deployer
                    if age_days < 30: age_risk = 30
                    elif age_days < 90: age_risk = 20
                    elif age_days < 180: age_risk = 10
                else: # If the source addresses are also new, considered higher risk. 
                    if age_days < 90: age_risk = 20
                    elif age_days < 180: age_risk = 10
            
            layer_info['risk_contribution'] += age_risk
            trace_risk_score += age_risk

            # Dispersion pattern check
            if depth > 0:
                is_distributor = self.analyze_dispersion_pattern(current_addr)
                if is_distributor:
                    layer_info['is_distributor'] = True
                    layer_info['risk_contribution'] += 50
                    trace_risk_score += 50
            
            chain_info.append(layer_info)
            
            if not funder:
                trace_stop_reason = "No upstream funder found"
                break
            current_addr = funder
            time.sleep(0.5)

        return {"score": trace_risk_score, "chain": chain_info, "stop_reason": trace_stop_reason}

    def assess_token_risk(self, token_address):
        print(f"Analyzing Token: {token_address}...")
        
        # Step 0: Pre-check from Arkham database
        db_status = self.check_database_status(token_address)
        if db_status:
            print(f"  > Existing Entity Found: {db_status['label']} Risk")
            return {
                "token": token_address,
                "risk_assessment": {
                    "score": db_status['risk_score'],
                    "label": db_status['label'],
                    "flags": db_status['flags']
                },
                "details": db_status['details']
            }

        # Step 1: Deep scan for unknown token
        print("  > Unknown Token. Initiating Deep Scan...")
        
        token_params = {
            "base": token_address, 
            "chain": "solana", 
            "limit": 100, 
            "sortKey": "time", 
            "sortDir": "asc"
         }
        data = self._get("/transfers", token_params)
        tx_list = self._normalize_transfers_list(data)
        
        if not tx_list:
            return {"token": token_address, "error": "No token history found"}
            
        valid_txs = [t for t in tx_list if t.get('blockTimestamp')]
        if not valid_txs:
            return {"token": token_address, "error": "No valid timestamp data"}
            
        sorted_txs = sorted(valid_txs, key=lambda x: x['blockTimestamp'])
        first_tx = sorted_txs[0]
        from_data = first_tx.get('fromAddress') or {}
        to_data = first_tx.get('toAddress') or {}
        
        deployer = from_data.get('address')
        
        if not deployer:
             deployer = to_data.get('address')

        print(f"  > Identified Deployer: {deployer}")
        
        # Step 2: Trace funding
        funding_analysis = self.trace_funding_source(deployer, max_depth=3)
        
        # Step 3: Calculate final risk score
        final_score = 0
        final_score += funding_analysis['score']
        final_score = max(0, min(100, final_score))
        
        if final_score >= 70: label = "HIGH"
        elif final_score >= 30: label = "MEDIUM"
        else: label = "LOW"

        flags = []
        chain_desc = []
        for layer in funding_analysis['chain']:
            d = layer['layer']
            role = "Deployer" if d == 0 else f"Source-{d}"
            addr_short = f"{layer['address']}"
            
            desc_parts = [f"[{role}]"]
            if layer['age_days'] != -1:
                desc_parts.append(f"Age:{layer['age_days']}d")
            
            # If the deployer/source wallet was created shorter than 30/60 days, considered fresh
            if layer['age_days'] != -1 and ((d == 0 and layer['age_days'] < 30) or (d > 0 and layer['age_days'] <60)):
                flags.append(f"{role} is fresh wallet ({layer['age_days']} days)(Addr: {addr_short})")
                
            if layer.get('is_cex'):
                desc_parts.append("[CEX/SAFE]")
                flags.append(f"Funded by Trusted Entity: {layer.get('entity_name')}(Addr: {addr_short})")
                
            elif layer.get('is_distributor'):
                desc_parts.append("[DISTRIBUTOR]")
                flags.append(f"{role} shows suspicious dispersion pattern (Addr: {addr_short})")
            
            chain_desc.append(" ".join(desc_parts))
        # Token analysis output 
        return {
            "token": token_address,
            "deployer": deployer,
            "risk_assessment": {
                "score": final_score,
                "label": label,
                "flags": flags
            },
            "funding_chain_analysis": {
                "trace_log": chain_desc,
                "stop_reason": funding_analysis['stop_reason']
            }
        }