import requests
import time
from datetime import datetime, timedelta, timezone
import json

class SolanaTokenScanner:
    def __init__(self, api_key):
        self.base_url = "https://api.arkm.com"
        self.headers = {"API-Key": api_key}
        # Hardcoded keywords for CEXs as whitelist for back-up purposes
        self.cex_keywords = ["binance", "coinbase", "kraken", "okx", "bybit", "kucoin", "gate.io", "htx", "bitget", "upbit", "crypto.com", "circle", "tether"]
        
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
        if not data: return None 

        entity = data.get('arkhamEntity')
        label = data.get('arkhamLabel')

        # If no entity/label info exists, then continue deep scan
        if not entity and not label: 
            return None

        entity_name = entity.get('name', "Unknown") if entity else "Unknown"
        label_name = label.get('name', "Unknown") if label else "Unknown"
        full_name = (entity_name + " " + label_name).lower()

        # Check for high-risk labels(keywords were simply selected for possible existance)
        bad_keywords = ["scam", "phishing", "rug", "exploit", "hack", "heist"]
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
                "risk_score": 10, # Very low risk for established entities, but not 0
                "label": "LOW",
                "flags": [f"Established Project: {entity_name}"],
                "details": {"entity": entity_name, "reason": "Known Entity"}
            }
        return None

    def get_true_age_via_history(self, address):
        """
        /transfers api seems to have some limitations if a wallet has too many transactions.
        To avoid misjudging the creation time of a high-frequency transaction wallet(such as CEX hot wallet),
        we need to fetch the historical data of the wallet to get the real age.
        """
        params = {"chain": "solana"}
        data = self._get("/history/address/"+address, params)
        
        if not data: 
            return None
        
        # 解析 Arkham History 格式
        history_list = data.get('solana')
        
        if history_list and isinstance(history_list, list) and len(history_list) > 0:
            try:
                sorted_history = sorted(history_list, key=lambda x: x.get('time', '9999-12-31'))
                first_record = sorted_history[0]
                first_ts = first_record.get('time')
                
                if first_ts and isinstance(first_ts, str):
                    return datetime.fromisoformat(first_ts.replace('Z', '+00:00'))
            except Exception as e:
                print(f"Error parsing history date: {e}")
                return None
                
        return None

    def get_address_details(self, address):
        """
        Retrieves address creation time and funding source, 
        the basic idea is to find out if the deployer and the source addresses are new addresses.
        
        Note: It's easier to use GET/ intelligence/contract/address endpoint to find the deployer directly if accessible.
        """
        if not address: return None

        params = {
            "to": address,
            "chain": "solana",
            "limit": 100, 
            "sort": "time",
            "order": "asc"
        }
        
        tx_data = self._get("/transfers", params)
        tx_list = self._normalize_transfers_list(tx_data)
        
        if not tx_list:
            params["base"] = address
            del params["to"]
            tx_data = self._get("/transfers", params)
            tx_list = self._normalize_transfers_list(tx_data)

        if not tx_list:
            return {"address": address, "creation_time": None, "funder": None, "funder_entity": None, "tx_count": 0}

        valid_txs = [t for t in tx_list if t.get('blockTimestamp')]
        if not valid_txs:
             return {"address": address, "creation_time": None, "funder": None, "funder_entity": None, "tx_count": 0}

        sorted_txs = sorted(valid_txs, key=lambda x: x['blockTimestamp'])
        first_tx = sorted_txs[0]
        
        ts = first_tx.get('blockTimestamp')
        creation_time = None
        if ts:
            creation_time = datetime.fromisoformat(ts.replace('Z', '+00:00'))
            
        funder_address = None
        funder_entity_name = None
        
        from_data = first_tx.get('fromAddress') or {}
        to_data = first_tx.get('toAddress') or {}
        
        from_entity = first_tx.get('fromAddressEntity') or {}
        from_label = first_tx.get('fromAddressLabel') or {}
        
        entity_str = from_entity.get('name')
        if not entity_str: entity_str = from_label.get('name')

        from_addr = from_data.get('address')
        to_addr = to_data.get('address')
        
        if to_addr == address and from_addr:
            funder_address = from_addr
            funder_entity_name = entity_str
        
        if funder_address == address: 
            funder_address = None
            funder_entity_name = None

        return {
            "address": address,
            "creation_time": creation_time,
            "funder": funder_address,
            "funder_entity": funder_entity_name,
            "tx_count": len(tx_list)
        }

    def analyze_dispersion_pattern(self, address):
        """檢測分發模式"""
        if not address: return False
        params = {"from": address, "chain": "solana", "limit": 100}
        data = self._get("/transfers", params)
        tx_list = self._normalize_transfers_list(data)
        if not tx_list or len(tx_list) < 20: return False
        
        receivers = set()
        for tx in tx_list:
            to_addr = tx.get('toAddress', {}).get('address')
            if to_addr: receivers.add(to_addr)
            
        unique_ratio = len(receivers) / len(tx_list)
        if unique_ratio > 0.5 and len(receivers) > 20:
            return True
        return False

    def trace_funding_source(self, start_address, max_depth=3):
        """
        [V7 優化版]
        1. 若交易量滿且時間為0，呼叫 get_true_age_via_history 進行二次驗證。
        2. 若驗證為老錢包 (>180天)，豁免分發者檢測。
        3. 若驗證為新錢包 (<180天)，執行分發者檢測。
        """
        chain_info = []
        current_addr = start_address
        trace_risk_score = 0
        trace_stop_reason = "Max depth reached"
        
        for depth in range(max_depth + 1):
            details = self.get_address_details(current_addr)
            if not details: break
                
            creation_time = details['creation_time']
            funder = details['funder']
            funder_entity = details['funder_entity']
            tx_count = details.get('tx_count', 0)
            
            age_days = -1
            age_hours = 0
            
            if creation_time:
                now = datetime.now(timezone.utc)
                delta = now - creation_time
                age_days = delta.days
                age_hours = delta.seconds // 3600
            
            # === V7 核心邏輯：真實年齡二次驗證 ===
            is_verified_old_wallet = False # 標記是否通過了歷史快照驗證
            
            # 如果 transfers 資料顯示是極新的高頻錢包 (小於一天且滿100筆)
            if age_days < 1 and tx_count >= 100:
                # 調用 Portfolio History 查看更早的紀錄
                true_creation_time = self.get_true_age_via_history(current_addr)
                
                if true_creation_time:
                    true_delta = now - true_creation_time
                    true_age_days = true_delta.days
                    
                    # 更新為真實年齡
                    age_days = true_age_days
                    # 如果大於半年 (180天)
                    if true_age_days > 180:
                        is_verified_old_wallet = True
            
            layer_info = {
                "layer": depth,
                "address": current_addr,
                "age_days": age_days,
                "age_hours": age_hours,
                "is_cex": False,
                "is_verified_old": is_verified_old_wallet,
                "is_distributor": False,
                "entity_name": None,
                "risk_contribution": 0
            }

            # === 評分邏輯 ===
            age_risk = 0
            
            if age_days != -1:
                if is_verified_old_wallet:
                    # 是老錢包：給予極低風險甚至減分
                    age_risk = -10
                else:
                    # 是新錢包：照常評分
                    if depth == 0:
                        if age_days < 7: age_risk = 20
                        elif age_days < 14: age_risk = 15
                        elif age_days < 30: age_risk = 10
                    else:
                        if age_days < 30: age_risk = 15
                        elif age_days < 60: age_risk = 10

            layer_info['risk_contribution'] += age_risk
            trace_risk_score += age_risk

            # === 分發者檢測 (依據年齡判斷是否執行) ===
            if depth > 0:
                # 只有當它 "不是" 驗證過的老錢包時，我們才懷疑它是惡意分發者
                # 因為 CEX 熱錢包行為跟分發者一樣，但它是安全的
                if not is_verified_old_wallet:
                    is_distributor = self.analyze_dispersion_pattern(current_addr)
                    if is_distributor:
                        layer_info['is_distributor'] = True
                        layer_info['risk_contribution'] += 30
                        trace_risk_score += 30
            
            chain_info.append(layer_info)
            
            # Funder 是已知實體
            if funder_entity:
                layer_info['funded_by_entity'] = funder_entity
                trace_risk_score -= 40
                cex_layer = {
                    "layer": depth + 1,
                    "address": funder,
                    "age_days": -1,
                    "is_cex": True,
                    "entity_name": funder_entity,
                    "risk_contribution": -20
                }
                chain_info.append(cex_layer)
                trace_risk_score -= 20
                trace_stop_reason = f"Funded by Known Entity: {funder_entity}"
                break

            if not funder:
                trace_stop_reason = "No upstream funder found"
                break
            current_addr = funder
            time.sleep(0.5)

        return {"score": trace_risk_score, "chain": chain_info, "stop_reason": trace_stop_reason}

    def assess_token_risk(self, token_address):
        print(f"Analyzing Token: {token_address}...")
        
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

        print("  > Unknown Token. Initiating Deep Scan...")
        
        token_params = {
            "base": token_address, 
            "chain": "solana", 
            "limit": 100, 
            "sort": "time", 
            "order": "asc"
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
        if not deployer: deployer = to_data.get('address')

        print(f"  > Identified Deployer: {deployer}")
        
        funding_analysis = self.trace_funding_source(deployer, max_depth=3)
        
        final_score = 0
        final_score += funding_analysis['score']
        final_score = max(0, min(100, final_score))
        
        if final_score >= 70: label = "HIGH"
        elif final_score >= 40: label = "MEDIUM"
        else: label = "LOW"

        flags = []
        chain_desc = []
        for layer in funding_analysis['chain']:
            d = layer['layer']
            role = "Deployer" if d == 0 else f"Source-{d}"
            
            if layer.get('is_cex'):
                chain_desc.append(f"[{role}] is Known Entity: {layer.get('entity_name')} [SAFE]")
                flags.append(f"Fund source is {layer.get('entity_name')}")
                continue

            desc_parts = [f"[{role}]"]
            
            if layer.get('is_verified_old'):
                desc_parts.append(f"Verified Old Wallet ({layer['age_days']} days)")
            elif layer['age_days'] != -1:
                age_str = f"{layer['age_days']}d"
                if layer['age_days'] == 0: age_str += f" {layer['age_hours']}h"
                desc_parts.append(f"Age: {age_str}")
                
                is_fresh = False
                if (d==0 and layer['age_days']<30) or (d>0 and layer['age_days']<60):
                    is_fresh = True
                    flags.append(f"{role} is fresh wallet ({age_str})")

            if layer.get('funded_by_entity'):
                 desc_parts.append(f"<- Funded by: {layer.get('funded_by_entity')}")

            if layer.get('is_distributor'):
                desc_parts.append("[DISTRIBUTOR]")
                flags.append(f"{role} suspicious dispersion")
            
            chain_desc.append(" ".join(desc_parts))

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