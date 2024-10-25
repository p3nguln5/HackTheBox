import requests
import json
import secrets
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256

class CTFSolver:
    def __init__(self, url):
        self.url = url
        self.session = requests.Session()
        self.initialized = False
        print(f"\n{'='*50}")
        print(f"Starting CTF Solver for URL: {url}")
        print(f"{'='*50}\n")
    
    def get_parameters(self):
        """Step 1: Get the DH parameters"""
        print("\n[Step 1] Requesting Diffie-Hellman parameters...")
        response = requests.post(f'{self.url}/api/request-session-parameters')
        print(f"Response status: {response.status_code}")
        print(f"Raw response: {response.content.decode()}")
        
        params = json.loads(response.content)
        self.g = int(params['g'], 16)
        self.p = int(params['p'], 16)
        print(f"[+] Parameters received:")
        print(f"    g (generator) = {self.g} (0x{self.g:x})")
        print(f"    p (prime)     = {self.p} (0x{self.p:x})")
        print(f"    Prime size: {self.p.bit_length()} bits")
        
    def generate_keys(self):
        """Generate our DH keypair"""
        print("\n[Step 2] Generating client keypair...")
        self.private_key = secrets.randbelow(self.p)
        self.public_key = pow(self.g, self.private_key, self.p)
        # Convert to hex and ensure it matches server format
        self.public_key_hex = hex(self.public_key)
        print(f"[+] Generated private key: (hidden for security)")
        print(f"[+] Generated public key (hex): {self.public_key_hex}")
        
    def init_session(self):
        """Step 3: Initialize session and exchange keys"""
        print("\n[Step 3] Initializing session with server...")
        try:
            # Clean up hex string to remove 'L' suffix if present
            cleaned_pub_key = self.public_key_hex
            if cleaned_pub_key.endswith('L'):
                cleaned_pub_key = cleaned_pub_key[:-1]
            
            # Create payload with hex string
            payload = {'client_public_key': int(self.public_key)}
            print(f"[>] Sending payload: {payload}")
            
            response = requests.post(f'{self.url}/api/init-session', json=payload)
            print(f"[<] Response status: {response.status_code}")
            print(f"[<] Raw response: {response.content.decode()}")
            
            if response.status_code != 200:
                print(f"[-] Server returned error status: {response.status_code}")
                return False
            
            data = json.loads(response.content)
            
            if 'server_public_key' in data:
                self.server_public_key = int(data['server_public_key'], 16)
                print(f"[+] Server's public key: {hex(self.server_public_key)}")
                
                # Calculate shared secret and derive session key
                shared_secret = pow(self.server_public_key, self.private_key, self.p)
                print(f"[+] Calculated shared secret: {hex(shared_secret)}")
                
                self.session_key = sha256(str(shared_secret).encode()).digest()
                print(f"[+] Derived session key (SHA256): {self.session_key.hex()}")
                
                self.initialized = True
                return True
            else:
                print(f"[-] No server public key in response: {data}")
                return False
                
        except Exception as e:
            print(f"[-] Error during session initialization: {str(e)}")
            print("[-] Full error:")
            import traceback
            print(traceback.format_exc())
            return False
    
    def get_challenge(self):
        """Step 4: Get encrypted challenge"""
        print("\n[Step 4] Requesting encrypted challenge...")
        response = requests.post(f'{self.url}/api/request-challenge')
        print(f"[<] Response status: {response.status_code}")
        print(f"[<] Raw response: {response.content.decode()}")
        
        data = json.loads(response.content)
        encrypted_challenge = b64decode(data['encrypted_challenge'])
        print(f"[+] Received encrypted challenge (b64 decoded): {encrypted_challenge.hex()}")
        
        # Decrypt challenge
        iv = encrypted_challenge[:16]
        ciphertext = encrypted_challenge[16:]
        print(f"[+] IV: {iv.hex()}")
        print(f"[+] Ciphertext: {ciphertext.hex()}")
        
        cipher = AES.new(self.session_key, AES.MODE_CBC, iv)
        self.challenge = unpad(cipher.decrypt(ciphertext), 16)
        self.challenge_hash = sha256(self.challenge).hexdigest()
        print(f"[+] Decrypted challenge: {self.challenge.hex()}")
        print(f"[+] Challenge hash: {self.challenge_hash}")
        
    def get_flag(self):
        """Step 5: Send encrypted packet with 'flag' action"""
        print("\n[Step 5] Requesting flag...")
        # Encrypt packet
        iv = secrets.token_bytes(16)
        cipher = AES.new(self.session_key, AES.MODE_CBC, iv)
        encrypted_packet = iv + cipher.encrypt(pad(b'flag', 16))
        
        payload = {
            'challenge': self.challenge_hash,
            'packet_data': b64encode(encrypted_packet).decode()
        }
        print(f"[>] Sending payload:")
        print(f"    Challenge hash: {payload['challenge']}")
        print(f"    Encrypted packet (b64): {payload['packet_data']}")
        
        response = requests.post(f'{self.url}/api/dashboard', json=payload)
        print(f"[<] Response status: {response.status_code}")
        print(f"[<] Raw response: {response.content.decode()}")
        
        try:
            data = json.loads(response.content)
            if 'packet_data' in data:
                encrypted_flag = b64decode(data['packet_data'])
                iv = encrypted_flag[:16]
                ciphertext = encrypted_flag[16:]
                print(f"[+] Received encrypted flag:")
                print(f"    IV: {iv.hex()}")
                print(f"    Ciphertext: {ciphertext.hex()}")
                
                cipher = AES.new(self.session_key, AES.MODE_CBC, iv)
                flag = unpad(cipher.decrypt(ciphertext), 16).decode()
                print(f"\n[!!!] FLAG FOUND: {flag}")
                return flag
            else:
                print(f"[-] Error getting flag: {data}")
                return None
        except Exception as e:
            print(f"[-] Error processing response: {str(e)}")
            return None

def main():
    url = "http://83.136.252.233:31091"
    solver = CTFSolver(url)
    
    try:
        # Execute all steps
        solver.get_parameters()
        solver.generate_keys()
        if solver.init_session():
            solver.get_challenge()
            flag = solver.get_flag()
            if flag:
                print("\n[+] Challenge completed successfully!")
                print(f"[+] Final Flag: {flag}")
            else:
                print("\n[-] Failed to retrieve flag")
    except Exception as e:
        print(f"\n[-] Error occurred: {str(e)}")
        import traceback
        print(f"[-] Traceback:")
        print(traceback.format_exc())

if __name__ == "__main__":
    main()
