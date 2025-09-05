import os
import json
import hashlib
import base64
import secrets
from datetime import datetime
from pathlib import Path
import streamlit as st
import io
import tempfile

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

class EncryptionError(Exception):
    """Custom exception for encryption-related errors"""
    pass

class AdvancedEncryption:
    """Advanced encryption class supporting multiple algorithms"""
    
    def __init__(self):
        self.supported_algorithms = {
            'caesar': 'Caesar Cipher',
            'vigenere': 'Vigenère Cipher', 
            'xor': 'XOR Cipher',
            'substitution': 'Substitution Cipher',
            'fernet': 'Fernet (AES-based)' if CRYPTO_AVAILABLE else None
        }
        # Remove None values
        self.supported_algorithms = {k: v for k, v in self.supported_algorithms.items() if v is not None}
        self.alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        
    def generate_key(self, algorithm, password=None):
        """Generate encryption key based on algorithm"""
        if algorithm == 'caesar':
            return secrets.randbelow(25) + 1  # 1-25 to avoid 0
        elif algorithm == 'vigenere':
            return password or self._generate_random_key(16)
        elif algorithm == 'xor':
            return password or self._generate_random_key(32)
        elif algorithm == 'substitution':
            return self._generate_substitution_key()
        elif algorithm == 'fernet' and CRYPTO_AVAILABLE:
            if password:
                return self._derive_fernet_key(password)
            return Fernet.generate_key()
        else:
            raise EncryptionError(f"Unsupported algorithm: {algorithm}")
    
    def _generate_random_key(self, length):
        """Generate random key of specified length"""
        return ''.join(secrets.choice(self.alphabet + self.alphabet.lower() + '0123456789') 
                      for _ in range(length))
    
    def _generate_substitution_key(self):
        """Generate substitution cipher key"""
        shuffled = list(self.alphabet)
        for i in range(len(shuffled)):
            j = secrets.randbelow(len(shuffled))
            shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
        return ''.join(shuffled)
    
    def _derive_fernet_key(self, password):
        """Derive Fernet key from password"""
        if not CRYPTO_AVAILABLE:
            raise EncryptionError("Cryptography library not available")
        
        password_bytes = password.encode()
        salt = b'salt_1234567890'  # In production, use random salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        return key
    
    def caesar_cipher(self, text, key, decrypt=False):
        """Caesar cipher implementation"""
        shift = -key if decrypt else key
        result = ""
        for char in text:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                result += chr((ord(char) + shift - ascii_offset) % 26 + ascii_offset)
            else:
                result += char
        return result
    
    def vigenere_cipher(self, text, key, decrypt=False):
        """Vigenère cipher implementation"""
        key = str(key).upper()
        result = ""
        key_index = 0
        
        for char in text:
            if char.isalpha():
                char_upper = char.upper()
                key_char = key[key_index % len(key)]
                shift = ord(key_char) - ord('A')
                
                if decrypt:
                    shift = -shift
                
                encrypted_char = chr((ord(char_upper) - ord('A') + shift) % 26 + ord('A'))
                result += encrypted_char if char.isupper() else encrypted_char.lower()
                key_index += 1
            else:
                result += char
        return result
    
    def xor_cipher(self, text, key, decrypt=False):
        """XOR cipher implementation"""
        result = ""
        key_bytes = str(key).encode() if isinstance(key, (str, int)) else key
        
        for i, char in enumerate(text):
            key_char = key_bytes[i % len(key_bytes)]
            if isinstance(key_char, str):
                key_char = ord(key_char)
            result += chr(ord(char) ^ key_char)
        
        return result
    
    def substitution_cipher(self, text, key, decrypt=False):
        """Substitution cipher implementation"""
        key = str(key)
        if len(key) != 26:
            raise EncryptionError("Substitution key must be 26 characters long")
            
        if decrypt:
            # Create reverse mapping
            mapping = {key[i]: self.alphabet[i] for i in range(26)}
        else:
            mapping = {self.alphabet[i]: key[i] for i in range(26)}
        
        result = ""
        for char in text:
            if char.upper() in mapping:
                encrypted_char = mapping[char.upper()]
                result += encrypted_char if char.isupper() else encrypted_char.lower()
            else:
                result += char
        return result
    
    def fernet_cipher(self, text, key, decrypt=False):
        """Fernet encryption implementation"""
        if not CRYPTO_AVAILABLE:
            raise EncryptionError("Cryptography library not available for Fernet")
        
        try:
            fernet = Fernet(key)
            if decrypt:
                return fernet.decrypt(text.encode()).decode()
            else:
                return fernet.encrypt(text.encode()).decode()
        except Exception as e:
            raise EncryptionError(f"Fernet operation failed: {str(e)}")
    
    def encrypt_text(self, text, algorithm, key):
        """Encrypt text using specified algorithm"""
        if algorithm == 'caesar':
            return self.caesar_cipher(text, key)
        elif algorithm == 'vigenere':
            return self.vigenere_cipher(text, key)
        elif algorithm == 'xor':
            return self.xor_cipher(text, key)
        elif algorithm == 'substitution':
            return self.substitution_cipher(text, key)
        elif algorithm == 'fernet':
            return self.fernet_cipher(text, key)
        else:
            raise EncryptionError(f"Unsupported algorithm: {algorithm}")
    
    def decrypt_text(self, text, algorithm, key):
        """Decrypt text using specified algorithm"""
        if algorithm == 'caesar':
            return self.caesar_cipher(text, key, decrypt=True)
        elif algorithm == 'vigenere':
            return self.vigenere_cipher(text, key, decrypt=True)
        elif algorithm == 'xor':
            return self.xor_cipher(text, key, decrypt=True)
        elif algorithm == 'substitution':
            return self.substitution_cipher(text, key, decrypt=True)
        elif algorithm == 'fernet':
            return self.fernet_cipher(text, key, decrypt=True)
        else:
            raise EncryptionError(f"Unsupported algorithm: {algorithm}")

def initialize_session_state():
    """Initialize Streamlit session state variables"""
    if 'encryption_history' not in st.session_state:
        st.session_state.encryption_history = []
    if 'generated_key' not in st.session_state:
        st.session_state.generated_key = None
    if 'algorithm' not in st.session_state:
        st.session_state.algorithm = 'caesar'

def add_to_history(operation, algorithm, filename, timestamp):
    """Add operation to history"""
    st.session_state.encryption_history.append({
        'operation': operation,
        'algorithm': algorithm,
        'filename': filename,
        'timestamp': timestamp
    })
    # Keep only last 10 operations
    if len(st.session_state.encryption_history) > 10:
        st.session_state.encryption_history.pop(0)

def main():
    """Main Streamlit application"""
    st.set_page_config(
        page_title="Advanced File Encryption Tool",
        page_icon="🔒",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    initialize_session_state()
    encryptor = AdvancedEncryption()
    
    # Custom CSS for modern UI
    st.markdown("""
    <style>
    /* Main styling */
    .main {
        background-color: #0E1117;
    }
    
    /* Header styling */
    .main-header {
        font-size: 2.8rem;
        font-weight: 800;
        text-align: center;
        background: linear-gradient(135deg, #6A11CB 0%, #2575FC 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 2rem;
        padding: 1rem;
    }
    
    /* Card styling */
    .card {
        background-color: #1F2937;
        border-radius: 12px;
        padding: 1.5rem;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        margin-bottom: 1.5rem;
        border-left: 4px solid #6A11CB;
    }
    
    .card-header {
        font-size: 1.4rem;
        font-weight: 600;
        margin-bottom: 1rem;
        color: #F3F4F6;
    }
    
    /* Algorithm info box */
    .algorithm-info {
        background: linear-gradient(135deg, #1F2937 0%, #111827 100%);
        padding: 1.2rem;
        border-radius: 10px;
        margin: 1rem 0;
        border: 1px solid #374151;
    }
    
    /* Success and error boxes */
    .success-box {
        background-color: #064E3B;
        border: 1px solid #047857;
        color: #D1FAE5;
        padding: 1.2rem;
        border-radius: 10px;
        margin: 1rem 0;
    }
    
    .error-box {
        background-color: #7F1D1D;
        border: 1px solid #B91C1C;
        color: #FECACA;
        padding: 1.2rem;
        border-radius: 10px;
        margin: 1rem 0;
    }
    
    /* Button styling */
    .stButton button {
        background: linear-gradient(135deg, #6A11CB 0%, #2575FC 100%);
        color: white;
        border: none;
        border-radius: 8px;
        padding: 0.5rem 1rem;
        font-weight: 600;
        width: 100%;
        transition: all 0.3s ease;
    }
    
    .stButton button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
    }
    
    /* Sidebar styling */
    .css-1d391kg {
        background-color: #111827;
    }
    
    /* Tab styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    
    .stTabs [data-baseweb="tab"] {
        background: #1F2937;
        border-radius: 8px 8px 0 0;
        padding: 10px 16px;
        border: 1px solid #374151;
        margin-right: 4px;
    }
    
    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, #6A11CB 0%, #2575FC 100%);
        border: none;
    }
    
    /* File uploader styling */
    .stFileUploader {
        background-color: #1F2937;
        border-radius: 8px;
        padding: 1rem;
    }
    
    /* Text area styling */
    .stTextArea textarea {
        background-color: #1F2937;
        color: #F3F4F6;
        border: 1px solid #374151;
    }
    
    /* Number input styling */
    .stNumberInput input {
        background-color: #1F2937;
        color: #F3F4F6;
        border: 1px solid #374151;
    }
    
    /* Select box styling */
    .stSelectbox div[data-baseweb="select"] {
        background-color: #1F2937;
        color: #F3F4F6;
        border: 1px solid #374151;
    }
    
    /* Text input styling */
    .stTextInput input {
        background-color: #1F2937;
        color: #F3F4F6;
        border: 1px solid #374151;
    }
    
    /* History item styling */
    .history-item {
        background-color: #1F2937;
        border-radius: 8px;
        padding: 0.8rem;
        margin-bottom: 0.5rem;
        border-left: 3px solid #6A11CB;
        font-size: 0.9rem;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Header
    st.markdown('<div class="main-header">🔐 Advanced File Encryption Tool</div>', unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.markdown('<div class="card-header">⚙️ Settings</div>', unsafe_allow_html=True)
        
        # Algorithm selection
        algorithm = st.selectbox(
            "Encryption Algorithm",
            options=list(encryptor.supported_algorithms.keys()),
            format_func=lambda x: encryptor.supported_algorithms[x],
            key="algorithm_select"
        )
        
        # Algorithm information
        algorithm_descriptions = {
            'caesar': "Simple substitution cipher with fixed shift",
            'vigenere': "Polyalphabetic cipher using keyword",
            'xor': "Bitwise XOR operation with key",
            'substitution': "Each letter mapped to different letter",
            'fernet': "Modern symmetric encryption (AES-based)"
        }
        
        st.markdown(f"""
        <div class="algorithm-info">
        <strong style="color: #60A5FA; font-size: 1.1rem;">{encryptor.supported_algorithms[algorithm]}</strong><br>
        <span style="color: #9CA3AF;">{algorithm_descriptions[algorithm]}</span>
        </div>
        """, unsafe_allow_html=True)
        
        # Key generation section
        st.markdown('<div class="card-header">🔑 Key Management</div>', unsafe_allow_html=True)
        
        if algorithm == 'fernet' and CRYPTO_AVAILABLE:
            password_mode = st.checkbox("Use password-based key", value=True)
            if password_mode:
                password = st.text_input("Password", type="password")
                if st.button("Generate Key from Password", key="pwd_key_btn"):
                    if password:
                        try:
                            key = encryptor.generate_key(algorithm, password)
                            st.session_state.generated_key = key
                            st.success("Key generated from password!")
                        except Exception as e:
                            st.error(f"Error generating key: {str(e)}")
                    else:
                        st.warning("Please enter a password")
            else:
                if st.button("Generate Random Key", key="rand_key_btn"):
                    try:
                        key = encryptor.generate_key(algorithm)
                        st.session_state.generated_key = key
                        st.success("Random key generated!")
                    except Exception as e:
                        st.error(f"Error generating key: {str(e)}")
        else:
            if st.button("Generate Random Key", key="gen_key_btn"):
                try:
                    key = encryptor.generate_key(algorithm)
                    st.session_state.generated_key = key
                    st.success(f"Key generated: {key}")
                except Exception as e:
                    st.error(f"Error generating key: {str(e)}")
        
        # Manual key input
        if algorithm == 'caesar':
            manual_key = st.number_input("Or enter Caesar shift (1-25)", min_value=1, max_value=25, value=3)
        else:
            manual_key = st.text_input("Or enter key manually", type="password" if algorithm == 'fernet' else "default")
        
        # History section
        st.markdown("---")
        st.markdown('<div class="card-header">📜 Recent Operations</div>', unsafe_allow_html=True)
        if st.session_state.encryption_history:
            for i, hist in enumerate(reversed(st.session_state.encryption_history[-5:])):
                op_color = "#10B981" if hist['operation'] == 'encrypt' else "#60A5FA"
                st.markdown(f"""
                <div class="history-item">
                    <span style="color: {op_color}; font-weight: 600;">{hist['operation'].title()}</span> - 
                    <span style="color: #FBBF24;">{hist['algorithm']}</span><br>
                    <span style="color: #9CA3AF; font-size: 0.8rem;">{hist['filename']} • {hist['timestamp']}</span>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.markdown('<div style="color: #9CA3AF; text-align: center; padding: 1rem;">No operations yet</div>', unsafe_allow_html=True)
        
        if st.button("Clear History", key="clear_hist_btn"):
            st.session_state.encryption_history = []
            st.rerun()
    
    # Main content
    tab1, tab2, tab3 = st.tabs(["📁 File Operations", "✏️ Text Operations", "ℹ️ Help & Info"])
    
    with tab1:
        st.markdown('<div class="card-header">File Encryption/Decryption</div>', unsafe_allow_html=True)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown('<div class="card-header" style="font-size: 1.2rem;">🔐 Encrypt File</div>', unsafe_allow_html=True)
            
            encrypt_file = st.file_uploader(
                "Choose file to encrypt",
                type=['txt', 'md', 'py', 'js', 'html', 'css', 'json', 'xml'],
                key="encrypt_upload"
            )
            
            if encrypt_file is not None:
                # Display file info
                file_size = len(encrypt_file.getvalue())
                st.info(f"📄 **File:** {encrypt_file.name} | 📊 **Size:** {file_size} bytes")
                
                # Determine key to use
                key_to_use = None
                if st.session_state.generated_key is not None:
                    key_to_use = st.session_state.generated_key
                elif manual_key:
                    key_to_use = manual_key
                
                if key_to_use is not None:
                    if st.button("🔐 Encrypt File", type="primary", key="encrypt_file_btn"):
                        try:
                            # Read file content
                            content = encrypt_file.read().decode('utf-8')
                            
                            # Encrypt content
                            encrypted_content = encryptor.encrypt_text(content, algorithm, key_to_use)
                            
                            # Create download button
                            encrypted_bytes = encrypted_content.encode('utf-8')
                            st.download_button(
                                label="📥 Download Encrypted File",
                                data=encrypted_bytes,
                                file_name=f"encrypted_{encrypt_file.name}",
                                mime="text/plain",
                                key="dl_encrypted_btn"
                            )
                            
                            # Add to history
                            add_to_history("encrypt", algorithm, encrypt_file.name, datetime.now().strftime("%H:%M:%S"))
                            
                            st.markdown(f"""
                            <div class="success-box">
                            <div style="display: flex; align-items: center; margin-bottom: 0.5rem;">
                                <span style="font-size: 1.5rem; margin-right: 0.5rem;">✅</span>
                                <span style="font-weight: 600;">File encrypted successfully!</span>
                            </div>
                            <div style="margin-left: 2rem;">
                                <div>🔒 Algorithm: {encryptor.supported_algorithms[algorithm]}</div>
                                <div>📊 Original size: {len(content)} characters</div>
                                <div>📈 Encrypted size: {len(encrypted_content)} characters</div>
                            </div>
                            </div>
                            """, unsafe_allow_html=True)
                            
                        except Exception as e:
                            st.markdown(f"""
                            <div class="error-box">
                            <div style="display: flex; align-items: center;">
                                <span style="font-size: 1.5rem; margin-right: 0.5rem;">❌</span>
                                <span style="font-weight: 600;">Encryption failed: {str(e)}</span>
                            </div>
                            </div>
                            """, unsafe_allow_html=True)
                else:
                    st.warning("⚠️ Please generate a key or enter one manually")
        
        with col2:
            st.markdown('<div class="card-header" style="font-size: 1.2rem;">🔓 Decrypt File</div>', unsafe_allow_html=True)
            
            decrypt_file = st.file_uploader(
                "Choose file to decrypt",
                type=['txt', 'md', 'py', 'js', 'html', 'css', 'json', 'xml'],
                key="decrypt_upload"
            )
            
            if decrypt_file is not None:
                # Display file info
                file_size = len(decrypt_file.getvalue())
                st.info(f"📄 **File:** {decrypt_file.name} | 📊 **Size:** {file_size} bytes")
                
                # Determine key to use
                key_to_use = None
                if st.session_state.generated_key is not None:
                    key_to_use = st.session_state.generated_key
                elif manual_key:
                    key_to_use = manual_key
                
                if key_to_use is not None:
                    if st.button("🔓 Decrypt File", type="primary", key="decrypt_file_btn"):
                        try:
                            # Read encrypted content
                            encrypted_content = decrypt_file.read().decode('utf-8')
                            
                            # Decrypt content
                            decrypted_content = encryptor.decrypt_text(encrypted_content, algorithm, key_to_use)
                                            # Create download button
                            decrypted_bytes = decrypted_content.encode('utf-8')
                            original_name = decrypt_file.name.replace("encrypted_", "")  # Hanya hapus prefiks "encrypted_"
                            st.download_button(
                                label="📥 Download Decrypted File",
                                data=decrypted_bytes,
                                file_name=f"decrypted_{original_name}",  # Pertahankan ekstensi asli
                                mime="text/plain",
                                key="dl_decrypted_btn"
                            )
                            
                            # Add to history
                            add_to_history("decrypt", algorithm, decrypt_file.name, datetime.now().strftime("%H:%M:%S"))
                            
                            st.markdown(f"""
                            <div class="success-box">
                            <div style="display: flex; align-items: center; margin-bottom: 0.5rem;">
                                <span style="font-size: 1.5rem; margin-right: 0.5rem;">✅</span>
                                <span style="font-weight: 600;">File decrypted successfully!</span>
                            </div>
                            <div style="margin-left: 2rem;">
                                <div>🔓 Algorithm: {encryptor.supported_algorithms[algorithm]}</div>
                                <div>📊 Encrypted size: {len(encrypted_content)} characters</div>
                                <div>📈 Decrypted size: {len(decrypted_content)} characters</div>
                            </div>
                            </div>
                            """, unsafe_allow_html=True)
                            
                        except Exception as e:
                            st.markdown(f"""
                            <div class="error-box">
                            <div style="display: flex; align-items: center; margin-bottom: 0.5rem;">
                                <span style="font-size: 1.5rem; margin-right: 0.5rem;">❌</span>
                                <span style="font-weight: 600;">Decryption failed: {str(e)}</span>
                            </div>
                            <div style="margin-left: 2rem;">
                                Make sure you're using the correct key and algorithm.
                            </div>
                            </div>
                            """, unsafe_allow_html=True)
                else:
                    st.warning("⚠️ Please generate a key or enter one manually")
    
    with tab2:
        st.markdown('<div class="card-header">Text Encryption/Decryption</div>', unsafe_allow_html=True)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown('<div class="card-header" style="font-size: 1.2rem;">Input Text</div>', unsafe_allow_html=True)
            input_text = st.text_area("Enter text to encrypt/decrypt", height=200, key="input_text_area")
            
            # Determine key to use
            key_to_use = None
            if st.session_state.generated_key is not None:
                key_to_use = st.session_state.generated_key
            elif manual_key:
                key_to_use = manual_key
            
            if input_text and key_to_use is not None:
                col_enc, col_dec = st.columns(2)
                
                with col_enc:
                    if st.button("🔐 Encrypt Text", key="encrypt_text_btn"):
                        try:
                            encrypted = encryptor.encrypt_text(input_text, algorithm, key_to_use)
                            st.session_state.text_result = encrypted
                            st.session_state.text_operation = "encrypted"
                            st.session_state.show_result = True
                        except Exception as e:
                            st.error(f"Encryption failed: {str(e)}")
                
                with col_dec:
                    if st.button("🔓 Decrypt Text", key="decrypt_text_btn"):
                        try:
                            decrypted = encryptor.decrypt_text(input_text, algorithm, key_to_use)
                            st.session_state.text_result = decrypted
                            st.session_state.text_operation = "decrypted"
                            st.session_state.show_result = True
                        except Exception as e:
                            st.error(f"Decryption failed: {str(e)}")
            elif input_text:
                st.warning("⚠️ Please generate a key or enter one manually")
        
        with col2:
            st.markdown('<div class="card-header" style="font-size: 1.2rem;">Output</div>', unsafe_allow_html=True)
            if hasattr(st.session_state, 'show_result') and st.session_state.show_result:
                st.text_area(
                    f"Result ({st.session_state.text_operation})",
                    value=st.session_state.text_result,
                    height=200,
                    key="output_text_area"
                )
                
                # Download button for text result
                st.download_button(
                    label=f"📥 Download {st.session_state.text_operation.title()} Text",
                    data=st.session_state.text_result,
                    file_name=f"{st.session_state.text_operation}_text.txt",
                    mime="text/plain",
                    key="dl_text_btn"
                )
                
                # Stats
                col1, col2 = st.columns(2)
                with col1:
                    st.metric("Input Length", f"{len(input_text)} chars")
                with col2:
                    st.metric("Output Length", f"{len(st.session_state.text_result)} chars")
            else:
                st.text_area("Result will appear here", value="", height=200, disabled=True, key="placeholder_output")
                st.info("👆 Enter text and encrypt/decrypt to see results")
    
    with tab3:
        st.markdown('<div class="card-header">Help & Information</div>', unsafe_allow_html=True)
        
        # Algorithm cards
        st.subheader("🔍 Algorithm Descriptions")
        
        alg_cols = st.columns(2)
        
        with alg_cols[0]:
            st.markdown("""
            <div class="card">
                <h3>Caesar Cipher</h3>
                <p><strong>Type:</strong> Simple substitution cipher</p>
                <p><strong>Key:</strong> Number (1-25)</p>
                <p><strong>Security:</strong> Low - easily broken</p>
                <p><strong>Use case:</strong> Educational purposes, simple obfuscation</p>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown("""
            <div class="card">
                <h3>Vigenère Cipher</h3>
                <p><strong>Type:</strong> Polyalphabetic substitution cipher</p>
                <p><strong>Key:</strong> Word or phrase</p>
                <p><strong>Security:</strong> Medium - stronger than Caesar but still breakable</p>
                <p><strong>Use case:</strong> Historical encryption, moderate security needs</p>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown("""
            <div class="card">
                <h3>XOR Cipher</h3>
                <p><strong>Type:</strong> Bitwise operation cipher</p>
                <p><strong>Key:</strong> Any string</p>
                <p><strong>Security:</strong> Depends on key quality</p>
                <p><strong>Use case:</strong> Quick encryption, stream ciphers</p>
            </div>
            """, unsafe_allow_html=True)
        
        with alg_cols[1]:
            st.markdown("""
            <div class="card">
                <h3>Substitution Cipher</h3>
                <p><strong>Type:</strong> Monoalphabetic substitution</p>
                <p><strong>Key:</strong> 26-character string (alphabet permutation)</p>
                <p><strong>Security:</strong> Low-medium - vulnerable to frequency analysis</p>
                <p><strong>Use case:</strong> Puzzles, basic encryption</p>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown("""
            <div class="card">
                <h3>Fernet (AES-based)</h3>
                <p><strong>Type:</strong> Modern symmetric encryption</p>
                <p><strong>Key:</strong> 256-bit key or password-derived</p>
                <p><strong>Security:</strong> High - cryptographically secure</p>
                <p><strong>Use case:</strong> Production encryption, sensitive data</p>
            </div>
            """, unsafe_allow_html=True)
        
        # Usage instructions
        st.subheader("📋 Usage Instructions")
        
        steps = st.container()
        with steps:
            st.markdown("""
            <div style="background-color: #1F2937; padding: 1.5rem; border-radius: 10px;">
                <div style="display: flex; margin-bottom: 1rem; align-items: flex-start;">
                    <div style="background: linear-gradient(135deg, #6A11CB 0%, #2575FC 100%); width: 30px; height: 30px; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin-right: 1rem; flex-shrink: 0;">1</div>
                    <div><strong>Select Algorithm</strong>: Choose from the dropdown in the sidebar</div>
                </div>
                <div style="display: flex; margin-bottom: 1rem; align-items: flex-start;">
                    <div style="background: linear-gradient(135deg, #6A11CB 0%, #2575FC 100%); width: 30px; height: 30px; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin-right: 1rem; flex-shrink: 0;">2</div>
                    <div><strong>Generate Key</strong>: Use the key generation buttons or enter manually</div>
                </div>
                <div style="display: flex; margin-bottom: 1rem; align-items: flex-start;">
                    <div style="background: linear-gradient(135deg, #6A11CB 0%, #2575FC 100%); width: 30px; height: 30px; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin-right: 1rem; flex-shrink: 0;">3</div>
                    <div><strong>File Operations</strong>: Upload files to encrypt/decrypt</div>
                </div>
                <div style="display: flex; margin-bottom: 1rem; align-items: flex-start;">
                    <div style="background: linear-gradient(135deg, #6A11CB 0%, #2575FC 100%); width: 30px; height: 30px; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin-right: 1rem; flex-shrink: 0;">4</div>
                    <div><strong>Text Operations</strong>: Enter text directly for quick operations</div>
                </div>
                <div style="display: flex; align-items: flex-start;">
                    <div style="background: linear-gradient(135deg, #6A11CB 0%, #2575FC 100%); width: 30px; height: 30px; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin-right: 1rem; flex-shrink: 0;">5</div>
                    <div><strong>Download Results</strong>: Use download buttons to save results</div>
                </div>
            </div>
            """, unsafe_allow_html=True)
        
        # Security notes
        st.subheader("⚠️ Security Notes")
        st.markdown("""
        <div class="algorithm-info">
            <ul>
            <li>Only Fernet provides cryptographic security</li>
            <li>Other algorithms are for educational/demonstration purposes</li>
            <li>Always use strong, random keys</li>
            <li>Keep keys secure and separate from encrypted data</li>
            <li>For production use, consider additional security measures</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
        
        # Requirements
        st.subheader("🔧 Requirements")
        st.markdown("""
        <div class="algorithm-info">
            <p><strong>Python 3.7+</strong></p>
            <p><strong>Streamlit</strong></p>
            <p><strong>cryptography library</strong> (for Fernet)</p>
                    
            Install dependencies:
            pip install streamlit cryptography
                    
            Run the application:
            streamlit run encryption_tool.py
        </div>
        """, unsafe_allow_html=True)
        
        if not CRYPTO_AVAILABLE:
            st.markdown("""
            <div class="error-box">
            <div style="display: flex; align-items: center; margin-bottom: 0.5rem;">
                <span style="font-size: 1.5rem; margin-right: 0.5rem;">⚠️</span>
                <span style="font-weight: 600;">Cryptography library not installed</span>
            </div>
            <div style="margin-left: 2rem;">
                Fernet encryption is not available. Install with:
                <div style="background-color: #111827; padding: 0.5rem; border-radius: 5px; margin: 0.5rem 0;">
                <code>pip install cryptography</code>
                </div>
            </div>
            </div>
            """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()