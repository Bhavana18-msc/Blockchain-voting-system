import hashlib
import time
import streamlit as st
from cryptography.fernet import Fernet

# Blockchain class to store votes
class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_votes = []
        self.create_block(previous_hash='1', proof=100)

    def create_block(self, proof, previous_hash=None):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'votes': self.current_votes,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]) if self.chain else '1'
        }
        self.current_votes = []
        self.chain.append(block)
        return block

    def add_vote(self, vote):
        self.current_votes.append(vote)

    def hash(self, block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_proof):
        proof = 0
        while self.valid_proof(last_proof, proof) is False:
            proof += 1
        return proof

    def valid_proof(self, last_proof, proof):
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"


# Encryption class for handling sensitive data (Voter ID and Name)
def generate_key():
    return Fernet.generate_key()

def encrypt_data(data, key):
    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode())
    return encrypted_data

def decrypt_data(encrypted_data, key):
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data).decode()
    return decrypted_data


# Initialize Blockchain and Encryption Key
blockchain = Blockchain()
key = generate_key()

# Streamlit page configuration
st.set_page_config(page_title="Blockchain Voting App", page_icon=":ballot_box_with_ballot:", layout="wide")

# UI Header
st.title("Blockchain Voting System")
st.markdown("""
This is a simple blockchain-based voting system. Please register, and then cast your vote.
""")

# Voter Registration Section
st.subheader("Voter Registration")
voter_id = st.text_input("Enter your Voter ID")
voter_name = st.text_input("Enter your Name")

if st.button("Register Voter"):
    if voter_id and voter_name:
        encrypted_voter = encrypt_data(f"{voter_id}:{voter_name}", key)
        st.success("Registration Successful!")
        st.write(f"Encrypted Voter Data: {encrypted_voter}")
    else:
        st.error("Please fill in both fields.")

# Voting Section
st.subheader("Cast Your Vote")
vote_choices = ["Candidate A", "Candidate B", "Candidate C"]
vote = st.selectbox("Select a Candidate", vote_choices)

if st.button("Cast Vote"):
    if vote:
        encrypted_vote = encrypt_data(vote, key)
        blockchain.add_vote(encrypted_vote)
        st.success("Vote Casted Successfully!")
        st.write(f"Encrypted Vote: {encrypted_vote}")
    else:
        st.error("Please select a candidate.")

# View Blockchain Information
if st.button("View Blockchain"):
    blockchain_data = blockchain.chain
    st.write("Blockchain Data:")
    for block in blockchain_data:
        st.write(block)
