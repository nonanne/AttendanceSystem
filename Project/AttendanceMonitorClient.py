from flask import Flask, request, render_template
from web3 import Web3
import requests
from datetime import datetime
import json
import ctypes
from solcx import compile_source, install_solc, set_solc_version
import time

app = Flask(__name__)
web3 = Web3(Web3.HTTPProvider('http://127.0.0.1:7545'))  # address of the Ganache RPC server

# install the Solidity compiler version 0.8.18
install_solc('0.8.18')

# set the Solidity compiler version to 0.8.18
set_solc_version('0.8.18')

account_1 = '0xA6b7F5D990d0d45421419daa8046820bb8Acd0F1'
private_key_1 = '0xa0735c165a60b3800fd6e469a2c5af94135bea55c1515f71742e8dd25221663f'

@app.route('/module')
def module():
    return render_template('module.html')

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/submit-attendanceData', methods=['POST'])
def submit_password():
    try:
        # Retrieve password (used as ID) and module number from the form
        password = request.form['password']  # Get the password to use as ID
        module_number = request.form['module']  # Get the module number
        current_date = datetime.now().strftime('%Y%m%d')  # Get the current date

        # Send the ID (password), date, and module number to AttendanceMonitorServer.go
        data = {
            "userId": str(password),  # Send the password as ID
            "date": current_date,     # Send the current date
            "module": module_number   # Send the module number
        }
        # Endpoint of AttendanceMonitorServer.go
        attendance_monitor_url = 'http://127.0.0.1:8080/sign-attendance'  
        # Get the response from AttendanceMonitorServer.go
        response = requests.post(attendance_monitor_url, json=data)
        response.raise_for_status()  # Raise an exception if the status code is not 200

        # parse the response from the server
        signed_data = response.json()

        # generate the proof
        input, proof = generate_proof(signed_data)
        print(f"Generated Proof: {proof}")

        # compile the smart contract
        with open('contract.sol', 'r', encoding='utf-8') as file:
            contract_source_code = file.read()
        compiled_sol = compile_source(contract_source_code, output_values=['abi', 'bin'])
        contract_id, contract_interface = compiled_sol.popitem()

        abi = contract_interface['abi']
        bytecode = contract_interface['bin']

        # deploy the smart contract
        Verifier = web3.eth.contract(abi=abi, bytecode=bytecode)

        nonce = web3.eth.get_transaction_count(account_1)
        txn_dict = Verifier.constructor().build_transaction({
            'from': account_1,
            'nonce': nonce,
            'gas': 6721975,
            'gasPrice': web3.to_wei('1', 'gwei')
        })

        try:
            # send the transaction 
            signed_txn = web3.eth.account.sign_transaction(txn_dict, private_key=private_key_1)
            tx_hash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
        except Exception as e:
            return f"Error: during contract deployment: {str(e)}"
        # get the contract address
        tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
        contract_address = tx_receipt.contractAddress
        print(f"Smart Contract Address: {contract_address}")

        # send proof and input to the verification server
        verification_url = 'http://127.0.0.1:5002/verify'
        verification_data = {
            'proof': proof,
            'input': input,
            'smart_contract_address': contract_address
        }

        # connect to the verification server
        response = requests.post(verification_url, json=verification_data)
        response.raise_for_status()  # raise an exception if the status code is not 200
        verification_result = response.json()

        print(f"Verification result: {verification_result['message']}")

        return render_template('home.html', verification_message=verification_result['message'])

    except requests.exceptions.RequestException as e:
        return f"Error: while sending request: {str(e)}"
    except json.JSONDecodeError as e:
        return f"Error: decoding JSON response: {str(e)}"
    except Exception as e:
        return f"Error: {str(e)}"

def generate_proof(signed_data):
    try:
        # load main.so
        lib = ctypes.CDLL('./gnark/main.so')  # main.so is the Go shared library
        generate_proof_func = lib.GenerateProofFromGo
        generate_proof_func.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
        generate_proof_func.restype = ctypes.c_char_p

       # include the date, userId, and module in the message
        message = f"{signed_data['date']}{signed_data['userId']}{signed_data['module']}"

        public_key_c = ctypes.c_char_p(signed_data['publicKey'].encode('utf-8'))
        signature_c = ctypes.c_char_p(signed_data['signature'].encode('utf-8'))
        message_c = ctypes.c_char_p(message.encode('utf-8'))
        # call the Go function to generate the proof
        start_time = time.time()
        proof_c = generate_proof_func(public_key_c, signature_c, message_c)
        end_time = time.time()
        proof_json = proof_c.decode('utf-8')
        print(f"Time: Proof generation took {end_time - start_time} seconds")

        # gain the proof and input from the proof_json
        proof_data = json.loads(proof_json)
        input = proof_data['input']
        proof = proof_data['eth_proof']

        return input, proof
    except Exception as e:
        # error handling for proof generation failure
        print(f"Error: generating proof: {str(e)}")
        raise

if __name__ == '__main__':
    app.run(debug=True)
