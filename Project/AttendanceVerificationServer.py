from flask import Flask, request, jsonify
from web3 import Web3
import json
import time

app = Flask(__name__)

# Connect to the Ganache RPC server
ganache_url = "http://127.0.0.1:7545"  # Ganache RPC server address
web3 = Web3(Web3.HTTPProvider(ganache_url))

# Check if the connection is successful
if not web3.is_connected():
    print("Error: Connection to Ganache failed")
else:
    print("Connected to Ganache")

# Define the ABI for the smart contract (without DebugLog event)
contract_abi = '''
[
	{
		"inputs": [],
		"name": "ProofInvalid",
		"type": "error"
	},
	{
		"inputs": [],
		"name": "PublicInputNotInField",
		"type": "error"
	},
	{
		"inputs": [
			{
				"internalType": "uint256[8]",
				"name": "proof",
				"type": "uint256[8]"
			}
		],
		"name": "compressProof",
		"outputs": [
			{
				"internalType": "uint256[4]",
				"name": "compressed",
				"type": "uint256[4]"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256[4]",
				"name": "compressedProof",
				"type": "uint256[4]"
			},
			{
				"internalType": "uint256[6]",
				"name": "input",
				"type": "uint256[6]"
			}
		],
		"name": "verifyCompressedProof",
		"outputs": [],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256[8]",
				"name": "proof",
				"type": "uint256[8]"
			},
			{
				"internalType": "uint256[6]",
				"name": "input",
				"type": "uint256[6]"
			}
		],
		"name": "verifyProof",
		"outputs": [],
		"stateMutability": "view",
		"type": "function"
	}
]
'''

# API endpoint to verify the proof and get results from contract.sol
@app.route('/verify', methods=['POST'])
def verify_attendance():
    try:
        print("Verification Server began processing request...")

        # Get proof, input, and smart_contract_address from the request body
        data = request.get_json()
        proof = data['proof']  # proof
        input_data = data['input']  # input
        smart_contract_address = data['smart_contract_address']

        # Print received data for debugging
        print("Received data from AttendanceMonitorClient:")
        print(f"Verification server Proof: {proof}")
        print(f"Verification server Input: {input_data}")
        print(f"Verification server Smart Contract Address: {smart_contract_address}")

        # Instantiate the smart contract using the address and ABI
        contract = web3.eth.contract(address=smart_contract_address, abi=contract_abi)

        # Convert proof and input to lists of integers (with 8 elements for proof and 6 for input)
        proof_int = [int(p) for p in proof[:8]]
        input_int = [int(i) for i in input_data[:6]]

        # Print converted proof_int and input_int for debugging
        print(f"Proof (after conversion to int): {proof_int}")
        print(f"Input (after conversion to int): {input_int}")

        # Estimate gas needed for the transaction
        try:
            gas_estimate = contract.functions.verifyProof(proof_int, input_int).estimate_gas()
        except Exception as e:
            return jsonify({'error': f"Error: Gas estimation failed: {str(e)}"}), 500
        print(f"Estimated gas: {gas_estimate}")
            
     # Call the verifyProof function with the converted proof and input, and specify gas
        try:
            start_time = time.time()
            contract.functions.verifyProof(proof_int, input_int).call({'gas': gas_estimate * 2})
            end_time = time.time()
        except Exception as e:
            return jsonify({'error': f"Contract verification failed: {str(e)}"}), 500
        print(f"Time: verification on contract addrress took {end_time - start_time} seconds")

        # Determine the verification result based on the contract's response
        result = 'success'
        print(f"Verification result from contract: {result}")

        # Return the verification result as a JSON response
        return jsonify({'message': result}), 200

    except Exception as e:
        # Print error log and return error details in the JSON response
        print(f"Error: {str(e)}")  # Display error log
        return jsonify({'error': str(e), 'details': str(e.__dict__)}), 500


if __name__ == '__main__':
    # Start the server on port 5002
    app.run(debug=True, port=5002)
