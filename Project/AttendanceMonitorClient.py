from flask import Flask, request, redirect, url_for, render_template
from web3 import Web3, HTTPProvider

app = Flask(__name__)
web3 = Web3(Web3.HTTPProvider('http://127.0.0.1:7545'))  # Ganacheのアドレス
contract_address = '0x1B9b326bA9F88Dc4eef7912508d2f2f2Bb94d67c'
abi = '''
[
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "num",
				"type": "uint256"
			}
		],
		"name": "store",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "retrieve",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	}
]
'''

account_1 = '0x618F4bE46E116b13Caca0E019a3a34FdAFA1233B'
private_key_1 = '0x79a55b8862c7db9dbc4dd1024fec43844f4f456b8755c6528c2097dbf36960a4'

app = Flask(__name__, template_folder='templates', static_folder='static')
@app.route('/module')
def module():
    return render_template('module.html')

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/submit-password', methods=['POST'])
def submit_password():
    try:
        password = int(request.form['password'])
        contract = web3.eth.contract(address=contract_address, abi=abi)

        nonce = web3.eth.get_transaction_count(account_1)
        txn = contract.functions.store(password).build_transaction({
            'gas': 70000,
            'gasPrice': web3.to_wei('1', 'gwei'),
            'from': account_1,
            'nonce': nonce
        })
        signed_txn = web3.eth.account.sign_transaction(txn, private_key_1)
        tx_hash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
        receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
        updated_value = contract.functions.retrieve().call()

        return render_template('home.html', initial=password, updated=updated_value)
    except Exception as e:
        return f"An error occurred: {str(e)}"

if __name__ == '__main__':
    app.run(debug=True)