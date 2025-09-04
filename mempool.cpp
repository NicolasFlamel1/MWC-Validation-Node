// Header files
#include "./common.h"
#include "./mempool.h"

using namespace std;


// Namespace
using namespace MwcValidationNode;


// Supporting function implementation

// Transaction hash operator
size_t Mempool::TransactionHash::operator()(const Transaction &transaction) const {
	
	// Return hash of the serialized transaction
	return hash<string>()(Common::toHexString(transaction.serialize()));
}

// Clear
void Mempool::clear() {

	// Clear fees
	fees.clear();
	
	// Clear outputs
	outputs.clear();
	
	// Clear transactions
	transactions.clear();
}

// Contains
bool Mempool::contains(const Transaction &transaction) const {

	// Return if transaction is in the transactions
	return transactions.contains(transaction);
}

// Insert
void Mempool::insert(Transaction &&transaction) {
	
	// Add transaction to transactions
	const unordered_set<Transaction, TransactionHash>::const_iterator value = transactions.insert(move(transaction)).first;
	
	// Go through all of the transaction's outputs
	for(const Output &output : value->getOutputs()) {
	
		// Add output to outputs
		outputs.emplace(output.getLookupValue().value(), make_pair(&output, &*value));
	}
	
	// Add transaction's fees to fees
	fees[value->getFees()].insert(&*value);
}

// Erase
Mempool::const_iterator Mempool::erase(const const_iterator &transaction) {

	// Erase transaction's fees from fees
	fees.at(transaction->getFees()).erase(&*transaction);
	
	// Check if no other transactions have the same fees
	if(fees.at(transaction->getFees()).empty()) {
	
		// Erase fee
		fees.erase(transaction->getFees());
	}
	
	// Go through all of the transaction's outputs
	for(const Output &output : transaction->getOutputs()) {
	
		// Erase output
		outputs.erase(output.getLookupValue().value());
	}
	
	// Return erasing transaction
	return transactions.erase(transaction);
}

// Erase
void Mempool::erase(const Transaction &transaction) {

	// Erase transaction
	erase(transactions.find(transaction));
}

// Iterator constant begin
Mempool::const_iterator Mempool::cbegin() const {

	// Return transactions constant begin
	return transactions.cbegin();
}

// Iterator constant end
Mempool::const_iterator Mempool::cend() const {

	// Return transactions constant end
	return transactions.cend();
}

// Get output
const Output *Mempool::getOutput(const vector<uint8_t> &outputLookupValue) const {

	// Check if output doesn't exist
	if(!outputs.contains(outputLookupValue)) {
	
		// Return null
		return nullptr;
	}
	
	// Return output
	return outputs.at(outputLookupValue).first;
}

// Get transaction
const Transaction *Mempool::getTransaction(const vector<uint8_t> &outputLookupValue) const {

	// Check if output doesn't exist
	if(!outputs.contains(outputLookupValue)) {
	
		// Return null
		return nullptr;
	}
	
	// Return transaction
	return outputs.at(outputLookupValue).second;
}

// Get fees
const map<uint64_t, unordered_set<const Transaction *>> &Mempool::getFees() const {

	// Return fees
	return fees;
}
