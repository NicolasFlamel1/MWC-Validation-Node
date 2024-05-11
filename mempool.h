// Header guard
#ifndef MWC_VALIDATION_NODE_MEMPOOL_H
#define MWC_VALIDATION_NODE_MEMPOOL_H


// Header files
#include "./common.h"
#include <map>
#include <unordered_map>
#include <unordered_set>
#include "./transaction.h"

using namespace std;


// Namespace
namespace MwcValidationNode {


// Classes

// Mempool class
class Mempool final {

	// Private
	private:
	
		// Transaction hash
		class TransactionHash {

			// Public
			public:
			
				// Operator
				size_t operator()(const Transaction &transaction) const;
		};
		
	// Public
	public:
	
		// Constant iterator
		typedef unordered_set<Transaction, TransactionHash>::const_iterator const_iterator;
		
		// Clear
		void clear();
		
		// Contains
		bool contains(const Transaction &transaction) const;
		
		// Insert
		void insert(Transaction &&transaction);
		
		// Erase
		const_iterator erase(const const_iterator &transaction);
		
		// Erase
		void erase(const Transaction &transaction);
		
		// Iterator constant begin
		const_iterator cbegin() const;
		
		// Iterator constant end
		const_iterator cend() const;
		
		// Get output
		const Output *getOutput(const vector<uint8_t> &outputLookupValue) const;
		
		// Get transaction
		const Transaction *getTransaction(const vector<uint8_t> &outputLookupValue) const;
		
		// Get fees
		const map<uint64_t, unordered_set<const Transaction *>> &getFees() const;
		
	// Private
	private:
		
		// Transactions
		unordered_set<Transaction, TransactionHash> transactions;
		
		// Outputs
		unordered_map<vector<uint8_t>, pair<const Output *, const Transaction *>, Common::Uint8VectorHash> outputs;
		
		// Fees
		map<uint64_t, unordered_set<const Transaction *>> fees;
};


}


#endif
