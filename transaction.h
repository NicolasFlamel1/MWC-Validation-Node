// Header guard
#ifndef MWC_VALIDATION_NODE_TRANSACTION_H
#define MWC_VALIDATION_NODE_TRANSACTION_H


// Header files
#include "./common.h"
#include <list>
#include "./block.h"

using namespace std;


// Namespace
namespace MwcValidationNode {


// Classes

// Node class forward declaration
class Node;

// Mempool class forward declaration
class Mempool;

// Transaction class
class Transaction final {

	// Public
	public:
	
		// Constructor
		explicit Transaction(const uint8_t offset[Crypto::SECP256K1_PRIVATE_KEY_LENGTH], list<Input> &&inputs, list<Output> &&outputs, list<Rangeproof> &&rangeproofs, list<Kernel> &&kernels);
		
		// Get offset
		const uint8_t *getOffset() const;
		
		// Get inputs
		const list<Input> &getInputs() const;
		
		// Get outputs
		const list<Output> &getOutputs() const;
		
		// Get rangeproofs
		const list<Rangeproof> &getRangeproofs() const;
		
		// Get kernels
		const list<Kernel> &getKernels() const;
		
		// Get fees
		uint64_t getFees() const;
		
		// Get required fees
		uint64_t getRequiredFees(const uint64_t baseFee) const;
		
		// Equal operator
		bool operator==(const Transaction &transaction) const;
		
	// Public for node class
	private:
	
		// Node friend class
		friend class Node;
		
		// Get inputs
		list<Input> &getInputs();
		
	// Public for mempool class
	private:
	
		// Mempool friend class
		friend class Mempool;
		
		// Serialize
		vector<uint8_t> serialize() const;
		
	// Private
	private:
	
		// Body weight output factor
		static const uint64_t BODY_WEIGHT_OUTPUT_FACTOR;
		
		// Offset
		uint8_t offset[Crypto::SECP256K1_PRIVATE_KEY_LENGTH];
	
		// Block
		Block block;
		
		// Fees
		uint64_t fees;
};


}


#endif
