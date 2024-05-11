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

// Transaction class
class Transaction final {

	// Public
	public:
	
		// Constructor
		explicit Transaction(const uint8_t offset[Crypto::SECP256K1_PRIVATE_KEY_LENGTH], list<Input> &&inputs, list<Output> &&outputs, list<Rangeproof> &&rangeproofs, list<Kernel> &&kernels);
		
		// Get offset
		const uint8_t *getOffset() const;
		
		// Get inputs
		list<Input> &getInputs();
		
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
		
		// Serialize
		vector<uint8_t> serialize() const;
		
		// Equal operator
		bool operator==(const Transaction &transaction) const;
		
		// Get required fees
		uint64_t getRequiredFees(const uint64_t baseFee) const;
		
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
