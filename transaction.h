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
		const list<Input> &getInputs() const;
		
		// Get outputs
		const list<Output> &getOutputs() const;
		
		// Get rangeproofs
		const list<Rangeproof> &getRangeproofs() const;
		
		// Get kernels
		const list<Kernel> &getKernels() const;
		
	// Private
	private:
	
		// Offset
		uint8_t offset[Crypto::SECP256K1_PRIVATE_KEY_LENGTH];
	
		// Block
		Block block;
};


}


#endif
