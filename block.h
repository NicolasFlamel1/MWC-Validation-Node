// Header guard
#ifndef MWC_VALIDATION_NODE_BLOCK_H
#define MWC_VALIDATION_NODE_BLOCK_H


// Header files
#include "./common.h"
#include <list>
#include "./input.h"
#include "./kernel.h"
#include "./output.h"
#include "./rangeproof.h"

using namespace std;


// Namespace
namespace MwcValidationNode {


// Structures

// Block structure
struct Block final {

	// Public
	public:
	
		// Constructor
		explicit Block(list<Input> &&inputs, list<Output> &&outputs, list<Rangeproof> &&rangeproofs, list<Kernel> &&kernels);
		
		// Get inputs
		const list<Input> &getInputs() const;
		
		// Get outputs
		list<Output> &getOutputs();
		
		// Get outputs
		const list<Output> &getOutputs() const;
		
		// Get rangeproofs
		list<Rangeproof> &getRangeproofs();
		
		// Get rangeproofs
		const list<Rangeproof> &getRangeproofs() const;
		
		// Get kernels
		list<Kernel> &getKernels();
		
		// Get kernels
		const list<Kernel> &getKernels() const;
		
	// Private
	private:
	
		// Is sorted and unique
		bool isSortedAndUnique() const;
		
		// Has valid weight
		bool hasValidWeight() const;
		
		// Has unique no recent duplicate kernel excesses
		bool hasUniqueNoRecentDuplicateKernelExcesses() const;
		
		// Has valid cut through
		bool hasValidCutThrough() const;
	
		// Inputs
		list<Input> inputs;
		
		// Outputs
		list<Output> outputs;
		
		// Rangeproofs
		list<Rangeproof> rangeproofs;
		
		// Kernels
		list<Kernel> kernels;
};


}


#endif
