// Header guard
#ifndef BLOCK_H
#define BLOCK_H


// Header files
#include "./common.h"
#include <list>
#include "./input.h"
#include "./kernel.h"
#include "./output.h"
#include "./rangeproof.h"

using namespace std;


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
		
		// Get rangeproofs
		list<Rangeproof> &getRangeproofs();
		
		// Get kernels
		list<Kernel> &getKernels();
		
	// Private
	private:
	
		// Is sorted and unique
		const bool isSortedAndUnique() const;
		
		// Has valid weight
		const bool hasValidWeight() const;
		
		// Has unique no recent duplicate kernel excesses
		const bool hasUniqueNoRecentDuplicateKernelExcesses() const;
		
		// Has valid cut through
		const bool hasValidCutThrough() const;
	
		// Inputs
		list<Input> inputs;
		
		// Outputs
		list<Output> outputs;
		
		// Rangeproofs
		list<Rangeproof> rangeproofs;
		
		// Kernels
		list<Kernel> kernels;
};


#endif
