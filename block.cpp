// Header files
#include "./common.h"
#include <cstring>
#include <set>
#include "blake2.h"
#include "./block.h"
#include "./consensus.h"
#include "./saturate_math.h"

using namespace std;


// Namespace
using namespace MwcValidationNode;


// Supporting function implementation

// Constructor
Block::Block(list<Input> &&inputs, list<Output> &&outputs, list<Rangeproof> &&rangeproofs, list<Kernel> &&kernels, const bool isTransaction) :

	// Set inputs to inputs
	inputs(move(inputs)),
	
	// Set outputs to outputs
	outputs(move(outputs)),
	
	// Set rangeproofs to rangeproofs
	rangeproofs(move(rangeproofs)),
	
	// Set kernels to kernels
	kernels(move(kernels))
{

	// Check if doesn't have valid weight
	if(!hasValidWeight(isTransaction)) {
	
		// Throw exception
		throw runtime_error("Doesn't have valid weight");
	}

	// Check if not sorted and unique
	if(!isSortedAndUnique()) {
	
		// Throw exception
		throw runtime_error("Not sorted and unique");
	}
	
	// Check if doesn't have unique no recent duplicate kernel excesses
	if(!hasUniqueNoRecentDuplicateKernelExcesses()) {
	
		// Throw exception
		throw runtime_error("Doesn't have unique no recent duplicate kernel excesses");
	}
	
	// Check if doesn't have valid cut through
	if(!hasValidCutThrough()) {
	
		// Throw exception
		throw runtime_error("Doesn't have valid cut through");
	}
}

// Get inputs
const list<Input> &Block::getInputs() const {

	// Return inputs
	return inputs;
}

// Get outputs
list<Output> &Block::getOutputs() {

	// Return outputs
	return outputs;
}

// Get outputs
const list<Output> &Block::getOutputs() const {

	// Return outputs
	return outputs;
}

// Get rangeproofs
list<Rangeproof> &Block::getRangeproofs() {

	// Return rangeproofs
	return rangeproofs;
}

// Get rangeproofs
const list<Rangeproof> &Block::getRangeproofs() const {

	// Return rangeproofs
	return rangeproofs;
}

// Get kernels
list<Kernel> &Block::getKernels() {

	// Return kernels
	return kernels;
}

// Get kernels
const list<Kernel> &Block::getKernels() const {

	// Return kernels
	return kernels;
}

// Is sorted and unique
bool Block::isSortedAndUnique() const {

	// Go through all inputs
	for(list<Input>::const_iterator i = next(inputs.cbegin()); i != inputs.cend(); ++i) {
	
		// Get serialized input
		const vector serializedInput = i->serialize();
		
		// Check if creating input's hash failed
		uint8_t inputHash[Crypto::BLAKE2B_HASH_LENGTH];
		if(blake2b(inputHash, sizeof(inputHash), serializedInput.data(), serializedInput.size(), nullptr, 0)) {
		
			// Throw exception
			throw runtime_error("Creating input's hash failed");
		}
		
		// Get serialized previous input
		const vector serializedPreviousInput = prev(i)->serialize();
		
		// Check if creating previous input's hash failed
		uint8_t previousInputHash[Crypto::BLAKE2B_HASH_LENGTH];
		if(blake2b(previousInputHash, sizeof(previousInputHash), serializedPreviousInput.data(), serializedPreviousInput.size(), nullptr, 0)) {
		
			// Throw exception
			throw runtime_error("Creating previous input's hash failed");
		}
		
		// Check if inputs aren't sorted and/or aren't unique
		if(memcmp(inputHash, previousInputHash, sizeof(previousInputHash)) <= 0) {
		
			// Return false
			return false;
		}
	}
	
	// Go through all outputs
	for(list<Output>::const_iterator i = next(outputs.cbegin()); i != outputs.cend(); ++i) {
	
		// Get serialized output
		const vector serializedOutput = i->serialize();
		
		// Check if creating output's hash failed
		uint8_t outputHash[Crypto::BLAKE2B_HASH_LENGTH];
		if(blake2b(outputHash, sizeof(outputHash), serializedOutput.data(), serializedOutput.size(), nullptr, 0)) {
		
			// Throw exception
			throw runtime_error("Creating outputs's hash failed");
		}
		
		// Get serialized previous output
		const vector serializedPreviousOutput = prev(i)->serialize();
		
		// Check if creating previous output's hash failed
		uint8_t previousOutputHash[Crypto::BLAKE2B_HASH_LENGTH];
		if(blake2b(previousOutputHash, sizeof(previousOutputHash), serializedPreviousOutput.data(), serializedPreviousOutput.size(), nullptr, 0)) {
		
			// Throw exception
			throw runtime_error("Creating previous output's hash failed");
		}
		
		// Check if outputs aren't sorted and/or aren't unique
		if(memcmp(outputHash, previousOutputHash, sizeof(previousOutputHash)) <= 0) {
		
			// Return false
			return false;
		}
	}
	
	// Go through all kernels
	for(list<Kernel>::const_iterator i = next(kernels.cbegin()); i != kernels.cend(); ++i) {
	
		// Get serialized kernel
		const vector serializedKernel = i->serialize();
		
		// Check if creating kernel's hash failed
		uint8_t kernelHash[Crypto::BLAKE2B_HASH_LENGTH];
		if(blake2b(kernelHash, sizeof(kernelHash), serializedKernel.data(), serializedKernel.size(), nullptr, 0)) {
		
			// Throw exception
			throw runtime_error("Creating kernel's hash failed");
		}
		
		// Get serialized previous kernel
		const vector serializedPreviousKernel = prev(i)->serialize();
		
		// Check if creating previous kernel's hash failed
		uint8_t previousKernelHash[Crypto::BLAKE2B_HASH_LENGTH];
		if(blake2b(previousKernelHash, sizeof(previousKernelHash), serializedPreviousKernel.data(), serializedPreviousKernel.size(), nullptr, 0)) {
		
			// Throw exception
			throw runtime_error("Creating previous kernel's hash failed");
		}
		
		// Check if kernels aren't sorted and/or aren't unique
		if(memcmp(kernelHash, previousKernelHash, sizeof(previousKernelHash)) <= 0) {
		
			// Return false
			return false;
		}
	}
	
	// Return true
	return true;
}

// Has valid weight
bool Block::hasValidWeight(const bool isTransaction) const {

	// Get weight
	const uint64_t weight = Consensus::getBlockWeight(inputs.size(), outputs.size(), kernels.size());
	
	// Check if weight is invalid
	if(weight > SaturateMath::subtract(Consensus::MAXIMUM_BLOCK_WEIGHT, isTransaction ? Consensus::COINBASE_WEIGHT : 0)) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Has unique no recent duplicate kernel excesses
bool Block::hasUniqueNoRecentDuplicateKernelExcesses() const {

	// Initialize serialized kernel excesses
	set<array<uint8_t, Crypto::COMMITMENT_LENGTH>> serializedKernelExcesses;
	
	// Go through all kernels
	for(const Kernel &kernel : kernels) {
		
		// Check if kernel has no recent duplicate features
		if(kernel.getFeatures() == Kernel::Features::NO_RECENT_DUPLICATE) {
	
			// Check if serializing kernel's excess failed
			array<uint8_t, Crypto::COMMITMENT_LENGTH> serializedKernelExcess;
			if(!secp256k1_pedersen_commitment_serialize(secp256k1_context_no_precomp, serializedKernelExcess.data(), &kernel.getExcess())) {
			
				// Throw exception
				throw runtime_error("Serializing kernel's excess failed");
			}
			
			// Check if serialized kernel excess already exists
			if(serializedKernelExcesses.contains(serializedKernelExcess)) {
			
				// Return false
				return false;
			}
			
			// Add serialized kernel excess to list
			serializedKernelExcesses.insert(move(serializedKernelExcess));
		}
	}
	
	// Return true
	return true;
}

// Has valid cut through
bool Block::hasValidCutThrough() const {

	// Initialize serialized commitments
	set<array<uint8_t, Crypto::COMMITMENT_LENGTH>> serializedCommitments;
	
	// Go through all inputs
	for(const Input &input : inputs) {
	
		// Check if serializing input's commitment failed
		array<uint8_t, Crypto::COMMITMENT_LENGTH> serializedInputCommitment;
		if(!secp256k1_pedersen_commitment_serialize(secp256k1_context_no_precomp, serializedInputCommitment.data(), &input.getCommitment())) {
		
			// Throw exception
			throw runtime_error("Serializing input's commitment failed");
		}
		
		// Check if serialized input commitment already exists
		if(serializedCommitments.contains(serializedInputCommitment)) {
		
			// Return false
			return false;
		}
		
		// Add serialized input commitment to list
		serializedCommitments.insert(move(serializedInputCommitment));
	}
	
	// Go through all outputs
	for(const Output &output : outputs) {
	
		// Check if serializing output's commitment failed
		array<uint8_t, Crypto::COMMITMENT_LENGTH> serializedOutputCommitment;
		if(!secp256k1_pedersen_commitment_serialize(secp256k1_context_no_precomp, serializedOutputCommitment.data(), &output.getCommitment())) {
		
			// Throw exception
			throw runtime_error("Serializing output's commitment failed");
		}
		
		// Check if serialized output commitment already exists
		if(serializedCommitments.contains(serializedOutputCommitment)) {
		
			// Return false
			return false;
		}
		
		// Add serialized output commitment to list
		serializedCommitments.insert(move(serializedOutputCommitment));
	}
	
	// Return true
	return true;
}
