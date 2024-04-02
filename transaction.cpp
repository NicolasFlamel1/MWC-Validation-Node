// Header files
#include "./common.h"
#include <cstring>
#include "./saturate_math.h"
#include "./transaction.h"

using namespace std;


// Namespace
using namespace MwcValidationNode;


// Supporting function implementation

// Constructor
Transaction::Transaction(const uint8_t offset[Crypto::SECP256K1_PRIVATE_KEY_LENGTH], list<Input> &&inputs, list<Output> &&outputs, list<Rangeproof> &&rangeproofs, list<Kernel> &&kernels) :

	// Create block using inputs, outputs, rangeproofs, and kernels
	block(move(inputs), move(outputs), move(rangeproofs), move(kernels), true)
{

	// Get if offset is zero
	const bool offsetIsZero = all_of(offset, offset + Crypto::SECP256K1_PRIVATE_KEY_LENGTH, [](const uint8_t value) {
	
		// Return if value is zero
		return !value;
	});
	
	// Initialize kernel excesses
	const secp256k1_pedersen_commitment *positiveExcesses[getKernels().size() + (offsetIsZero ? 0 : 1)];
	
	// Set fees to zero
	uint64_t fees = 0;
	
	// Go through all kernels
	size_t i = 0;
	for(const Kernel &kernel : getKernels()) {
	
		// Set positive excess to kernel's excess
		positiveExcesses[i++] = &kernel.getExcess();
		
		// Add kernel's fee to the fees
		fees = SaturateMath::add(fees, kernel.getFee());
	}
	
	// Check if offset isn't zero
	secp256k1_pedersen_commitment offsetCommitment;
	if(!offsetIsZero) {
	
		// Check if offset is invalid
		if(!secp256k1_ec_seckey_verify(secp256k1_context_no_precomp, offset)) {
		
			// Throw exception
			throw runtime_error("Offset is invalid");
		}
		
		// Check if getting commitment for the offset failed
		if(!secp256k1_pedersen_commit(secp256k1_context_no_precomp, &offsetCommitment, offset, 0, &secp256k1_generator_const_h, &secp256k1_generator_const_g)) {
		
			// Throw exception
			throw runtime_error("Getting commitment for the offset failed");
		}
		
		// Set positive excess to offset's commitment
		positiveExcesses[i] = &offsetCommitment;
	}
	
	// Check if getting kernel excesses sum failed
	secp256k1_pedersen_commitment kernelExcessesSum;
	const secp256k1_pedersen_commitment *negativeExcesses[] = {};
	if(!secp256k1_pedersen_commit_sum(secp256k1_context_no_precomp, &kernelExcessesSum, positiveExcesses, getKernels().size() + (offsetIsZero ? 0 : 1), negativeExcesses, 0)) {
	
		// Throw exception
		throw runtime_error("Getting kernel excesses sum failed");
	}
	
	// Check if serializing the kernel excesses sum failed
	uint8_t serializedKernelExcessesSum[Crypto::COMMITMENT_LENGTH];
	if(!secp256k1_pedersen_commitment_serialize(secp256k1_context_no_precomp, serializedKernelExcessesSum, &kernelExcessesSum)) {
	
		// Throw exception
		throw runtime_error("Serializing the kernel excesses sum failed");
	}
	
	// Initialize positive commitments
	const secp256k1_pedersen_commitment *positiveCommitments[getOutputs().size() + (fees ? 1 : 0)];
	
	// Go through all outputs
	i = 0;
	for(const Output &output : getOutputs()) {
	
		// Set positive commitment to output's commitment
		positiveCommitments[i++] = &output.getCommitment();
	}
	
	// Check if fees isn't zero
	secp256k1_pedersen_commitment feesCommitment;
	if(fees) {
	
		// Check if getting commitment for the fees failed
		const uint8_t zeroBlindingFactor[Crypto::SECP256K1_PRIVATE_KEY_LENGTH] = {};
		if(!secp256k1_pedersen_commit(secp256k1_context_no_precomp, &feesCommitment, zeroBlindingFactor, fees, &secp256k1_generator_const_h, &secp256k1_generator_const_g)) {
		
			// Throw exception
			throw runtime_error("Getting commitment for the fees failed");
		}
		
		// Set positive commitment to fee's commitment
		positiveCommitments[i] = &feesCommitment;
	}
	
	// Initialize negative commitments
	const secp256k1_pedersen_commitment *negativeCommitments[getInputs().size()];
	
	// Go through all inputs
	i = 0;
	for(const Input &input : getInputs()) {
	
		// Set negative commitment to inputs's commitment
		negativeCommitments[i++] = &input.getCommitment();
	}
	
	// Check if getting commitments sum failed
	secp256k1_pedersen_commitment commitmentsSum;
	if(!secp256k1_pedersen_commit_sum(secp256k1_context_no_precomp, &commitmentsSum, positiveCommitments, getOutputs().size() + (fees ? 1 : 0), negativeCommitments, getInputs().size())) {
	
		// Throw exception
		throw runtime_error("Getting commitments sum failed");
	}
	
	// Check if serializing the commitments sum failed
	uint8_t serializedCommitmentsSum[Crypto::COMMITMENT_LENGTH];
	if(!secp256k1_pedersen_commitment_serialize(secp256k1_context_no_precomp, serializedCommitmentsSum, &commitmentsSum)) {
	
		// Throw exception
		throw runtime_error("Serializing the commitments sum failed");
	}
	
	// Check if serialized commitments sum doesn't equal the serialized kernel excesses sum
	if(memcmp(serializedCommitmentsSum, serializedKernelExcessesSum, sizeof(serializedKernelExcessesSum))) {
	
		// Throw exception
		throw runtime_error("Serialized commitments sum doesn't equal the serialized kernel excesses sum");
	}
	
	// Set offset to offset
	memcpy(this->offset, offset, sizeof(this->offset));
}

// Get offset
const uint8_t *Transaction::getOffset() const {

	// Return offset
	return offset;
}

// Get inputs
const list<Input> &Transaction::getInputs() const {

	// Return block's inputs
	return block.getInputs();
}

// Get outputs
const list<Output> &Transaction::getOutputs() const {

	// Return block's outputs
	return block.getOutputs();
}

// Get rangeproofs
const list<Rangeproof> &Transaction::getRangeproofs() const {

	// Return block's rangeproofs
	return block.getRangeproofs();
}

// Get kernels
const list<Kernel> &Transaction::getKernels() const {

	// Return block's kernels
	return block.getKernels();
}
