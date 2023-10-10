// Header files
#include "./common.h"
#include <cstring>
#include "./consensus.h"
#include "./crypto.h"
#include "./header.h"
#include "./kernel.h"
#include "./merkle_mountain_range.h"
#include "./output.h"

using namespace std;


// Namespace
using namespace MwcValidationNode;


// Constants

// Secp256k1 scratch space length
const size_t Crypto::SECP256K1_SCRATCH_SPACE_LENGTH = 30 * Common::BYTES_IN_A_KILOBYTE;

// Secp256k1 number of generators
const size_t Crypto::SECP256k1_NUMBER_OF_GENERATORS = 256;

// Secp256k1 context
const unique_ptr<secp256k1_context, decltype(&secp256k1_context_destroy)> Crypto::secp256k1Context(secp256k1_context_create(SECP256K1_CONTEXT_VERIFY), secp256k1_context_destroy);

// Secp256k1 scratch space
thread_local const unique_ptr<secp256k1_scratch_space, decltype(&secp256k1_scratch_space_destroy)> Crypto::secp256k1ScratchSpace(secp256k1_scratch_space_create(secp256k1Context.get(), SECP256K1_SCRATCH_SPACE_LENGTH), secp256k1_scratch_space_destroy);

// Secp256k1 generators
const unique_ptr<secp256k1_bulletproof_generators, void(*)(secp256k1_bulletproof_generators *)> Crypto::secp256k1Generators(secp256k1_bulletproof_generators_create(secp256k1Context.get(), &secp256k1_generator_const_g, SECP256k1_NUMBER_OF_GENERATORS), [](secp256k1_bulletproof_generators *secp256k1Generators) {

	// Free secp256k1 generators
	secp256k1_bulletproof_generators_destroy(secp256k1Context.get(), secp256k1Generators);
});


// Supporting function implementation

// Get secp256k1 context
const secp256k1_context *Crypto::getSecp256k1Context() {
	
	// Return secp256k1 context
	return secp256k1Context.get();
}

// Get secp256k1 scratch space
secp256k1_scratch_space *Crypto::getSecp256k1ScratchSpace() {
	
	// Return secp256k1 scratch space
	return secp256k1ScratchSpace.get();
}

// Get secp256k1 generators
const secp256k1_bulletproof_generators *Crypto::getSecp256k1Generators() {
	
	// Return secp256k1 generators
	return secp256k1Generators.get();
}

// Verify kernel sums
bool Crypto::verifyKernelSums(const Header &header, const MerkleMountainRange<Kernel> &kernels, const MerkleMountainRange<Output> &outputs) {

	// Initialize kernel excesses sum with total kernel offset
	secp256k1_pedersen_commitment kernelExcessesSumWithTotalKernelOffset;
	
	// Check if header's total kernel offset isn't zero
	if(any_of(header.getTotalKernelOffset(), header.getTotalKernelOffset() + Crypto::SECP256K1_PRIVATE_KEY_LENGTH, [](const uint8_t value) {
	
		// Return if value isn't zero
		return value;
	
	})) {
	
		// Check if getting commitment for the header's total kernel offset failed
		secp256k1_pedersen_commitment totalKernelOffsetCommitment;
		if(!secp256k1_pedersen_commit(secp256k1_context_no_precomp, &totalKernelOffsetCommitment, header.getTotalKernelOffset(), 0, &secp256k1_generator_const_h, &secp256k1_generator_const_g)) {
		
			// Return false
			return false;
		}
		
		// Set positive excesses
		const secp256k1_pedersen_commitment *positiveExcesses[] = {
		
			// Kernels sum
			&kernels.getSum(),
			
			// Total kernel offset commitment
			&totalKernelOffsetCommitment
		};
		
		// Set negative excesses
		const secp256k1_pedersen_commitment *negativeExcesses[] = {};
		
		// Check if getting kernel excesses sum with total kernel offset failed
		if(!secp256k1_pedersen_commit_sum(secp256k1_context_no_precomp, &kernelExcessesSumWithTotalKernelOffset, positiveExcesses, 2, negativeExcesses, 0)) {
		
			// Return false
			return false;
		}
	}
	
	// Otherwise
	else {
	
		// Set kernel excesses sum with total kernel offset to the kernels sum
		kernelExcessesSumWithTotalKernelOffset = kernels.getSum();
	}
	
	// Check if serializing the kernel excesses sum with total kernel offset failed
	uint8_t serializedKernelExcessesSumWithTotalKernelOffset[Crypto::COMMITMENT_LENGTH];
	if(!secp256k1_pedersen_commitment_serialize(secp256k1_context_no_precomp, serializedKernelExcessesSumWithTotalKernelOffset, &kernelExcessesSumWithTotalKernelOffset)) {
	
		// Return false
		return false;
	}
	
	// Get total number of coinbase rewards at the header's height
	const uint64_t totalNumberOfCoinbaseRewards = Consensus::getTotalNumberOfCoinbaseRewards(header.getHeight());
	
	// Check if getting commitment for the total number of coinbase rewards failed
	secp256k1_pedersen_commitment totalNumberOfCoinbaseRewardsCommitment;
	const uint8_t zeroBlindingFactor[Crypto::SECP256K1_PRIVATE_KEY_LENGTH] = {};
	if(!secp256k1_pedersen_commit(secp256k1_context_no_precomp, &totalNumberOfCoinbaseRewardsCommitment, zeroBlindingFactor, totalNumberOfCoinbaseRewards, &secp256k1_generator_const_h, &secp256k1_generator_const_g)) {
	
		// Return false
		return false;
	}
	
	// Set positive commitments
	const secp256k1_pedersen_commitment *positiveCommitments[] = {
	
		// Outputs sum
		&outputs.getSum()
	};
	
	// Set negative commitments
	const secp256k1_pedersen_commitment *negativeCommitments[] = {
	
		// Total number of coinbase rewards commitment
		&totalNumberOfCoinbaseRewardsCommitment
	};
	
	// Check if getting UXTO commitments sum failed
	secp256k1_pedersen_commitment uxtoCommitmentsSum;
	if(!secp256k1_pedersen_commit_sum(secp256k1_context_no_precomp, &uxtoCommitmentsSum, positiveCommitments, 1, negativeCommitments, 1)) {
	
		// Return false
		return false;
	}
	
	// Check if serializing the UXTO commitments sum failed
	uint8_t serializedUxtoCommitmentsSum[Crypto::COMMITMENT_LENGTH];
	if(!secp256k1_pedersen_commitment_serialize(secp256k1_context_no_precomp, serializedUxtoCommitmentsSum, &uxtoCommitmentsSum)) {
	
		// Return false
		return false;
	}
	
	// Check if serialized UXTO commitments sum doesn't equal the serialized kernel excesses sum with total kernel offset
	if(memcmp(serializedUxtoCommitmentsSum, serializedKernelExcessesSumWithTotalKernelOffset, sizeof(serializedKernelExcessesSumWithTotalKernelOffset))) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}
