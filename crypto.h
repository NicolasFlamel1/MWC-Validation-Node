// Header guard
#ifndef MWC_VALIDATION_NODE_CRYPTO_H
#define MWC_VALIDATION_NODE_CRYPTO_H


// Header files
#include "./common.h"
#include <memory>
#include "secp256k1_bulletproofs.h"

using namespace std;


// Namespace
namespace MwcValidationNode {


// Classes

// Header class forward declaration
class Header;

// Kernel class forward declaration
class Kernel;

// Merkle mountain range forward declaration
template<typename MerkleMountainRangeLeafDerivedClass> class MerkleMountainRange;

// Output class forward declaration
class Output;

// Crypto class
class Crypto final {

	// Public
	public:
	
		// Constructor
		Crypto() = delete;
		
		// BLAKE2b hash length
		static const size_t BLAKE2B_HASH_LENGTH = 32;
		
		// Secp256k1 private key length
		static const size_t SECP256K1_PRIVATE_KEY_LENGTH = 32;
		
		// Cuckoo-cycle number of proof nonces
		static const uint64_t CUCKOO_CYCLE_NUMBER_OF_PROOF_NONCES = 42;
		
		// Commitment length
		static const size_t COMMITMENT_LENGTH = 33;
		
		// Bulletproof length
		static const size_t BULLETPROOF_LENGTH = 675;
		
		// Single-signer signature length
		static const size_t SINGLE_SIGNER_SIGNATURE_LENGTH = 64;
		
		// Get secp256k1 context
		static const secp256k1_context *getSecp256k1Context();
		
		// Get secp256k1 scratch space
		static secp256k1_scratch_space *getSecp256k1ScratchSpace();
		
		// Get secp256k1 generators
		static const secp256k1_bulletproof_generators *getSecp256k1Generators();
		
		// Verify kernel sums
		static bool verifyKernelSums(const Header &header, const MerkleMountainRange<Kernel> &kernels, const MerkleMountainRange<Output> &outputs);
	
	// Private
	private:
	
		// Secp256k1 scratch space length
		static const size_t SECP256K1_SCRATCH_SPACE_LENGTH;
		
		// Secp256k1 number of generators
		static const size_t SECP256k1_NUMBER_OF_GENERATORS;
		
		// Secp256k1 context
		static const unique_ptr<secp256k1_context, decltype(&secp256k1_context_destroy)> secp256k1Context;
		
		// Secp256k1 scratch space
		static thread_local const unique_ptr<secp256k1_scratch_space, decltype(&secp256k1_scratch_space_destroy)> secp256k1ScratchSpace;
		
		// Secp256k1 generators
		static const unique_ptr<secp256k1_bulletproof_generators, void(*)(secp256k1_bulletproof_generators *)> secp256k1Generators;
};


}


#endif
