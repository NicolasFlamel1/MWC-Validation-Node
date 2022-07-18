// Header guard
#ifndef KERNEL_H
#define KERNEL_H


// Header files
#include "./common.h"
#include "./crypto.h"
#include "./merkle_mountain_range_leaf.h"

using namespace std;


// Classes

// Kernel class
class Kernel final : public MerkleMountainRangeLeaf<Kernel, sizeof(uint8_t) + sizeof(uint64_t) + sizeof(uint64_t) + Crypto::COMMITMENT_LENGTH + Crypto::SINGLE_SIGNER_SIGNATURE_LENGTH, secp256k1_pedersen_commitment> {

	// Public
	public:
	
		// Features
		enum class Features : uint8_t {
		
			// Plain
			PLAIN,
			
			// Coinbase
			COINBASE,
			
			// Height locked
			HEIGHT_LOCKED,
			
			// No recent duplicate
			NO_RECENT_DUPLICATE,
			
			// Unknown
			UNKNOWN
		};
		
		// Constructor
		explicit Kernel(const Features features, const uint64_t fee, const uint64_t lockHeight, const uint64_t relativeHeight, const uint8_t excess[Crypto::COMMITMENT_LENGTH], const uint8_t signature[Crypto::SINGLE_SIGNER_SIGNATURE_LENGTH], const bool isGenesisBlockKernel = false);
		
		// Serialize
		virtual const vector<uint8_t> serialize() const override final;
		
		// Add to sum
		virtual void addToSum(secp256k1_pedersen_commitment &sum, const AdditionReason additionReason) const override final;
		
		// Subtract from sum
		virtual void subtractFromSum(secp256k1_pedersen_commitment &sum, const SubtractionReason subtractionReason) const override final;
		
		// Equality operator
		const bool operator==(const Kernel &other) const;
		
		// Inequality operator
		const bool operator!=(const Kernel &other) const;
		
		// Get features
		const Features getFeatures() const;
		
		// Get fee
		const uint64_t getFee() const;
		
		// Get lock height
		const uint64_t getLockHeight() const;
		
		// Get relative height
		const uint64_t getRelativeHeight() const;
		
		// Get excess
		const secp256k1_pedersen_commitment &getExcess() const;
		
		// Get signature
		const secp256k1_ecdsa_signature &getSignature() const;
		
		// Unserialize
		static const Kernel unserialize(const array<uint8_t, SERIALIZED_LENGTH> &serializedKernel, const bool isGenesisBlockKernel);
	
	// Private
	private:
	
		// Maximum relative height
		static const uint64_t MAXIMUM_RELATIVE_HEIGHT;
		
		// Get message to sign
		const array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH> getMessageToSign() const;
		
		// Features
		Features features;
		
		// Fee
		uint64_t fee;
		
		// Lock height
		uint64_t lockHeight;
		
		// Relative height
		uint64_t relativeHeight;
		
		// Excess
		secp256k1_pedersen_commitment excess;
		
		// Signature
		secp256k1_ecdsa_signature signature;
};


#endif
