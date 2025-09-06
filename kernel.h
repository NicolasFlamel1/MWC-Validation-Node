// Header guard
#ifndef MWC_VALIDATION_NODE_KERNEL_H
#define MWC_VALIDATION_NODE_KERNEL_H


// Header files
#include "./common.h"
#include "./crypto.h"
#include "./merkle_mountain_range_leaf.h"

using namespace std;


// Namespace
namespace MwcValidationNode {


// Classes

// Kernel class
class Kernel final : public MerkleMountainRangeLeaf<Kernel, sizeof(uint8_t) + sizeof(uint64_t) + sizeof(uint64_t) + Crypto::COMMITMENT_LENGTH + Crypto::SINGLE_SIGNER_SIGNATURE_LENGTH, secp256k1_pedersen_commitment, true> {

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
		virtual vector<uint8_t> serialize() const override final;
		
		// Get lookup value
		virtual optional<vector<uint8_t>> getLookupValue() const override final;
		
		// Add to sum
		virtual void addToSum(secp256k1_pedersen_commitment &sum, const AdditionReason additionReason) const override final;
		
		// Subtract from sum
		virtual void subtractFromSum(secp256k1_pedersen_commitment &sum, const SubtractionReason subtractionReason) const override final;
		
		// Save
		virtual void save(ofstream &file) const override final;
		
		// Equality operator
		bool operator==(const Kernel &other) const;
		
		// Inequality operator
		bool operator!=(const Kernel &other) const;
		
		// Get features
		Features getFeatures() const;
		
		// Get masked fee
		uint64_t getMaskedFee() const;
		
		// Get unmasked fee
		uint64_t getUnmaskedFee() const;
		
		// Get lock height
		uint64_t getLockHeight() const;
		
		// Get relative height
		uint64_t getRelativeHeight() const;
		
		// Get excess
		const secp256k1_pedersen_commitment &getExcess() const;
		
		// Get signature
		const uint8_t *getSignature() const;
		
		// Get serialized protocol version
		static uint32_t getSerializedProtocolVersion(const array<uint8_t, MAXIMUM_SERIALIZED_LENGTH> &serializedKernel, const array<uint8_t, MAXIMUM_SERIALIZED_LENGTH>::size_type serializedKernelLength, const uint32_t protocolVersion);
		
		// Unserialize
		static pair<Kernel, array<uint8_t, MAXIMUM_SERIALIZED_LENGTH>::size_type> unserialize(const array<uint8_t, MAXIMUM_SERIALIZED_LENGTH> &serializedKernel, const array<uint8_t, MAXIMUM_SERIALIZED_LENGTH>::size_type serializedKernelLength, const uint32_t protocolVersion, const bool isGenesisBlockKernel);
		
		// Restore
		static Kernel restore(ifstream &file);
		
		// Save sum
		static void saveSum(const secp256k1_pedersen_commitment &sum, ofstream &file);
		
		// Restore sum
		static void restoreSum(secp256k1_pedersen_commitment &sum, ifstream &file);
	
	// Private
	private:
	
		// Constructor
		explicit Kernel(ifstream &file);
		
		// Maximum relative height
		static const uint64_t MAXIMUM_RELATIVE_HEIGHT;
		
		// Get message to sign
		array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH> getMessageToSign() const;
		
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
		uint8_t signature[Crypto::SINGLE_SIGNER_SIGNATURE_LENGTH];
};


}


#endif
