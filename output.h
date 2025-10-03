// Header guard
#ifndef MWC_VALIDATION_NODE_OUTPUT_H
#define MWC_VALIDATION_NODE_OUTPUT_H


// Header files
#include "./common.h"
#include "./crypto.h"
#include "./merkle_mountain_range_leaf.h"

using namespace std;


// Namespace
namespace MwcValidationNode {


// Classes

// Merkle mountain range class forward declaration
template<typename MerkleMountainRangeLeafDerivedClass> class MerkleMountainRange;

// Node class forward declaration
class Node;

// Block class forward declaration
class Block;

// Transaction class forward declaration
class Transaction;

// Consensus class forward declaration
class Consensus;

// Output class
class Output final : public MerkleMountainRangeLeaf<Output, sizeof(uint8_t) + Crypto::COMMITMENT_LENGTH, secp256k1_pedersen_commitment> {

	// Public
	public:
	
		// Features
		enum class Features : uint8_t {
		
			// Plain
			PLAIN,
			
			// Coinbase
			COINBASE,
			
			// Unknown
			UNKNOWN
		};
		
		// Constructor
		explicit Output(const Features features, const uint8_t commitment[Crypto::COMMITMENT_LENGTH]);
		
		// Get features
		Features getFeatures() const;
		
		// Get commitment
		const secp256k1_pedersen_commitment &getCommitment() const;
		
		// Equality operator
		bool operator==(const Output &other) const;
		
		// Inequality operator
		bool operator!=(const Output &other) const;
		
		// Get lookup value
		virtual optional<vector<uint8_t>> getLookupValue() const override final;
		
	// Public for Merkle mountain range class
	private:
	
		// Merkle mountain range friend class
		friend class MerkleMountainRange<Output>;
		
		// Add to sum
		virtual void addToSum(secp256k1_pedersen_commitment &sum, const AdditionReason additionReason) const override final;
		
		// Subtract from sum
		virtual void subtractFromSum(secp256k1_pedersen_commitment &sum, const SubtractionReason subtractionReason) const override final;
		
		// Save
		virtual void save(ofstream &file) const override final;
		
		// Restore
		static Output restore(ifstream &file);
		
		// Save sum
		static void saveSum(const secp256k1_pedersen_commitment &sum, ofstream &file);
		
		// Restore sum
		static void restoreSum(secp256k1_pedersen_commitment &sum, ifstream &file);
		
		// Get serialized protocol version
		static uint32_t getSerializedProtocolVersion(const array<uint8_t, MAXIMUM_SERIALIZED_LENGTH> &serializedOutput, const array<uint8_t, MAXIMUM_SERIALIZED_LENGTH>::size_type serializedOutputLength, const uint32_t protocolVersion);
		
		// Unserialize
		static pair<Output, array<uint8_t, MAXIMUM_SERIALIZED_LENGTH>::size_type> unserialize(const array<uint8_t, MAXIMUM_SERIALIZED_LENGTH> &serializedOutput, const array<uint8_t, MAXIMUM_SERIALIZED_LENGTH>::size_type serializedOutputLength, const uint32_t protocolVersion, const bool isGenesisBlockOutput);
		
	// Public for node, block, and transaction classes
	private:
	
		// Node, block, and transaction friend classes
		friend class Node;
		friend class Block;
		friend class Transaction;
		
		// Serialize
		virtual vector<uint8_t> serialize() const override final;
		
	// Public for consensus class
	private:
	
		// Consensus friend class
		friend class Consensus;
		
		// Constructor
		explicit Output(const Features features, const uint8_t commitment[Crypto::COMMITMENT_LENGTH], const bool isGenesisBlockOutput);
		
	// Private
	private:
	
		// Constructor
		explicit Output(ifstream &file);
		
		// Features
		Features features;
		
		// Commitment
		secp256k1_pedersen_commitment commitment;
};


}


#endif
