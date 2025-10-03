// Header guard
#ifndef MWC_VALIDATION_NODE_INPUT_H
#define MWC_VALIDATION_NODE_INPUT_H


// Header files
#include "./common.h"
#include "./crypto.h"
#include "./output.h"

using namespace std;


// Namespace
namespace MwcValidationNode {


// Classes

// Node class forward declaration
class Node;

// Block class forward declaration
class Block;

// Message class forward declaration
class Message;

// Transaction class forward declaration
class Transaction;

// Input class
class Input final {

	// Public
	public:
	
		// Features
		enum class Features : uint8_t {
		
			// Plain
			PLAIN,
			
			// Coinbase
			COINBASE,
			
			// Unknown
			UNKNOWN,
			
			// Same as output
			SAME_AS_OUTPUT
		};
		
		// Constructor
		explicit Input(const Features features, const uint8_t commitment[Crypto::COMMITMENT_LENGTH]);
		
		// Get features
		Features getFeatures() const;
		
		// Get commitment
		const secp256k1_pedersen_commitment &getCommitment() const;
		
		// Get lookup value
		vector<uint8_t> getLookupValue() const;
		
	// Public for node class
	private:
	
		// Node friend class
		friend class Node;
		
		// Set features
		void setFeatures(const Features features);
		
	// Public for block, message, and transaction classes
	private:
	
		// Block, message, and transaction friend classes
		friend class Block;
		friend class Message;
		friend class Transaction;
		
		// Serialize
		vector<uint8_t> serialize(const uint32_t protocolVersion = 0) const;
		
	// Private
	private:
	
		// Features
		Features features;
		
		// Commitment
		secp256k1_pedersen_commitment commitment;
};


}


#endif
