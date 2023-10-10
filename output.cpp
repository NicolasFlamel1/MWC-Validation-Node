// Header files
#include"./common.h"
#include <cstring>
#include "./consensus.h"
#include "./output.h"
#include "secp256k1_commitment.h"

using namespace std;


// Namespace
using namespace MwcValidationNode;


// Supporting function implementation

// Constructor
Output::Output(const Features features, const uint8_t commitment[Crypto::COMMITMENT_LENGTH], const bool isGenesisBlockOutput) :

	// Set features to features
	features(features)
{

	// Check if features is invalid
	if(features == Features::UNKNOWN) {
	
		// Throw exception
		throw runtime_error("Features is invalid");
	}
	
	// Check if commitment is invalid
	if(!secp256k1_pedersen_commitment_parse(secp256k1_context_no_precomp, &this->commitment, commitment)) {
	
		// Throw exception
		throw runtime_error("Commitment is invalid");
	}
	
	// Check if output doesn't match the genesis block output
	if(isGenesisBlockOutput && *this != Consensus::GENESIS_BLOCK_OUTPUT) {
	
		// Throw exception
		throw runtime_error("Output doesn't match the genesis block output");
	}
}

// Serialize
vector<uint8_t> Output::serialize() const {

	// Initialize serialized output
	vector<uint8_t> serializedOutput;
	
	// Append features to serialized output
	Common::writeUint8(serializedOutput, static_cast<underlying_type_t<Features>>(features));
	
	// Check if serializing commitment failed
	uint8_t serializedCommitment[Crypto::COMMITMENT_LENGTH];
	if(!secp256k1_pedersen_commitment_serialize(secp256k1_context_no_precomp, serializedCommitment, &commitment)) {
	
		// Throw exception
		throw runtime_error("Serializing commitment failed");
	}
	
	// Append serialized commitment to serialized output
	serializedOutput.insert(serializedOutput.cend(), cbegin(serializedCommitment), cend(serializedCommitment));
	
	// Return serialized output
	return serializedOutput;
}

// Get lookup value
optional<vector<uint8_t>> Output::getLookupValue() const {

	// Check if serializing commitment failed
	vector<uint8_t> serializedCommitment(Crypto::COMMITMENT_LENGTH);
	if(!secp256k1_pedersen_commitment_serialize(secp256k1_context_no_precomp, serializedCommitment.data(), &commitment)) {
	
		// Throw exception
		throw runtime_error("Serializing commitment failed");
	}
	
	// Return serialized commitment
	return serializedCommitment;
}

// Add to sum
void Output::addToSum(secp256k1_pedersen_commitment &sum, const AdditionReason additionReason) const {

	// Check if sum is zero
	if(all_of(reinterpret_cast<uint8_t *>(&sum), reinterpret_cast<uint8_t *>(&sum) + sizeof(sum), [](const uint8_t value) {
	
		// Return if value is zero
		return !value;
	})) {
	
		// Set sum to commitment
		sum = commitment;
	}
	
	// Otherwise
	else {
	
		// Set positive commitments
		const secp256k1_pedersen_commitment *positiveCommitments[] = {
		
			// Sum
			&sum,
			
			// Commitment
			&commitment
		};
		
		// Set negative commitments
		const secp256k1_pedersen_commitment *negativeCommitments[] = {};

		// Check if adding to positive and negative commitments failed
		secp256k1_pedersen_commitment result;
		if(!secp256k1_pedersen_commit_sum(secp256k1_context_no_precomp, &result, positiveCommitments, 2, negativeCommitments, 0)) {
		
			// Throw exception
			throw runtime_error("Adding to positive and negative commitments failed");
		}
		
		// Set sum to the result
		sum = result;
	}
}

// Subtract from sum
void Output::subtractFromSum(secp256k1_pedersen_commitment &sum, const SubtractionReason subtractionReason) const {

	// Check if subtracting because pruned or rewinded
	if(subtractionReason == SubtractionReason::PRUNED || subtractionReason == SubtractionReason::REWINDED) {
	
		// Check if sum is zero
		if(all_of(reinterpret_cast<uint8_t *>(&sum), reinterpret_cast<uint8_t *>(&sum) + sizeof(sum), [](const uint8_t value) {
		
			// Return if value is zero
			return !value;
		})) {
		
			// Set positive commitments
			const secp256k1_pedersen_commitment *positiveCommitments[] = {};
			
			// Set negative commitments
			const secp256k1_pedersen_commitment *negativeCommitments[] = {
			
				// Commitment
				&commitment
			};

			// Check if adding to positive and negative commitments failed
			secp256k1_pedersen_commitment result;
			if(!secp256k1_pedersen_commit_sum(secp256k1_context_no_precomp, &result, positiveCommitments, 0, negativeCommitments, 1)) {
			
				// Throw exception
				throw runtime_error("Adding to positive and negative commitments failed");
			}
			
			// Set sum to the result
			sum = result;
		}
		
		// Otherwise
		else {
	
			// Check if serializing sum and/or commitment failed
			uint8_t serializedSum[Crypto::COMMITMENT_LENGTH];
			uint8_t serializedCommitment[Crypto::COMMITMENT_LENGTH];
			if(!secp256k1_pedersen_commitment_serialize(secp256k1_context_no_precomp, serializedSum, &sum) || !secp256k1_pedersen_commitment_serialize(secp256k1_context_no_precomp, serializedCommitment, &commitment)) {
			
				// Throw exception
				throw runtime_error("Serializing sum and/or commitment failed");
			}
			
			// Check if serialized sum and serialized commitment are equal
			if(!memcmp(serializedSum, serializedCommitment, sizeof(serializedCommitment))) {
			
				// Set sum to zero
				memset(&sum, 0, sizeof(sum));
			}
			
			// Otherwise
			else {
			
				// Set positive commitments
				const secp256k1_pedersen_commitment *positiveCommitments[] = {
				
					// Sum
					&sum
				};
				
				// Set negative commitments
				const secp256k1_pedersen_commitment *negativeCommitments[] = {
				
					// Commitment
					&commitment
				};

				// Check if adding to positive and negative commitments failed
				secp256k1_pedersen_commitment result;
				if(!secp256k1_pedersen_commit_sum(secp256k1_context_no_precomp, &result, positiveCommitments, 1, negativeCommitments, 1)) {
				
					// Throw exception
					throw runtime_error("Adding to positive and negative commitments failed");
				}
				
				// Set sum to the result
				sum = result;
			}
		}
	}
}

// Save
void Output::save(ofstream &file) const {

	// Write features to file
	file.write(reinterpret_cast<const char *>(&features), sizeof(features));
	
	// Check if serializing commitment failed
	uint8_t serializedCommitment[Crypto::COMMITMENT_LENGTH];
	if(!secp256k1_pedersen_commitment_serialize(secp256k1_context_no_precomp, serializedCommitment, &commitment)) {
	
		// Throw exception
		throw runtime_error("Serializing commitment failed");
	}
	
	// Write commitment to file
	file.write(reinterpret_cast<const char *>(serializedCommitment), sizeof(serializedCommitment));
}

// Equality operator
bool Output::operator==(const Output &other) const {

	// Check if features differ
	if(features != other.features) {
	
		// Return false
		return false;
	}
	
	// Check if serializing commitments failed
	uint8_t serializedCommitment[Crypto::COMMITMENT_LENGTH];
	uint8_t otherSerializedCommitment[Crypto::COMMITMENT_LENGTH];
	if(!secp256k1_pedersen_commitment_serialize(secp256k1_context_no_precomp, serializedCommitment, &commitment) || !secp256k1_pedersen_commitment_serialize(secp256k1_context_no_precomp, otherSerializedCommitment, &other.commitment)) {
	
		// Throw exception
		throw runtime_error("Serializing commitments failed");
	}
	
	// Check if serialized commitments differ
	if(memcmp(serializedCommitment, otherSerializedCommitment, sizeof(otherSerializedCommitment))) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Inequality operator
bool Output::operator!=(const Output &other) const {

	// Return if outputs aren't equal
	return !(*this == other);
}

// Get features
Output::Features Output::getFeatures() const {

	// Return features
	return features;
}

// Get commitment
const secp256k1_pedersen_commitment &Output::getCommitment() const {

	// Return commitment
	return commitment;
}

// Get serialized protocol version
uint32_t Output::getSerializedProtocolVersion(const array<uint8_t, MAXIMUM_SERIALIZED_LENGTH> &serializedOutput, const array<uint8_t, MAXIMUM_SERIALIZED_LENGTH>::size_type serializedOutputLength, const uint32_t protocolVersion) {

	// Return protocol version
	return protocolVersion;
}

// Unserialize
pair<Output, array<uint8_t, Output::MAXIMUM_SERIALIZED_LENGTH>::size_type> Output::unserialize(const array<uint8_t, MAXIMUM_SERIALIZED_LENGTH> &serializedOutput, const array<uint8_t, MAXIMUM_SERIALIZED_LENGTH>::size_type serializedOutputLength, const uint32_t protocolVersion, const bool isGenesisBlockOutput) {

	// Check if serialized output doesn't contain features and a commitment
	if(serializedOutputLength < MAXIMUM_SERIALIZED_LENGTH) {
	
		// Throw exception
		throw runtime_error("Serialized output doesn't contain features and a commitment");
	}
	
	// Get features from serialized output
	const Features features = (Common::readUint8(serializedOutput, 0) < static_cast<underlying_type_t<Features>>(Features::UNKNOWN)) ? static_cast<Features>(Common::readUint8(serializedOutput, 0)) : Features::UNKNOWN;
	
	// Get commitment from serialized output
	const uint8_t *commitment = &serializedOutput[sizeof(features)];
	
	// Return output
	return {Output(features, commitment, isGenesisBlockOutput), MAXIMUM_SERIALIZED_LENGTH};
}

// Restore
Output Output::restore(ifstream &file) {

	// Return output created from file
	return Output(file);
}

// Save sum
void Output::saveSum(const secp256k1_pedersen_commitment &sum, ofstream &file) {

	// Check if sum isn't zero
	uint8_t serializedSum[Crypto::COMMITMENT_LENGTH] = {};
	if(any_of(reinterpret_cast<const uint8_t *>(&sum), reinterpret_cast<const uint8_t *>(&sum) + sizeof(sum), [](const uint8_t value) {
	
		// Return if value isn't zero
		return value;
	})) {
	
		// Check if serializing sum failed
		if(!secp256k1_pedersen_commitment_serialize(secp256k1_context_no_precomp, serializedSum, &sum)) {
		
			// Throw exception
			throw runtime_error("Serializing sum failed");
		}
	}
	
	// Write sum to file
	file.write(reinterpret_cast<const char *>(serializedSum), sizeof(serializedSum));
}

// Restore sum
void Output::restoreSum(secp256k1_pedersen_commitment &sum, ifstream &file) {

	// Read sum from file
	uint8_t serializedSum[Crypto::COMMITMENT_LENGTH];
	file.read(reinterpret_cast<char *>(serializedSum), sizeof(serializedSum));
	
	// Check if sum is zero
	if(all_of(serializedSum, serializedSum + sizeof(serializedSum), [](const uint8_t value) {
	
		// Return if value is zero
		return !value;
	})) {
	
		// Set sum to zero
		memset(&sum, 0, sizeof(sum));
	}
	
	// Otherwise
	else {
	
		// Check if parsing sum failed
		if(!secp256k1_pedersen_commitment_parse(secp256k1_context_no_precomp, &sum, serializedSum)) {
	
			// Throw exception
			throw runtime_error("Parsing sum failed");
		}
	}
}

// Constructor
Output::Output(ifstream &file) {

	// Read features from file
	file.read(reinterpret_cast<char *>(&features), sizeof(features));
	
	// Read commitment from file
	uint8_t serializedCommitment[Crypto::COMMITMENT_LENGTH];
	file.read(reinterpret_cast<char *>(serializedCommitment), sizeof(serializedCommitment));
	
	// Check if parsing commitment failed
	if(!secp256k1_pedersen_commitment_parse(secp256k1_context_no_precomp, &commitment, serializedCommitment)) {
	
		// Throw exception
		throw runtime_error("Parsing commitment failed");
	}
}
