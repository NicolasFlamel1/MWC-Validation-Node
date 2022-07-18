// Header guard
#ifndef CONSENSUS_H
#define CONSENSUS_H


// Header files
#include "./common.h"
#include "./header.h"
#include "./kernel.h"
#include "./output.h"
#include "./rangeproof.h"

using namespace std;


// Classes

// Consensus class
class Consensus final {

	// Public
	public:
		
		// Block time
		static const chrono::seconds BLOCK_TIME;
		
		// Minute height
		static const uint64_t MINUTE_HEIGHT;
		
		// Hour height
		static const uint64_t HOUR_HEIGHT;
		
		// Day height
		static const uint64_t DAY_HEIGHT;
		
		// Week height
		static const uint64_t WEEK_HEIGHT;
		
		// Year height
		static const uint64_t YEAR_HEIGHT;
		
		// C29 edge bits
		static const uint8_t C29_EDGE_BITS;
		
		// C31 edge bits
		static const uint8_t C31_EDGE_BITS;
		
		// Maximum edge bits
		static const uint8_t MAXIMUM_EDGE_BITS;
		
		// Genesis block header
		static const Header GENESIS_BLOCK_HEADER;
		
		// Genesis block kernel
		static const Kernel GENESIS_BLOCK_KERNEL;
		
		// Genesis block output
		static const Output GENESIS_BLOCK_OUTPUT;
		
		// Genesis block rangeproof
		static const Rangeproof GENESIS_BLOCK_RANGEPROOF;
	
		// Maximum block weight
		static const uint64_t MAXIMUM_BLOCK_WEIGHT;
		
		// Block input weight
		static const uint64_t BLOCK_INPUT_WEIGHT;
		
		// Block output weight
		static const uint64_t BLOCK_OUTPUT_WEIGHT;
		
		// Block kernel weight
		static const uint64_t BLOCK_KERNEL_WEIGHT;
		
		// Block output length
		static const size_t BLOCK_OUTPUT_LENGTH;
		
		// Maximum block length
		static const size_t MAXIMUM_BLOCK_LENGTH;
		
		// Difficulty adjustment window
		static const uint64_t DIFFICULTY_ADJUSTMENT_WINDOW;
		
		// C29 headers adjustment damp factor
		static const uint64_t C29_HEADERS_ADJUSTMENT_DAMP_FACTOR;
		
		// C29 headers adjustment clamp factor
		static const uint64_t C29_HEADERS_ADJUSTMENT_CLAMP_FACTOR;
		
		// Minimum secondary scaling
		static const uint32_t MINIMUM_SECONDARY_SCALING;
		
		// Window duration adjustment damp factor
		static const uint64_t WINDOW_DURATION_ADJUSTMENT_DAMP_FACTOR;

		// Window duration adjustment clamp factor
		static const uint64_t WINDOW_DURATION_ADJUSTMENT_CLAMP_FACTOR;

		// Minimum difficulty
		static const uint64_t MINIMUM_DIFFICULTY;
		
		// State sync height threshold
		static const uint64_t STATE_SYNC_HEIGHT_THRESHOLD;
		
		// Cut through horizon
		static const uint64_t CUT_THROUGH_HORIZON;
		
		// Coinbase maturity
		static const uint64_t COINBASE_MATURITY;
		
		// Constructor
		Consensus() = delete;
		
		// Get header version
		static const uint16_t getHeaderVersion(const uint64_t height);
		
		// Get block weight
		static const uint64_t getBlockWeight(const uint64_t numberOfInputs, const uint64_t numberOfOutputs, const uint64_t numberOfKernels);
		
		// Is block hash banned
		static const bool isBlockHashBanned(const uint8_t blockHash[Crypto::BLAKE2B_HASH_LENGTH]);
		
		// Get graph weight
		static const uint64_t getGraphWeight(const uint64_t height, const uint8_t edgeBits);
		
		// Get C29 proof of work ratio
		static const uint64_t getC29ProofOfWorkRatio(const uint64_t height);
		
		// Get maximum difficulty
		static const uint64_t getMaximumDifficulty(const Header &header);
		
		// Get coinbase reward
		static const uint64_t getCoinbaseReward(const uint64_t height);
		
		// Get total number of coinbase rewards
		static const uint64_t getTotalNumberOfCoinbaseRewards(const uint64_t height);
	
	// Private
	private:
	
		// C31 hard fork height
		static const uint64_t C31_HARD_FORK_HEIGHT;
		
		// Base edge bits
		static const uint8_t BASE_EDGE_BITS;
		
		// Banned block hashes
		static const uint8_t BANNED_BLOCK_HASHES[][Crypto::BLAKE2B_HASH_LENGTH];
		
		// Starting C29 proof of work ratio
		static const int STARTING_C29_PROOF_OF_WORK_RATIO;
		
		// C29 proof of work duration
		static const uint64_t C29_PROOF_OF_WORK_DURATION;
		
		// Get epoch reward
		static const uint64_t getEpochReward(const uint8_t epoch);
		
		// Get epoch block offset
		static const uint64_t getEpochBlockOffset(const uint8_t epoch);
		
		// Get epoch duration
		static const uint64_t getEpochDuration(const uint8_t epoch);
};


#endif
