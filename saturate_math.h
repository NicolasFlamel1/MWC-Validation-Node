// Header guard
#ifndef SATURATE_MATH_H
#define SATURATE_MATH_H


// Header files
#include "./common.h"

using namespace std;


// Classes

// Saturate math class
class SaturateMath final {

	// Public
	public:
	
		// Constructor
		SaturateMath() = delete;
		
		// Add
		static const uint64_t add(const uint64_t firstAddend, const uint64_t secondAddend);
		
		// Subtract
		static const uint64_t subtract(const uint64_t minuend, const uint64_t subtrahend);
		
		// Multiply
		static const uint64_t multiply(const uint64_t multiplicand, const uint64_t multiplier);
};


#endif
