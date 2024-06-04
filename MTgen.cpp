#include <iostream>
#include <fstream>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <vector>
#include <cstring>
#include <bitset>
#include <stdexcept>
#include <cmath>
#include <map>
#include <chrono>
#include <random>

class SHA256RandomGenerator {
public:
    SHA256RandomGenerator() {

        if (RAND_bytes(seed, sizeof(seed)) != 1) {
            throw std::runtime_error("Failed to initialize entropy source");
        }
    }

    std::vector<unsigned char> generateRandomBytes(size_t numBytes) {
        std::vector<unsigned char> randomBytes;
        randomBytes.reserve(numBytes);

        while (randomBytes.size() < numBytes) {

            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256(seed, sizeof(seed), hash);


            size_t bytesToCopy = std::min(numBytes - randomBytes.size(), sizeof(hash));
            randomBytes.insert(randomBytes.end(), hash, hash + bytesToCopy);


            memcpy(seed, hash, sizeof(seed));
        }

        return randomBytes;
    }

private:
    unsigned char seed[SHA256_DIGEST_LENGTH];
};

void writeBitsToFile(const std::vector<unsigned char>& data, const std::string& filename) {
    std::ofstream outFile(filename);
    if (!outFile) {
        throw std::runtime_error("Failed to open file for writing");
    }

    for (const auto& byte : data) {
        std::bitset<8> bits(byte);
        outFile << bits.to_string();
    }

    outFile.close();
}

std::vector<unsigned char> readFromFile(const std::string& filename) {
    std::ifstream inFile(filename, std::ios::binary);
    if (!inFile) {
        throw std::runtime_error("Failed to open file for reading");
    }
    std::vector<unsigned char> data((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();
    return data;
}

void runBitwiseTest(const std::vector<unsigned char>& randomBytes) {
    int zeroCount = 0;
    int oneCount = 0;

    for (unsigned char byte : randomBytes) {
        std::bitset<8> bits(byte);
        zeroCount += bits.size() - bits.count();
        oneCount += bits.count();
    }

    std::cout << "Zero count: " << zeroCount << std::endl;
    std::cout << "One count: " << oneCount << std::endl;


    double totalBits = zeroCount + oneCount;
    double expectedCount = totalBits / 2.0;
    double chiSquare = (std::pow(zeroCount - expectedCount, 2) / expectedCount) +
                       (std::pow(oneCount - expectedCount, 2) / expectedCount);

    std::cout << "Chi-square value: " << chiSquare << std::endl;
    

    double criticalValue = 3.841; 
    if (chiSquare < criticalValue) {
        std::cout << "Passes the bitwise test for randomness." << std::endl;
    } else {
        std::cout << "Fails the bitwise test for randomness." << std::endl;
    }
}

void runBlockTest(const std::vector<unsigned char>& randomBytes, size_t blockSize) {
    size_t numBits = randomBytes.size() * 8;
    size_t numBlocks = numBits / blockSize;
    std::map<std::string, int> blockCount;

    for (size_t i = 0; i < numBlocks; ++i) {
        std::string block = "";
        for (size_t j = 0; j < blockSize; ++j) {
            size_t bitIndex = i * blockSize + j;
            size_t byteIndex = bitIndex / 8;
            size_t bitOffset = bitIndex % 8;
            bool bit = (randomBytes[byteIndex] >> (7 - bitOffset)) & 1;
            block += bit ? '1' : '0';
        }
        blockCount[block]++;
    }

    std::cout << "Block counts: " << std::endl;
    for (const auto& pair : blockCount) {
        std::cout << pair.first << ": " << pair.second << std::endl;
    }


    double expectedCount = numBlocks / std::pow(2, blockSize);
    double chiSquare = 0.0;
    for (const auto& pair : blockCount) {
        chiSquare += std::pow(pair.second - expectedCount, 2) / expectedCount;
    }

    std::cout << "Block chi-square value: " << chiSquare << std::endl;

    double criticalValue = 24.996; 
    if (blockCount.size() > 1) {
        criticalValue = 24.996; 
    }
    if (chiSquare < criticalValue) {
        std::cout << "Passes the block test for randomness." << std::endl;
    } else {
        std::cout << "Fails the block test for randomness." << std::endl;
    }
}

void generateAndTestFile(size_t fileSizeMB, const std::string& filename) {
    SHA256RandomGenerator rng;

    size_t fileSize = fileSizeMB * 1024 * 1024;
    auto start = std::chrono::high_resolution_clock::now();
    std::vector<unsigned char> randomBytes = rng.generateRandomBytes(fileSize);
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> generationTime = end - start;
    std::cout << "Generation time for " << fileSizeMB << " MB: " << generationTime.count() << " seconds" << std::endl;

    writeBitsToFile(randomBytes, filename);
}

void generateRandomKeys(SHA256RandomGenerator& rng, size_t numKeys) {
    size_t keySize = 32; 
    auto start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < numKeys; ++i) {
        std::vector<unsigned char> key = rng.generateRandomBytes(keySize);
    }
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> generationTime = end - start;
    std::cout << "Generation time for " << numKeys << " keys: " << generationTime.count() << " seconds" << std::endl;
}

void testRandomKeyGeneration(SHA256RandomGenerator& rng) {

    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<size_t> dist(1000, 10000);
    size_t numKeys = dist(mt);

    std::cout << "Generating " << numKeys << " keys..." << std::endl;
    generateRandomKeys(rng, numKeys);
}

int main() {
    try {
        SHA256RandomGenerator rng;

        std::vector<unsigned char> randomBytes = rng.generateRandomBytes(1000);

        writeBitsToFile(randomBytes, "output.txt");

        std::vector<unsigned char> readBytes = readFromFile("output.txt");

        runBitwiseTest(readBytes);

        runBlockTest(readBytes, 8);

        testRandomKeyGeneration(rng);

        generateAndTestFile(1, "output_1MB.txt");
        generateAndTestFile(100, "output_100MB.txt");
        generateAndTestFile(1000, "output_1000MB.txt");

    } catch (const std::exception &ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
