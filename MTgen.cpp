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

class SHA256RandomGenerator {
public:
    SHA256RandomGenerator() {
        // Инициализируем начальную энтропию
        if (RAND_bytes(seed, sizeof(seed)) != 1) {
            throw std::runtime_error("Failed to initialize entropy source");
        }
    }

    std::vector<unsigned char> generateRandomBytes(size_t numBytes) {
        std::vector<unsigned char> randomBytes;
        randomBytes.reserve(numBytes);

        while (randomBytes.size() < numBytes) {
            // Хешируем текущий seed с помощью SHA-256
            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256(seed, sizeof(seed), hash);

            // Добавляем хешированные байты к выходу
            size_t bytesToCopy = std::min(numBytes - randomBytes.size(), sizeof(hash));
            randomBytes.insert(randomBytes.end(), hash, hash + bytesToCopy);

            // Обновляем seed
            memcpy(seed, hash, sizeof(seed));
        }

        return randomBytes;
    }

private:
    unsigned char seed[SHA256_DIGEST_LENGTH];
};

void writeToFile(const std::vector<unsigned char>& data, const std::string& filename) {
    std::ofstream outFile(filename, std::ios::binary);
    if (!outFile) {
        throw std::runtime_error("Failed to open file for writing");
    }
    outFile.write(reinterpret_cast<const char*>(data.data()), data.size());
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

    // Проверяем, что количество нулей и единиц примерно равно
    double totalBits = zeroCount + oneCount;
    double expectedCount = totalBits / 2;
    double chiSquare = (std::pow(zeroCount - expectedCount, 2) / expectedCount) +
                       (std::pow(oneCount - expectedCount, 2) / expectedCount);

    std::cout << "Chi-square value: " << chiSquare << std::endl;
    
    // Для 1 степени свободы и уровня значимости 0.05 критическое значение хи-квадрат ~3.841
    if (chiSquare < 3.841) {
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

    // Проверяем равномерное распределение блоков
    double expectedCount = numBlocks / std::pow(2, blockSize);
    double chiSquare = 0.0;
    for (const auto& pair : blockCount) {
        chiSquare += std::pow(pair.second - expectedCount, 2) / expectedCount;
    }

    std::cout << "Block chi-square value: " << chiSquare << std::endl;

    // Для k степеней свободы и уровня значимости 0.05 критическое значение хи-квадрат
    double criticalValue = 24.996; // Для 1 степени свободы
    if (blockCount.size() > 1) {
        criticalValue = 24.996; // Для 2 степеней свободы
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

    writeToFile(randomBytes, filename);



}

void generateRandomKeys(SHA256RandomGenerator& rng, size_t numKeys) {
    size_t keySize = 32; // Assuming each key is 32 bytes
    auto start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < numKeys; ++i) {
        std::vector<unsigned char> key = rng.generateRandomBytes(keySize);
    }
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> generationTime = end - start;
    std::cout << "Generation time for " << numKeys << " keys: " << generationTime.count() << " seconds" << std::endl;
}

int main() {
    try {
        SHA256RandomGenerator rng;

        // Генерируем 1000 случайных байт
        std::vector<unsigned char> randomBytes = rng.generateRandomBytes(1000);

        // Записываем случайные байты в файл
        writeToFile(randomBytes, "output");

        // Читаем случайные байты из файла
        std::vector<unsigned char> readBytes = readFromFile("output");

        // Запускаем побитовый тест
        runBitwiseTest(readBytes);

        // Запускаем поблочный тест с размером блока 4 бита
        runBlockTest(readBytes, 4);

        generateAndTestFile(1, "output_1MB");
        generateAndTestFile(100, "output_100MB");
        generateAndTestFile(1000, "output_1000MB");

    } catch (const std::exception &ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}

