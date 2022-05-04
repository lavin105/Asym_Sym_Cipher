#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <vector>
#include <cstring>
#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <bits/stdc++.h>
#include <stdlib.h>
#include <time.h>

std::vector<uint32_t> readPlaintextTo31BitMessageVector(std::string filePath);
void writeToPublicKeyFile(std::string pubKeyFilePath, std::vector<uint32_t> outputKeyPair);
void writeToPrivateKeyFile(std::string privKeyFilePath, std::vector<uint32_t> outputKeyPair);
std::vector<uint32_t> generateKeys(uint32_t g);
uint64_t modularExponentiation(uint64_t a, uint64_t b, uint64_t n);
std::string chosenWhitness(uint64_t n, uint64_t a);
std::string randomWhitnesses(uint64_t n, uint64_t s);
std::vector<std::vector<uint32_t>> encryptMessage(std::string keyFilePath, std::vector<uint32_t> messageVector);
void writeCiphertextToFile(std::string outputFile, std::vector<std::vector<uint32_t>> encryptedVector);
std::vector<std::vector<uint32_t>> readCiphertextFromFile(std::string inFile);
std::string decryptMessage(std::vector<std::vector<uint32_t>> encryptedVector, std::string keyFilePath);
std::string hexToAscii(std::string hex);
void writeDecryptedMessageToFile(std::string outFile, std::string asciiString);

int main(int argc, char *argv[])
{
    std::string keyFile;
    std::string inFile;
    std::string outFile;
    std::vector<uint32_t> outputKeyVector;
    std::vector<uint32_t> inputMessageVector;
    std::vector<std::vector<uint32_t>> encryptMessageVector;
    std::vector<std::vector<uint32_t>> encryptedMessageVectorFromCiphertextFile;
    std::string asciiStringToOutput;

    if (argc < 2)
    {
        std::cout << "Missing Required Arguments!\n";
        std::cout << "Usage for key generation: ./wsu-pub-crypt -genkey\n";
        std::cout << "Usage for encryption: ./wsu-pub-crypt -e -k pubkey.txt -in ptext.txt -out ctext.txt\n";
        std::cout << "Usage for decryption: ./wsu-pub-crypt -d -k prikey.txt -in ctext.txt -out dtext.txt\n";
        return (EXIT_FAILURE);
    }
    if ((std::string)argv[1] == "-genkey")
    {
        if (argc > 2)
        {
            std::cout << "Too Many Arguments!\n";
            std::cout << "Usage for key generation: ./wsu-pub-crypt -genkey\n";
            return (EXIT_FAILURE);
        }
        std::cout << "Generating your public and private keys...\n";
        outputKeyVector = generateKeys(2);
        writeToPublicKeyFile("pubkey.txt", outputKeyVector);
        writeToPrivateKeyFile("prikey.txt", outputKeyVector);
    }
    else if ((std::string)argv[1] == "-e")
    {
        if (argc < 8)
        {
            std::cout << "Missing Required Arguments!\n";
            std::cout << "Usage for encryption: ./wsu-pub-crypt -e -k pubkey.txt -in ptext.txt -out ctext.txt\n";
            return (EXIT_FAILURE);
        }
        if (argc > 8)
        {
            std::cout << "Too Many Arguments!\n";
            std::cout << "Usage for encryption: ./wsu-pub-crypt -e -k pubkey.txt -in ptext.txt -out ctext.txt\n";
            return (EXIT_FAILURE);
        }
        if ((std::string)argv[2] == "-k")
        {
            keyFile = (std::string)argv[3];
        }
        else
        {
            std::cout << "Third argument must be -k !\n";
            return (EXIT_FAILURE);
        }
        if ((std::string)argv[4] == "-in")
        {
            inFile = (std::string)argv[5];
        }
        else
        {
            std::cout << "Fifth argument must be -in !\n";
            return (EXIT_FAILURE);
        }
        if ((std::string)argv[6] == "-out")
        {
            outFile = (std::string)argv[7];
        }
        else
        {
            std::cout << "Seventh argument must be -out !\n";
            return (EXIT_FAILURE);
        }

        std::cout << "Encryption message from " << inFile << "...\n";
        inputMessageVector = readPlaintextTo31BitMessageVector(inFile);
        encryptMessageVector = encryptMessage(keyFile, inputMessageVector);
        writeCiphertextToFile(outFile, encryptMessageVector);
    }
    else if ((std::string)argv[1] == "-d")
    {
        if (argc < 8)
        {
            std::cout << "Missing Required Arguments!\n";
            std::cout << "Usage for decryption: ./wsu-pub-crypt -d -k prikey.txt -in ctext.txt -out dtext.txt\n";
            return (EXIT_FAILURE);
        }
        if (argc > 8)
        {
            std::cout << "Too Many Arguments!\n";
            std::cout << "Usage for decryption: ./wsu-pub-crypt -d -k prikey.txt -in ctext.txt -out dtext.txt\n";
            return (EXIT_FAILURE);
        }
        if ((std::string)argv[2] == "-k")
        {
            keyFile = (std::string)argv[3];
        }
        else
        {
            std::cout << "Third argument must be -k !\n";
            return (EXIT_FAILURE);
        }
        if ((std::string)argv[4] == "-in")
        {
            inFile = (std::string)argv[5];
        }
        else
        {
            std::cout << "Fifth argument must be -in !\n";
            return (EXIT_FAILURE);
        }
        if ((std::string)argv[6] == "-out")
        {
            outFile = (std::string)argv[7];
        }
        else
        {
            std::cout << "Seventh argument must be -out !\n";
            return (EXIT_FAILURE);
        }

        std::cout << "Decrypting message from " << inFile << "...\n";
        encryptedMessageVectorFromCiphertextFile = readCiphertextFromFile(inFile);
        asciiStringToOutput = decryptMessage(encryptedMessageVectorFromCiphertextFile, keyFile);
        writeDecryptedMessageToFile(outFile, asciiStringToOutput);
    }
    else
    {
        std::cout << "Critical Error: this block should never be reached.\n";
        return (EXIT_FAILURE);
    }

    return 0;
}
void writeDecryptedMessageToFile(std::string outFile, std::string asciiString)
{
    std::cout << "Writing Decrypted Message to " << outFile << "\n";
    std::ofstream out(outFile);
    out << asciiString;
    out.close();
}

std::string decryptMessage(std::vector<std::vector<uint32_t>> encryptedVector, std::string keyFilePath)
{
    std::vector<uint32_t> privateKeysVector;
    std::vector<uint32_t> messageVectorInteger;
    std::string hexMessage;
    std::ifstream f;
    f.open(keyFilePath);
    if (f.fail())
    {
        std::cout << keyFilePath << " does not exist specify the correct private key file.\n";
        exit(EXIT_FAILURE);
    }
    std::string private_key_str((std::istreambuf_iterator<char>(f)),
                                (std::istreambuf_iterator<char>()));
    f.close();

    //std::cout << private_key_str << "\n";

    std::istringstream ss(private_key_str);
    std::string num;
    while (ss >> num)
    {
        char *e;
        privateKeysVector.push_back(std::strtoul(num.c_str(), &e, 10));
    }
    uint32_t p = privateKeysVector[0];
    uint32_t g = privateKeysVector[1];
    uint32_t d = privateKeysVector[2];

    for (int i = 0; i < encryptedVector.size(); i++)
    {
        uint32_t C1;
        uint32_t C2;
        uint32_t m;
        for (int j = 0; j < encryptedVector[i].size(); j++)
        {
            if (j == 0)
            {
                //std::cout << "j: " << j << std::endl;
                C1 = (uint32_t)modularExponentiation((uint64_t)encryptedVector[i][j], (uint64_t)(p - 1 - d), (uint64_t)p);
            }
            else
            {
                //std::cout << "j: " << j << std::endl;

                C2 = (uint32_t)modularExponentiation((uint64_t)encryptedVector[i][j], (uint64_t)(1), (uint64_t)p);
            }
        }

        m = (uint32_t)modularExponentiation((uint64_t)C1 * C2, (uint64_t)(1), (uint64_t)p);
        messageVectorInteger.push_back(m);
    }
    std::stringstream sstream;
    for (int i = 0; i < messageVectorInteger.size(); i++)
    {

        sstream << std::hex << std::setw(8) << std::setfill('0') << messageVectorInteger[i];
        hexMessage = sstream.str();
    }
    std::string asciiString = hexToAscii(hexMessage);

    return asciiString;
}
// Method that convers hex to ascii
std::string hexToAscii(std::string hex)
{
    std::string ascii = "";
    for (int i = 0; i < hex.length(); i += 2)
    {
        std::string two_chars = hex.substr(i, 2);
        if (two_chars == "00")
        {
            continue;
        }
        else
        {
            char ch = stoul(two_chars, nullptr, 16);
            //std::cout << two_chars << ": " << ch << "\n";
            ascii += ch;
        }
    }
    return ascii;
}

std::vector<std::vector<uint32_t>> readCiphertextFromFile(std::string inFile)
{
    std::vector<std::vector<uint32_t>> encryptMessageVectorFromFile;
    std::vector<uint32_t> pairVector;
    std::ifstream f;
    f.open(inFile);
    if (f.fail())
    {
        std::cout << inFile << " does not exist specify the correct ciphertext file.\n";
        exit(EXIT_FAILURE);
    }
    std::string input_str((std::istreambuf_iterator<char>(f)),
                          (std::istreambuf_iterator<char>()));
    f.close();

    //std::cout << input_str << "\n";
    std::istringstream ss(input_str);
    std::string num;
    while (ss >> num)
    {
        char *e;
        pairVector.push_back(std::strtoul(num.c_str(), &e, 10));
        if (pairVector.size() == 2)
        {
            encryptMessageVectorFromFile.push_back(pairVector);
            pairVector.clear();
        }
    }

    return encryptMessageVectorFromFile;
}

void writeCiphertextToFile(std::string outputFile, std::vector<std::vector<uint32_t>> encryptedVector)
{

    std::cout << "Writing encrypted message to " << outputFile << "\n";
    std::ofstream out(outputFile);

    for (int i = 0; i < encryptedVector.size(); i++)
    {

        for (int j = 0; j < encryptedVector[i].size(); j++)
        {
            out << encryptedVector[i][j] << " ";
        }
        if (i != encryptedVector.size() - 1)
        {
            out << "\n";
        }
    }
    out.close();
}

std::vector<std::vector<uint32_t>> encryptMessage(std::string keyFilePath, std::vector<uint32_t> messageVector)
{
    std::vector<std::vector<uint32_t>> encryptedMessageVector;
    std::vector<uint32_t> publicKeysVector;
    std::vector<uint32_t> kVector;
    std::vector<uint32_t> C1C2Vector;
    std::ifstream f;
    f.open(keyFilePath);
    if (f.fail())
    {
        std::cout << keyFilePath << " does not exist specify the correct plaintext file.\n";
        exit(EXIT_FAILURE);
    }
    std::string input_str((std::istreambuf_iterator<char>(f)),
                          (std::istreambuf_iterator<char>()));
    f.close();

    //std::cout << input_str << "\n";
    std::istringstream ss(input_str);
    std::string num;
    while (ss >> num)
    {
        char *e;
        publicKeysVector.push_back(std::strtoul(num.c_str(), &e, 10));
    }
    uint32_t p = publicKeysVector[0];
    uint32_t g = publicKeysVector[1];
    uint32_t e2 = publicKeysVector[2];

    //std::cout << p << "\n";
    //std::cout << g << "\n";
    //std::cout << e2 << "\n";
    std::srand((unsigned)std::time(NULL));
    for (int i = 0; i < messageVector.size(); i++)
    {
        uint32_t randomK = rand() % p;
        //std::cout << "random k: " << randomK << "\n";
        kVector.push_back(randomK);
    }

    for (int i = 0; i < messageVector.size(); i++)
    {
        uint32_t C1 = (uint32_t)modularExponentiation((uint64_t)g, (uint64_t)kVector[i], (uint64_t)p);
        uint32_t aModP = (uint32_t)modularExponentiation((uint64_t)e2, (uint64_t)kVector[i], (uint64_t)p);
        uint32_t bModP = (uint32_t)modularExponentiation((uint64_t)messageVector[i], (uint64_t)1, (uint64_t)p);
        uint32_t C2 = (uint32_t)modularExponentiation((uint64_t)aModP * bModP, (uint64_t)1, (uint64_t)p);

        //std::cout << "C1: " << C1 << "\n";
        //std::cout << "C2: " << C2 << "\n";

        C1C2Vector.push_back(C1);
        C1C2Vector.push_back(C2);
        encryptedMessageVector.push_back(C1C2Vector);
        C1C2Vector.clear();
    }

    return encryptedMessageVector;
}

std::vector<uint32_t> generateKeys(uint32_t g)
{
    std::vector<uint32_t> keyVector;
    std::srand((unsigned)std::time(NULL));
    bool foundQ = false;
    bool foundP = false;
    uint32_t randomQ;
    uint32_t p;
    uint64_t overflow;

    while (foundP == false)
    {
        while (foundQ == false)
        {
            randomQ = rand() % 0x7FFFFFFF + 0x40000000;
            overflow = (uint64_t)2 * randomQ + 1;
            if (randomQ % 12 == 5 && overflow < 4294967295 && randomWhitnesses((uint64_t)randomQ, 5) == "Almost Surley Prime")
            {
                foundQ = true;
            }
            else
            {
                foundQ = false;
            }
        }
        p = (2 * randomQ) + 1;
        if (randomWhitnesses((uint64_t)p, 5) == "Almost Surley Prime" && (p >> 31) & 1 == 1)
        {
            foundP = true;
            foundQ = true;
        }
        else
        {
            foundQ = false;
            foundP = false;
        }
    }

    uint32_t d = rand() % ((p - 1) - 1 + 1) + 1;
    while (d < 1 || d > p)
    {
        d = rand() % ((p - 1) - 1 + 1) + 1;
    }
    uint64_t e2;
    e2 = modularExponentiation((uint64_t)g, (uint64_t)d, (uint64_t)p);
    keyVector.push_back((uint32_t)p);
    keyVector.push_back((uint32_t)g);
    keyVector.push_back((uint32_t)e2);
    keyVector.push_back((uint32_t)d);

    return keyVector;
}

std::vector<uint32_t> readPlaintextTo31BitMessageVector(std::string filePath)
{
    std::vector<uint32_t> integerPlaintextMessageVector31Bits;
    std::vector<std::string> stringPlaintextMessageVector8CharsHex;
    std::ifstream f;
    f.open(filePath);
    if (f.fail())
    {
        std::cout << filePath << " does not exist specify the correct plaintext file.\n";
        exit(EXIT_FAILURE);
    }
    std::string fileString((std::istreambuf_iterator<char>(f)),
                           (std::istreambuf_iterator<char>()));
    f.close();

    std::stringstream ss;
    for (const auto &item : fileString)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << int(item);
    }
    std::string hex_string = ss.str();
    std::string builder = "";
    for (int i = 0; i < hex_string.length(); i++)
    {
        builder = builder + hex_string[i];
        if (builder.length() == 8)
        {
            stringPlaintextMessageVector8CharsHex.push_back(builder);
            builder.clear();
        }
        else if (i == hex_string.length() - 1)
        {
            stringPlaintextMessageVector8CharsHex.push_back(builder);
            builder.clear();
        }
        else
        {
        }
    }

    for (int i = 0; i < stringPlaintextMessageVector8CharsHex.size(); i++)
    {
        // Convert each vector entry to hex
        uint32_t input_hex;
        std::stringstream toHexInt;
        toHexInt << std::hex << stringPlaintextMessageVector8CharsHex[i];
        toHexInt >> input_hex;
        integerPlaintextMessageVector31Bits.push_back(input_hex);
    }

    return integerPlaintextMessageVector31Bits;
}

void writeToPublicKeyFile(std::string pubKeyFilePath, std::vector<uint32_t> outputKeyPair)
{
    uint32_t p = outputKeyPair[0];
    uint32_t g = outputKeyPair[1];
    uint32_t e2 = outputKeyPair[2];
    std::cout << "Writing public key information p: " << p << " g: " << g << " e2: " << e2 << " to " << pubKeyFilePath << "\n";
    std::ofstream out(pubKeyFilePath);
    out << p << " " << g << " " << e2;
    out.close();
}
void writeToPrivateKeyFile(std::string privKeyFilePath, std::vector<uint32_t> outputKeyPair)
{
    uint32_t p = outputKeyPair[0];
    uint32_t g = outputKeyPair[1];
    uint32_t d = outputKeyPair[3];
    std::cout << "Writing private key information p: " << p << " g: " << g << " d: " << d << " to " << privKeyFilePath << "\n";
    std::ofstream out(privKeyFilePath);
    out << p << " " << g << " " << d;
    out.close();
}
std::string chosenWhitness(uint64_t n, uint64_t a)
{
    if (n <= 1)
    {
        return "Composite";
    }
    if (n % 2 == 0 && n != 2)
    {
        return "Composite";
    }
    if (n == 2 || n == 3)
    {
        return "Maybe Prime";
    }
    if (a <= 1 || a >= n - 1)
    {
        std::cout << "-a must be between 1 and " << n - 1 << " your a value is " << a << ".\n";
        exit(EXIT_FAILURE);
    }

    uint64_t n_minus_1 = n - 1;
    uint64_t x;
    uint64_t k_test;
    uint64_t q;
    uint64_t k;

    for (k_test = 1; pow(2, k_test) <= n_minus_1; k_test++)
    {
        x = n_minus_1 / pow(2, k_test);
        if (roundf(x) == x)
        {
            if ((uint64_t)x % 2 == 1)
            {
                q = (uint64_t)x;
                k = k_test;
                break;
            }
        }
    }

    uint64_t val = modularExponentiation(a, q, n);
    if (val == 1)
    {
        return "Maybe Prime";
    }
    for (int j = 0; j <= k - 1; j++)
    {
        int new_b = pow(2, j) * q;

        uint64_t val2 = modularExponentiation(a, new_b, n);
        if (val2 == n_minus_1)
        {
            return "Maybe Prime";
        }
    }
    return "Composite";
}

uint64_t modularExponentiation(uint64_t a, uint64_t b, uint64_t n)
{
    uint64_t c = 0;
    uint64_t d = 1;
    for (int i = 63; i >= 0; i--)
    {
        c = 2 * c;
        d = (d * d) % n;
        if (((b >> i) & 1) == 1)
        {
            c = c + 1;
            d = (d * a) % n;
        }
    }
    return d;
}
std::string randomWhitnesses(uint64_t n, uint64_t s)
{
    if (s <= 0)
    {
        std::cout << "-s must be greater than 0.\n";
        exit(EXIT_FAILURE);
    }
    if (n <= 1)
    {
        return "Composite";
    }
    if (n % 2 == 0 && n != 2)
    {
        return "Composite";
    }
    uint64_t a;
    for (int j = 1; j <= s; j++)
    {
        if (n == 2 || n == 3)
        {
            continue;
        }
        // Generate random whitnesses that are > 1 and < (n-1)
        a = rand() % ((n - 2) - 2 + 1) + 2;
        if (chosenWhitness(n, a) == "Composite")
        {
            return "Composite";
        }
    }
    return "Almost Surley Prime";
}