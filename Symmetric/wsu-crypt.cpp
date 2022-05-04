//wsu-crypt.cpp
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
using namespace std;

//Constants
const int FTABLE[16][16] =
    {0xa3, 0xd7, 0x09, 0x83, 0xf8, 0x48, 0xf6, 0xf4, 0xb3, 0x21, 0x15, 0x78, 0x99, 0xb1, 0xaf, 0xf9,
     0xe7, 0x2d, 0x4d, 0x8a, 0xce, 0x4c, 0xca, 0x2e, 0x52, 0x95, 0xd9, 0x1e, 0x4e, 0x38, 0x44, 0x28,
     0x0a, 0xdf, 0x02, 0xa0, 0x17, 0xf1, 0x60, 0x68, 0x12, 0xb7, 0x7a, 0xc3, 0xe9, 0xfa, 0x3d, 0x53,
     0x96, 0x84, 0x6b, 0xba, 0xf2, 0x63, 0x9a, 0x19, 0x7c, 0xae, 0xe5, 0xf5, 0xf7, 0x16, 0x6a, 0xa2,
     0x39, 0xb6, 0x7b, 0x0f, 0xc1, 0x93, 0x81, 0x1b, 0xee, 0xb4, 0x1a, 0xea, 0xd0, 0x91, 0x2f, 0xb8,
     0x55, 0xb9, 0xda, 0x85, 0x3f, 0x41, 0xbf, 0xe0, 0x5a, 0x58, 0x80, 0x5f, 0x66, 0x0b, 0xd8, 0x90,
     0x35, 0xd5, 0xc0, 0xa7, 0x33, 0x06, 0x65, 0x69, 0x45, 0x00, 0x94, 0x56, 0x6d, 0x98, 0x9b, 0x76,
     0x97, 0xfc, 0xb2, 0xc2, 0xb0, 0xfe, 0xdb, 0x20, 0xe1, 0xeb, 0xd6, 0xe4, 0xdd, 0x47, 0x4a, 0x1d,
     0x42, 0xed, 0x9e, 0x6e, 0x49, 0x3c, 0xcd, 0x43, 0x27, 0xd2, 0x07, 0xd4, 0xde, 0xc7, 0x67, 0x18,
     0x89, 0xcb, 0x30, 0x1f, 0x8d, 0xc6, 0x8f, 0xaa, 0xc8, 0x74, 0xdc, 0xc9, 0x5d, 0x5c, 0x31, 0xa4,
     0x70, 0x88, 0x61, 0x2c, 0x9f, 0x0d, 0x2b, 0x87, 0x50, 0x82, 0x54, 0x64, 0x26, 0x7d, 0x03, 0x40,
     0x34, 0x4b, 0x1c, 0x73, 0xd1, 0xc4, 0xfd, 0x3b, 0xcc, 0xfb, 0x7f, 0xab, 0xe6, 0x3e, 0x5b, 0xa5,
     0xad, 0x04, 0x23, 0x9c, 0x14, 0x51, 0x22, 0xf0, 0x29, 0x79, 0x71, 0x7e, 0xff, 0x8c, 0x0e, 0xe2,
     0x0c, 0xef, 0xbc, 0x72, 0x75, 0x6f, 0x37, 0xa1, 0xec, 0xd3, 0x8e, 0x62, 0x8b, 0x86, 0x10, 0xe8,
     0x08, 0x77, 0x11, 0xbe, 0x92, 0x4f, 0x24, 0xc5, 0x32, 0x36, 0x9d, 0xcf, 0xf3, 0xa6, 0xbb, 0xac,
     0x5e, 0x6c, 0xa9, 0x13, 0x57, 0x25, 0xb5, 0xe3, 0xbd, 0xa8, 0x3a, 0x01, 0x05, 0x59, 0x2a, 0x46};
const long _2TOTHE16 = pow(2, 16);
//End Constants

// Method Declaration
vector<vector<int>> key_gen_for_encryption(uint64_t hex_key);
vector<vector<int>> key_gen_for_decryption(vector<vector<int>> encrypted_key);
uint64_t hex_from_keyFile(string key_file_path);
vector<uint16_t> whitening_key_create(uint64_t key);
vector<vector<uint16_t>> hex_from_plaintextFile(string input_file_path);
vector<vector<uint16_t>> whiten_input_output_vector(vector<vector<uint16_t>> initial, vector<uint16_t> white_key);
uint16_t G(uint16_t r, uint8_t k0, uint8_t k1, uint8_t k2, uint8_t k3);
vector<uint16_t> F_encrypt(vector<uint16_t> vector_to_encrypt, vector<int> rounds_keys);
vector<vector<uint16_t>> perform_encryption(vector<vector<uint16_t>> in_vector, vector<vector<int>> key_vector);
uint8_t Ftable_compute(uint8_t in);
string convert_hex_vector_to_hex_string(vector<vector<uint16_t>> vector_to_convert);
void write_ciphertext_to_file(string text, string file);
vector<vector<uint16_t>> hex_from_ciphertext_file(string file_path);
vector<uint16_t> F_decrypt(vector<uint16_t> vector_to_decrypt, vector<int> rounds_keys);
vector<vector<uint16_t>> perform_decryption(vector<vector<uint16_t>> in_vector, vector<vector<int>> key_vector);
string hex_to_ascii(string hex);
void write_decrypted_text_to_file(string text, string file);
// End Method Declarations

int main(int argc, char *argv[])
{
  // Variable Declarations
  vector<vector<uint16_t>> initial_vector;
  vector<vector<uint16_t>> whitened_vector;
  vector<uint16_t> separated_key_for_whitening;
  vector<vector<int>> encryption_round_key_vector;
  vector<vector<int>> decryption_round_key_vector;
  vector<vector<uint16_t>> encrypted_vector;
  vector<vector<uint16_t>> decrypted_vector;
  vector<vector<uint16_t>> final_whitened_encrypted_output_vector;
  vector<vector<uint16_t>> final_whitened_decrypted_output_vector;
  string encrypted_hex_to_output;
  string decrypted_hex_to_output;
  vector<vector<uint16_t>> ciphertext_vector;
  string decrypted_plaintext;
  string mode;
  string key_file;
  string in_file;
  string out_file;
  // End Variable Declarations

  // Check to make sure all command line arguments are  and assign them to variables
  if (argc < 8)
  {
    cout << "Missing required arguments." << endl;
    cout << "Usage for encryption: ./wsu-crypt -e -k key.txt -in plaintext.txt -out ciphertext.txt" << endl;
    cout << "Usage for decryption: ./wsu-crypt -d -k key.txt -in ciphertext.txt -out decrypted.txt" << endl;
    return 1;
  }
  if (argc > 8)
  {
    cout << "Too many arguments provided." << endl;
    cout << "Usage for encryption: ./wsu-crypt -e -k key.txt -in plaintext.txt -out ciphertext.txt" << endl;
    cout << "Usage for decryption: ./wsu-crypt -d -k key.txt -in ciphertext.txt -out decrypted.txt" << endl;
    return 1;
  }
  if (argv[1] != NULL)
  {
    mode = argv[1];
  }

  if (argv[3] != NULL && (string)argv[2] == "-k")
  {
    key_file = argv[3];
  }
  else
  {
    cout << "Must have -k followed by the key file.\n";
    return 1;
  }

  if (argv[5] != NULL && (string)argv[4] == "-in")
  {
    in_file = argv[5];
  }
  else
  {
    cout << "Must have -in followed by the input file.\n";
    return 1;
  }
  if (argv[7] != NULL && (string)argv[6] == "-out")
  {
    out_file = argv[7];
  }
  else
  {
    cout << "Must have -out followed by the output file.\n";
    return 1;
  }
  // Check the mode and perform encryption(-e) or decryption(-d)
  if (mode == "-e")
  {
    cout << "Encrypting" << endl;
    // Read the hex from plaintext input file
    initial_vector = hex_from_plaintextFile(in_file);
    // Create a separated key used for whitening from the provided key file
    separated_key_for_whitening = whitening_key_create(hex_from_keyFile(key_file));
    // Whiten the input vector using the separated whitening key
    whitened_vector = whiten_input_output_vector(initial_vector, separated_key_for_whitening);
    // Generate the round keys
    encryption_round_key_vector = key_gen_for_encryption(hex_from_keyFile(key_file));
    // Perform the core encryption which calls F and G functions
    encrypted_vector = perform_encryption(whitened_vector, encryption_round_key_vector);
    // Whiten the encrypted vector again
    final_whitened_encrypted_output_vector = whiten_input_output_vector(encrypted_vector, separated_key_for_whitening);
    // Convert the hex int values to hex string equivalent
    encrypted_hex_to_output = convert_hex_vector_to_hex_string(final_whitened_encrypted_output_vector);
    // Write the encrypted hex string to the output file
    write_ciphertext_to_file(encrypted_hex_to_output, out_file);
    cout << "Encryption Finished" << endl;
    return 0;
  }
  else if (mode == "-d")
  {
    cout << "Decrypting" << endl;
    // Generate encryption round keys
    encryption_round_key_vector = key_gen_for_encryption(hex_from_keyFile(key_file));
    // Use the encryption keys and reverse to create the decryption round keys
    decryption_round_key_vector = key_gen_for_decryption(encryption_round_key_vector);
    // Read the hex string from the ciphertext file
    ciphertext_vector = hex_from_ciphertext_file(in_file);
    // Create separated whitening key from the key file
    separated_key_for_whitening = whitening_key_create(hex_from_keyFile(key_file));
    // Whiten the input ciphertext vector
    whitened_vector = whiten_input_output_vector(ciphertext_vector, separated_key_for_whitening);
    // Perform the core decryption which calls the F and G functions
    decrypted_vector = perform_decryption(whitened_vector, decryption_round_key_vector);
    // Whiten the decrypted vector
    final_whitened_decrypted_output_vector = whiten_input_output_vector(decrypted_vector, separated_key_for_whitening);
    // Convert the hex int vector to hex string
    decrypted_hex_to_output = convert_hex_vector_to_hex_string(final_whitened_decrypted_output_vector);
    // Convert the hex string to ascii characters
    decrypted_plaintext = hex_to_ascii(decrypted_hex_to_output);
    // Write decrypted ascii values to the output file
    write_decrypted_text_to_file(decrypted_plaintext, out_file);
    cout << "Decryption Finished" << endl;
    return 0;
  }
  else
  {
    cout << "Invalid Mode." << endl;
    cout << "Mode must be -e or -d" << endl;
    return 1;
  }
}

// Method that writes decrypted text to a file
void write_decrypted_text_to_file(string text, string file)
{
  cout << "Writing Decrypted Plaintex to " << file << endl;
  ofstream out(file);
  out << text;
  out.close();
}

// Method that convers hex to ascii
string hex_to_ascii(string hex)
{
  string ascii = "";
  for (int i = 0; i < hex.length(); i += 2)
  {
    string two_chars = hex.substr(i, 2);
    char ch = stoul(two_chars, nullptr, 16);
    ascii += ch;
  }
  return ascii;
}

// Method that performs 16 decryption rounds calling F_decrypt and G methods
vector<vector<uint16_t>> perform_decryption(vector<vector<uint16_t>> in_vector, vector<vector<int>> key_vector)
{
  vector<vector<uint16_t>> final_vector;
  vector<uint16_t> round_result;

  for (int i = 0; i < in_vector.size(); i++)
  {
    round_result = F_decrypt(in_vector[i], key_vector[0]);
    for (int i = 1; i < 16; i++)
    {
      round_result = F_decrypt(round_result, key_vector[i]);
    }

    vector<uint16_t> final_flipped = {round_result[2], round_result[3], round_result[0], round_result[1]};
    final_vector.push_back(final_flipped);
  }
  return final_vector;
}

// The F function for decryption
vector<uint16_t> F_decrypt(vector<uint16_t> vector_to_decrypt, vector<int> rounds_keys)
{
  vector<uint16_t> round_result;
  uint16_t new_r0, new_r1, new_r2, new_r3;
  new_r2 = vector_to_decrypt[0]; // Takes the value of old r0
  new_r3 = vector_to_decrypt[1]; // Takes the value of old r1
  uint16_t combined_k8k9;
  uint16_t combined_k10k11;
  combined_k8k9 = rounds_keys[8] << 8 | rounds_keys[9];
  combined_k10k11 = rounds_keys[10] << 8 | rounds_keys[11];
  uint16_t T0 = G(vector_to_decrypt[0], rounds_keys[0], rounds_keys[1], rounds_keys[2], rounds_keys[3]);
  uint16_t T1 = G(vector_to_decrypt[1], rounds_keys[4], rounds_keys[5], rounds_keys[6], rounds_keys[7]);
  uint16_t F0 = (T0 + (2 * T1) + combined_k8k9) % _2TOTHE16;
  uint16_t F1 = ((2 * T0) + T1 + combined_k10k11) % _2TOTHE16;
  uint16_t r2_left_rotate;
  r2_left_rotate = ((vector_to_decrypt[2] << 1) | (vector_to_decrypt[2] >> 15));
  uint16_t r2 = F0 ^ r2_left_rotate;
  new_r0 = r2;
  uint16_t r3;
  r3 = F1 ^ vector_to_decrypt[3];
  uint16_t r3_right_rotate;
  r3_right_rotate = ((r3 >> 1) | (r3 << 15));
  new_r1 = r3_right_rotate;
  round_result.push_back(new_r0);
  round_result.push_back(new_r1);
  round_result.push_back(new_r2);
  round_result.push_back(new_r3);
  return round_result;
}

// Method that reads the hex from the ciphertext input file
vector<vector<uint16_t>> hex_from_ciphertext_file(string file_path)
{
  vector<vector<uint16_t>> result;
  vector<vector<string>> text_vector;
  vector<string> text;
  string line;
  ifstream f;
  f.open(file_path);
  if (f.fail())
  {
    cout << file_path << " does not exist specify the correct ciphertext file." << endl;
    exit(EXIT_FAILURE);
  }
  f.close();
  ifstream ifs(file_path);
  string key_str((std::istreambuf_iterator<char>(ifs)),
                 (std::istreambuf_iterator<char>()));
  if (key_str.length() == 0)
  {
    cout << "No ciphertext in ciphertext file please make sure you have ran the encryption." << endl;
    exit(EXIT_FAILURE);
  }
  string builder = "";
  for (int i = 0; i < key_str.length(); i++)
  {
    builder = builder + key_str[i];
    if (builder.length() == 4)
    {
      text.push_back(builder);
      builder.clear();
    }
    if (text.size() == 4)
    {
      text_vector.push_back(text);
      text.clear();
    }
  }

  uint16_t temp;
  vector<uint16_t> hex_vector;
  for (int i = 0; i < text_vector.size(); i++)
  {
    for (int j = 0; j < text_vector[i].size(); j++)
    {
      stringstream toHexInt;
      toHexInt << hex << text_vector[i][j];
      toHexInt >> temp;
      hex_vector.push_back(temp);
    }
    result.push_back(hex_vector);
    hex_vector.clear();
  }

  return result;
}

// Method that reverses the encryption round keys to creat the decryption round keys
vector<vector<int>> key_gen_for_decryption(vector<vector<int>> encrypted_keys)
{

  vector<vector<int>> decryption_keys = {encrypted_keys[15], encrypted_keys[14],
                                         encrypted_keys[13], encrypted_keys[12], encrypted_keys[11], encrypted_keys[10],
                                         encrypted_keys[9], encrypted_keys[8], encrypted_keys[7], encrypted_keys[6],
                                         encrypted_keys[5], encrypted_keys[4], encrypted_keys[3],
                                         encrypted_keys[2], encrypted_keys[1], encrypted_keys[0]};

  return decryption_keys;
}

// Method that writes the hex string to the output file
void write_ciphertext_to_file(string text, string file)
{
  cout << "Writing Ciphertext to " << file << endl;
  ofstream out(file);
  out << text;
  out.close();
}

// Method to convert the 16 bit integer values back to a hex string to output
string convert_hex_vector_to_hex_string(vector<vector<uint16_t>> vector_to_convert)
{
  vector<uint16_t> combined;
  vector<string> hex_string_vector;
  string hex_string = "";
  vector<string> leading_0s_hex_string_vector;
  for (int i = 0; i < vector_to_convert.size(); i++)
  {
    for (int j = 0; j < vector_to_convert[i].size(); j++)
    {
      combined.push_back(vector_to_convert[i][j]);
    }
  }

  for (int i = 0; i < combined.size(); i++)
  {
    stringstream sstream;
    sstream << std::hex << combined[i];
    string result = sstream.str();
    hex_string_vector.push_back(result);
  }
  for (int i = 0; i < hex_string_vector.size(); i++)
  {
    if (hex_string_vector[i].length() == 1)
    {
      hex_string_vector[i].insert(0, "000");
    }
    else if (hex_string_vector[i].length() == 2)
    {
      hex_string_vector[i].insert(0, "00");
    }
    else if (hex_string_vector[i].length() == 3)
    {
      hex_string_vector[i].insert(0, "0");
    }
    else
    {
      // Do nothing
    }
  }
  for (int i = 0; i < hex_string_vector.size(); i++)
  {
    hex_string += hex_string_vector[i];
  }
  if (hex_string.substr(hex_string.length() - 14, 14) == "00000000000007")
  {
    hex_string.erase(hex_string.length() - 14, 14);
  }
  else if (hex_string.substr(hex_string.length() - 12, 12) == "000000000006")
  {
    hex_string.erase(hex_string.length() - 12, 12);
  }
  else if (hex_string.substr(hex_string.length() - 10, 10) == "0000000005")
  {
    hex_string.erase(hex_string.length() - 10, 10);
  }
  else if (hex_string.substr(hex_string.length() - 8, 8) == "00000004")
  {
    hex_string.erase(hex_string.length() - 8, 8);
  }
  else if (hex_string.substr(hex_string.length() - 6, 6) == "000003")
  {
    hex_string.erase(hex_string.length() - 6, 6);
  }
  else if (hex_string.substr(hex_string.length() - 4, 4) == "0002")
  {
    hex_string.erase(hex_string.length() - 4, 4);
  }
  else if (hex_string.substr(hex_string.length() - 2, 2) == "01")
  {
    hex_string.erase(hex_string.length() - 2, 2);
  }
  else
  {
    // Do nothing
  }
  return hex_string;
}

// Method to get the desired value from the ftable
uint8_t Ftable_compute(uint8_t in)
{
  int high_4bits;
  int low_4bits;
  int table_results;
  high_4bits = (in >> 4) & 0xF;
  low_4bits = in & 0xF;
  table_results = FTABLE[high_4bits][low_4bits];
  return table_results;
}

// The G function
uint16_t G(uint16_t r, uint8_t k0, uint8_t k1, uint8_t k2, uint8_t k3)
{
  uint8_t g1; //High 8 bits
  uint8_t g2; //Low 8 bits
  uint8_t g3, g4, g5, g6;
  uint16_t combined;
  g1 = (r >> 8) & 0xFF;
  g2 = r & 0xFF;
  g3 = Ftable_compute(g2 ^ k0) ^ g1;
  g4 = Ftable_compute(g3 ^ k1) ^ g2;
  g5 = Ftable_compute(g4 ^ k2) ^ g3;
  g6 = Ftable_compute(g5 ^ k3) ^ g4;
  combined = g5 << 8 | g6;
  return combined;
}

// The F function for encryption
vector<uint16_t> F_encrypt(vector<uint16_t> vector_to_encrypt, vector<int> rounds_keys)
{
  vector<uint16_t> round_result;
  uint16_t new_r0, new_r1, new_r2, new_r3;
  new_r2 = vector_to_encrypt[0]; // Takes the value of old r0
  new_r3 = vector_to_encrypt[1]; // Takes the value of old r1
  uint16_t combined_k8k9;
  uint16_t combined_k10k11;
  combined_k8k9 = rounds_keys[8] << 8 | rounds_keys[9];
  combined_k10k11 = rounds_keys[10] << 8 | rounds_keys[11];
  uint16_t T0 = G(vector_to_encrypt[0], rounds_keys[0], rounds_keys[1], rounds_keys[2], rounds_keys[3]);
  uint16_t T1 = G(vector_to_encrypt[1], rounds_keys[4], rounds_keys[5], rounds_keys[6], rounds_keys[7]);
  uint16_t F0 = (T0 + (2 * T1) + combined_k8k9) % _2TOTHE16;
  uint16_t F1 = ((2 * T0) + T1 + combined_k10k11) % _2TOTHE16;
  uint16_t right_rotated_r2_after_xor;
  uint16_t left_rotated_r3_before_xor;
  uint16_t r3;
  uint16_t r2;
  left_rotated_r3_before_xor = ((vector_to_encrypt[3] << 1) | (vector_to_encrypt[3] >> 15));
  // XOR F1 with left_rotated
  r3 = F1 ^ left_rotated_r3_before_xor;
  // XOR F0 with vect[2] then rotate right
  r2 = F0 ^ vector_to_encrypt[2];
  right_rotated_r2_after_xor = ((r2 >> 1) | (r2 << 15));
  new_r0 = right_rotated_r2_after_xor;
  new_r1 = r3;
  round_result.push_back(new_r0);
  round_result.push_back(new_r1);
  round_result.push_back(new_r2);
  round_result.push_back(new_r3);
  return round_result;
}

// Method that performs 16 encryption rounds calling F_encrypt and G methods
vector<vector<uint16_t>> perform_encryption(vector<vector<uint16_t>> in_vector, vector<vector<int>> key_vector)
{
  vector<vector<uint16_t>> final_vector;
  vector<uint16_t> round_result;

  for (int i = 0; i < in_vector.size(); i++)
  {
    round_result = F_encrypt(in_vector[i], key_vector[0]);
    for (int i = 1; i < 16; i++)
    {
      round_result = F_encrypt(round_result, key_vector[i]);
    }

    vector<uint16_t> final_flipped = {round_result[2], round_result[3], round_result[0], round_result[1]};
    final_vector.push_back(final_flipped);
  }

  return final_vector;
}

// Method to whiten the input or output vector with the key
vector<vector<uint16_t>> whiten_input_output_vector(vector<vector<uint16_t>> initial, vector<uint16_t> white_key)
{
  vector<vector<uint16_t>> result_vector;
  uint16_t key_word0 = white_key[0];
  uint16_t key_word1 = white_key[1];
  uint16_t key_word2 = white_key[2];
  uint16_t key_word3 = white_key[3];
  uint16_t new_word0;
  uint16_t new_word1;
  uint16_t new_word2;
  uint16_t new_word3;
  vector<uint16_t> temp_vector;
  for (int i = 0; i < initial.size(); i++)
  {
    new_word0 = (initial[i][0] ^ key_word0);
    new_word1 = (initial[i][1] ^ key_word1);
    new_word2 = (initial[i][2] ^ key_word2);
    new_word3 = (initial[i][3] ^ key_word3);
    temp_vector.push_back(new_word0);
    temp_vector.push_back(new_word1);
    temp_vector.push_back(new_word2);
    temp_vector.push_back(new_word3);
    result_vector.push_back(temp_vector);
    temp_vector.clear();
  }
  return result_vector;
}

// Method to convert the hex string key file to hex int
uint64_t hex_from_keyFile(string key_file_path)
{
  string key_str;
  string line;
  ifstream f;
  f.open(key_file_path);
  if (f.fail())
  {
    cout << key_file_path << " does not exist specify the correct key file." << endl;
    exit(EXIT_FAILURE);
  }
  while (getline(f, line))
  {
    key_str += line;
  }
  f.close();
  if (key_str.length() < 16)
  {
    cout << "Input key is less than 64 bits.\nPlease modify your key.txt file to contain 16 hex characters." << endl;
    exit(EXIT_FAILURE);
  }
  if (key_str.length() > 16 && key_str.substr(0, 2) == "0x" || key_str.substr(0, 2) == "0X")
  {
    key_str.erase(0, 2);
  }
  if (key_str.length() > 16)
  {
    cout << "Input key is more than 64 bits.\nPlease modify your key.txt file to contain 16 hex characters.\nCheck for blank or empty spaces and extra lines." << endl;
    exit(EXIT_FAILURE);
  }
  uint64_t key_hex;
  stringstream toHexInt;
  toHexInt << hex << key_str;
  toHexInt >> key_hex;
  return key_hex;
}

// Method that creates the key used for whitening
vector<uint16_t> whitening_key_create(uint64_t key)
{
  vector<uint16_t> whitening_16bit_vector;
  uint16_t word0 = (key >> 48) & 0xFFFF;
  whitening_16bit_vector.push_back(word0);
  uint16_t word1 = (key >> 32) & 0xFFFF;
  whitening_16bit_vector.push_back(word1);
  uint16_t word2 = (key >> 16) & 0xFFFF;
  whitening_16bit_vector.push_back(word2);
  uint16_t word3 = key & 0xFFFF;
  whitening_16bit_vector.push_back(word3);
  return whitening_16bit_vector;
}

// Method to convert the plaintext input into usable hex values
vector<vector<uint16_t>> hex_from_plaintextFile(string input_file_path)
{
  vector<string> hex_string_vector;
  vector<uint16_t> hex_64bit_vector;
  vector<vector<uint16_t>> word_vector;
  string line;
  ifstream f;
  f.open(input_file_path);
  if (f.fail())
  {
    cout << input_file_path << " does not exist specify the correct plaintext file." << endl;
    exit(EXIT_FAILURE);
  }
  f.close();
  ifstream ifs(input_file_path);
  string input_str((std::istreambuf_iterator<char>(ifs)),
                   (std::istreambuf_iterator<char>()));

  if (input_str.length() == 0)
  {
    cout << "Plaintext file empty add text to encrypt." << endl;
    exit(EXIT_FAILURE);
  }
  stringstream ss;
  for (const auto &item : input_str)
  {
    ss << hex << setw(2) << setfill('0') << int(item);
  }
  string hex_string = ss.str();
  int count_0 = 0;
  while (hex_string.length() % 16 != 0)
  {
    hex_string = hex_string + "0";
    count_0++;
  }
  if (count_0 == 14)
  {
    hex_string.erase(hex_string.length() - 1, 1);
    hex_string.insert(hex_string.length(), "7");
  }
  else if (count_0 == 12)
  {
    hex_string.erase(hex_string.length() - 1, 1);
    hex_string.insert(hex_string.length(), "6");
  }
  else if (count_0 == 10)
  {
    hex_string.erase(hex_string.length() - 1, 1);
    hex_string.insert(hex_string.length(), "5");
  }
  else if (count_0 == 8)
  {
    hex_string.erase(hex_string.length() - 1, 1);
    hex_string.insert(hex_string.length(), "4");
  }
  else if (count_0 == 6)
  {
    hex_string.erase(hex_string.length() - 1, 1);
    hex_string.insert(hex_string.length(), "3");
  }
  else if (count_0 == 4)
  {
    hex_string.erase(hex_string.length() - 1, 1);
    hex_string.insert(hex_string.length(), "2");
  }
  else if (count_0 == 2)
  {
    hex_string.erase(hex_string.length() - 1, 1);
    hex_string.insert(hex_string.length(), "1");
  }
  else
  {
    // Do nothing
  }
  string builder;
  for (int i = 0; i < hex_string.length(); i++)
  {
    builder = builder + hex_string[i];
    if (builder.length() == 16)
    {
      hex_string_vector.push_back(builder);
      builder.clear();
    }
  }
  for (int i = 0; i < hex_string_vector.size(); i++)
  {
    // Convert each vector entry to hex
    uint64_t input_hex;
    stringstream toHexInt;
    toHexInt << hex << hex_string_vector[i];
    toHexInt >> input_hex;
    // Break each entry into 4 words and store in new word vector
    uint16_t word0 = (input_hex >> 48) & 0xFFFF;
    hex_64bit_vector.push_back(word0);
    uint16_t word1 = (input_hex >> 32) & 0xFFFF;
    hex_64bit_vector.push_back(word1);
    uint16_t word2 = (input_hex >> 16) & 0xFFFF;
    hex_64bit_vector.push_back(word2);
    uint16_t word3 = input_hex & 0xFFFF;
    hex_64bit_vector.push_back(word3);
    word_vector.push_back(hex_64bit_vector);
    hex_64bit_vector.clear();
  }
  return word_vector;
}

// Method to generate the rounds keys for encryption
vector<vector<int>> key_gen_for_encryption(uint64_t key_hex)
{
  vector<vector<int>> key_vector;
  vector<int> temp_vector;
  int adder = 0;
  int round;
  for (int i = 0; i < 192; i++)
  {
    key_hex = ((key_hex << 1) | (key_hex >> 63));
    if (adder == 4)
    {
      adder = 0;
    }
    if (i < 12)
    {
      round = 0;
    }
    else if (i < 24)
    {
      round = 1;
    }
    else if (i < 36)
    {
      round = 2;
    }
    else if (i < 48)
    {
      round = 3;
    }
    else if (i < 60)
    {
      round = 4;
    }
    else if (i < 72)
    {
      round = 5;
    }
    else if (i < 84)
    {
      round = 6;
    }
    else if (i < 96)
    {
      round = 7;
    }
    else if (i < 108)
    {
      round = 8;
    }
    else if (i < 120)
    {
      round = 9;
    }
    else if (i < 132)
    {
      round = 10;
    }
    else if (i < 144)
    {
      round = 11;
    }
    else if (i < 156)
    {
      round = 12;
    }
    else if (i < 168)
    {
      round = 13;
    }
    else if (i < 180)
    {
      round = 14;
    }
    else if (i < 192)
    {
      round = 15;
    }

    unsigned int target_number = ((4 * round) + adder) % 8;
    auto byte7 = (key_hex >> 56) & 0xFF;
    auto byte6 = (key_hex >> 48) & 0xFF;
    auto byte5 = (key_hex >> 40) & 0xFF;
    auto byte4 = (key_hex >> 32) & 0xFF;
    auto byte3 = (key_hex >> 24) & 0xFF;
    auto byte2 = (key_hex >> 16) & 0xFF;
    auto byte1 = (key_hex >> 8) & 0xFF;
    auto byte0 = key_hex & 0xFF;
    switch (target_number)
    {
    case 0:
    {
      temp_vector.push_back((uint8_t)byte0);
      break;
    }
    case 1:
    {
      temp_vector.push_back((uint8_t)byte1);
      break;
    }
    case 2:
    {
      temp_vector.push_back((uint8_t)byte2);
      break;
    }
    case 3:
    {
      temp_vector.push_back((uint8_t)byte3);
      break;
    }
    case 4:
    {
      temp_vector.push_back((uint8_t)byte4);
      break;
    }
    case 5:
    {
      temp_vector.push_back((uint8_t)byte5);
      break;
    }
    case 6:
    {
      temp_vector.push_back((uint8_t)byte6);
      break;
    }
    case 7:
    {
      temp_vector.push_back((uint8_t)byte7);
      break;
    }
    }
    if (temp_vector.size() == 12)
    {
      key_vector.push_back(temp_vector);
      temp_vector.clear();
    }
    adder++;
  }
  return key_vector;
}