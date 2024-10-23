# Bitcoin Key and Address Generator

Этот проект реализует генерацию Bitcoin-ключей и адресов, используя библиотеку OpenSSL для криптографических операций. Он включает в себя создание приватных и публичных ключей, адресов P2PKH и P2SH, а также кодирование в формате WIF (Wallet Import Format).

## Описание функций

- `create_ec_key(const UC_VECTOR& privateKey)`: Создает EC ключ из переданного приватного ключа в формате `uint8_t` вектора. Возвращает указатель на созданный ключ или `std::nullopt` в случае ошибки.
  
- `generate_public_key(const UC_VECTOR& privateKey, bool isCompressed)`: Генерирует публичный ключ на основе предоставленного приватного ключа. Возвращает строку с публичным ключом и вектор его байтов.

- `sha256(const std::string& str)`: Вычисляет SHA-256 хэш для переданной строки. Возвращает хэш в шестнадцатеричном формате и байтовый вектор.

- `double_sha256(const UC_VECTOR& data)`: Вычисляет двойной SHA-256 хэш для предоставленных данных.

- `ripemd160(const UC_VECTOR& data)`: Вычисляет RIPEMD-160 хэш для предоставленных данных. Возвращает хэш в шестнадцатеричном формате и байтовый вектор.

- `create_wif(const UC_VECTOR& privateKey, bool isCompressed)`: Создает WIF из приватного ключа. Если `isCompressed` равно `true`, добавляет признак сжатия.

- `create_p2pkh_address(const UC_VECTOR& publicKeyBytes)`: Создает P2PKH адрес из публичного ключа. Возвращает адрес в формате Base58 и вектор его байтов.

- `create_p2sh_address(const UC_VECTOR& script)`: Создает P2SH адрес из скрипта. Возвращает адрес в формате Base58.

## Пример использования

В функции `main` реализован пример работы с кодом. Она генерирует ключи и адреса на основе строки `"bitcoin is awesome"`:

```cpp
int main(int argc, char** argv) {
    const std::string input = "bitcoin is awesome";
    // Прочие вызовы функций
}
```

![{E1634490-5071-4D9D-8D8A-B4A101A318F1}](https://github.com/user-attachments/assets/1ae2eca4-ff41-42b5-9b44-c961f048b1f4)

### Сборка и запуск

Для сборки проекта с помощью CMake выполните следующие шаги:

1. Убедитесь, что у вас установлены CMake и OpenSSL. Если у вас их нет, вы можете установить их, используя пакетный менеджер вашей операционной системы.

    - Для Ubuntu:

      ```bash
      sudo apt update
      sudo apt install cmake libssl-dev
      ```

    - Для macOS (с установленным Homebrew):

      ```bash
      brew install cmake openssl
      ```

    - Для Windows, вы можете скачать CMake и OpenSSL с их официальных сайтов.

2. Создайте директорию для сборки и перейдите в нее:

    ```bash
    mkdir build
    cd build
    ```

3. Выполните команду CMake для конфигурации проекта:

    ```bash
    cmake ..
    ```

4. Скомпилируйте проект:

    ```bash
    make
    ```

5. Запустите скомпилированный файл:

    ```bash
    ./bitcoin_key_generator
    ```

