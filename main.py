"""
That is simple chipher program named 'Kuznechik'
Here is mode of simple replacement
"""
import binascii

galua_params = (148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1)
galua_params_reverse = (1, 148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148)

size_of_bock = 32

# Таблица степеней двойки в полях Галуа
galua_fields = (1, 2, 4, 8, 16, 32, 64, 128, 195, 69, 138, 215, 109, 218, 119, 238, 31, 62, 124, 248, 51, 102, 204, 91,
                182, 175, 157, 249, 49, 98, 196, 75, 150, 239, 29, 58, 116, 232, 19, 38, 76, 152, 243, 37, 74, 148, 235,
                21, 42, 84, 168, 147, 229, 9, 18, 36, 72, 144, 227, 5, 10, 20, 40, 80, 160, 131, 197, 73, 146, 231, 13,
                26, 52, 104, 208, 99, 198, 79, 158, 255, 61, 122, 244, 43, 86, 172, 155, 245, 41, 82, 164, 139, 213,
                105, 210, 103, 206, 95, 190, 191, 189, 185, 177, 161, 129, 193, 65, 130, 199, 77, 154, 247, 45, 90, 180,
                171, 149, 233, 17, 34, 68, 136, 211, 101, 202, 87, 174, 159, 253, 57, 114, 228, 11, 22, 44, 88, 176,
                163, 133, 201, 81, 162, 135, 205, 89, 178, 167, 141, 217, 113, 226, 7, 14, 28, 56, 112, 224, 3, 6, 12,
                24, 48, 96, 192, 67, 134, 207, 93, 186, 183, 173, 153, 241, 33, 66, 132, 203, 85, 170, 151, 237, 25, 50,
                100, 200, 83, 166, 143, 221, 121, 242, 39, 78, 156, 251, 53, 106, 212, 107, 214, 111, 222, 127, 254, 63,
                126, 252, 59, 118, 236, 27, 54, 108, 216, 115, 230, 15, 30, 60, 120, 240, 35, 70, 140, 219, 117, 234,
                23, 46, 92, 184, 179, 165, 137, 209, 97, 194, 71, 142, 223, 125, 250, 55, 110, 220, 123, 246, 47, 94,
                188, 187, 181, 169, 145, 225, 1)

# Таблица для прямого хода (straight)
nonlinear_params = (252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233, 119, 240, 219, 147, 46,
                    153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66,
                    139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31, 235, 52, 44,
                    81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204, 181, 112, 14, 86, 8, 12, 118, 18, 191,
                    114, 19, 71, 156, 183, 93, 135, 21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158,
                    178, 177, 50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87, 223, 245, 36, 169,
                    62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3, 224, 15, 236, 222, 122, 148, 176, 188, 220,
                    232, 40, 80, 78, 51, 10, 74, 167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65,
                    173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59, 7, 88, 179, 64, 134, 172,
                    29, 247, 48, 55, 107, 228, 136, 217, 231, 137, 225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144,
                    202, 216, 133, 97, 32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166,
                    116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182)
# Таблица для обратного хода (reverse)
nonlinear_params_reverse = (165, 45, 50, 143, 14, 48, 56, 192, 84, 230, 158, 57, 85, 126, 82, 145, 100, 3, 87, 90, 28, 96,
                            7, 24, 33, 114, 168, 209, 41, 198, 164, 63, 224, 39, 141, 12, 130, 234, 174, 180, 154, 99, 73,
                            229, 66, 228, 21, 183, 200, 6, 112, 157, 65, 117, 25, 201, 170, 252, 77, 191, 42, 115, 132,
                            213, 195, 175, 43, 134, 167, 177, 178, 91, 70, 211, 159, 253, 212, 15, 156, 47, 155, 67, 239,
                            217, 121, 182, 83, 127, 193, 240, 35, 231, 37, 94, 181, 30, 162, 223, 166, 254, 172, 34, 249,
                            226, 74, 188, 53, 202, 238, 120, 5, 107, 81, 225, 89, 163, 242, 113, 86, 17, 106, 137, 148,
                            101, 140, 187, 119, 60, 123, 40, 171, 210, 49, 222, 196, 95, 204, 207, 118, 44, 184, 216, 46,
                            54, 219, 105, 179, 20, 149, 190, 98, 161, 59, 22, 102, 233, 92, 108, 109, 173, 55, 97, 75,
                            185, 227, 186, 241, 160, 133, 131, 218, 71, 197, 176, 51, 250, 150, 111, 110, 194, 246, 80,
                            255, 93, 169, 142, 23, 27, 151, 125, 236, 88, 247, 31, 251, 124, 9, 13, 122, 103, 69, 135,
                            220, 232, 79, 29, 78, 4, 235, 248, 243, 62, 61, 189, 138, 136, 221, 205, 11, 19, 152, 2, 147,
                            128, 144, 208, 36, 52, 203, 237, 244, 206, 153, 16, 68, 64, 146, 58, 1, 38, 18, 26, 72, 104,
                            245, 129, 139, 199, 214, 32, 10, 8, 0, 76, 215, 116)
round_keys = []


def generate_keys(input_key: str):
    """
    :param input_key:
    :type input_key str
    :return:
    """
    # convert to hex
    secret_key = binascii.hexlify(input_key.encode('utf8')).decode('utf8')
    while len(secret_key) <= 64:
        secret_key += secret_key
    secret_key = secret_key[:64]

    constants = []  # Константы
    f = []  # ячейки Фейстеля
    keys = [secret_key[:int(len(secret_key) / 2)], secret_key[int(len(secret_key) / 2):]]

    # Заполнение констант
    for i in range(32):
        if len(hex(i + 1)[2:]) == 1:
            constants.append(l_transform('0' + hex(i + 1)[2:] + '000000000000000000000000000000').upper())
        else:
            constants.append(l_transform(hex(i + 1)[2:] + '000000000000000000000000000000').upper())

    # Формирование ячеек Фейстеля
    f.append([keys[1], xor(l_transform(s_transform(xor(secret_key[0], constants[0]))), keys[1])])
    for i in range(32):
        keys = [f[i][1], xor(l_transform(s_transform(xor(f[i][0], constants[i]))), f[i][1])]
        f.append(keys)

    # разбиение заданного ключа пополам
    keys = [secret_key[:int(len(secret_key) / 2)], secret_key[int(len(secret_key) / 2):]]

    # формирование новых ключей из ячеек Фейстеля
    for i in range(len(f)):
        if (i + 1) % 8 == 0:
            keys.append(f[i][0])
            keys.append(f[i][1])
    return keys


def convert_base(number, tobs=10, frombs=10):
    """
    Функция для перевода числа из одной системы счисления в другую
    :param number:
    :type number intstr
    :param tobs:
    :type tobs int
    :param frombs:
    :type frombs int
    :return: Number in new number system
    :rtype str
    """
    # Преобразование в десятичное число
    if isinstance(number, str):
        n = int(number, frombs)
    else:
        n = int(number)

    # Преобразование десятичного числа в необходимую систему счисления
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"
    if n < tobs:
        return alphabet[n]
    else:
        return convert_base(n // tobs, tobs) + alphabet[n % tobs]


def xor(any_text1: str, any_text2: str, base=16):
    """
    xor для двух шестнадцатеричных строк
    :param any_text1:
    :type any_text1: str
    :param any_text2:
    :type any_text2: str
    :param base:
    :type base: int
    :return: 32-character long string
    :raise:  Append leading zeros, if amount symbols
            in result less than amount symbols in text
    """
    text1_in_base = int(any_text1, base)
    text2_in_base = int(any_text2, base)
    result = hex(text1_in_base ^ text2_in_base)[2:].upper()  # переводим в 16-ричную систему счисления
    result = (len(any_text1) - len(result)) * '0' + result  # Добавление ведущих нулей
    return result


def l_transform(num: str):
    """
    linear transformation
    :param num:
    :type num: str
    :return: string of number in hexadecimal system
    """
    for i in range(16):
        indexes_in_galua_fields = []
        hx_index = []
        galua_values = []

        for j in range(len(galua_params)):
            indexes_in_galua_fields.append(galua_fields.index(
                galua_params[len(galua_params) - j - 1]))
            if int(convert_base(num[j*2:j*2+2], frombs=16)) == 0:
                hx_index.append(257)
            else:
                hx_index.append(galua_fields.index(int(
                    convert_base(num[j*2:j*2+2], frombs=16))))

        for j in range(len(galua_params)):
            if hx_index[j] != 257:
                galua_values.append(
                    galua_fields[(hx_index[j] + indexes_in_galua_fields[j]) % 256])

        galua_num = galua_values[0]
        if len(galua_values) != 1:
            for j in range(len(galua_values) - 1):
                # XOR массива значений, полученных из таблицы степеней двойки `galua_fields`
                galua_num = int(xor(str(galua_num), str(galua_values[j + 1]), base=10), 16) % 256
        galua_num = convert_base(galua_num, tobs=16, frombs=16)
        if len(str(galua_num)) == 1:
            galua_num = '0' + str(galua_num)
        else:
            galua_num = str(galua_num)

        num = num[2:] + galua_num
    return num.upper()

# a = l("11111111111111111111111111111111")
# b = l(a)
# print(b)


def inverse_l(num: str):
    """
    inverse linear transformation
    :param num:
    :type num: str
    :return: string of number in hexadecimal system
    """
    for i in range(16):
        indexes_in_galua_fields = []
        hx_index = []
        galua_values = []

        for j in range(len(galua_params)):
            indexes_in_galua_fields.append(galua_fields.index(
                galua_params_reverse[len(galua_params) - j - 1]))
            if int(convert_base(num[j * 2:j * 2 + 2], frombs=16)) == 0:
                hx_index.append(257)
            else:
                hx_index.append(galua_fields.index(
                    int(convert_base(num[j * 2:j * 2 + 2], frombs=16))))

        for j in range(len(galua_params)):
            if hx_index[j] != 257:
                galua_values.append(
                    galua_fields[(hx_index[j] + indexes_in_galua_fields[j]) % 256])

        galua_num = galua_values[0]
        if len(galua_values) != 1:
            for j in range(len(galua_values) - 1):
                # XOR массива значений, полученных из таблицы степеней двойки `galua_fields`
                galua_num = int(xor(str(galua_num), str(galua_values[j + 1]), base=10), 16) % 256
        galua_num = convert_base(galua_num, tobs=16, frombs=16)
        if len(str(galua_num)) == 1:
            galua_num = '0' + str(galua_num)
        else:
            galua_num = str(galua_num)

        num = galua_num + num[:len(num) - 2]
    return num.upper()


def s_transform(txt_like_num):
    """
    nonlinear transformaton
    :param txt_like_num:
    :type txt_like_num: str
    :return: string of number in hexadecimal system with completed replace
    """

    for i in range(16):
        num_for_replace = txt_like_num[i * 2: i * 2 + 2]

        convert_num = convert_base(num_for_replace, frombs=16)
        num_for_replace = convert_base(nonlinear_params[int(convert_num)], 16)
        if len(num_for_replace) == 1:
            num_for_replace = '0' + num_for_replace
        txt_like_num = txt_like_num[: i * 2] + num_for_replace + txt_like_num[i * 2 + 2:]
    return txt_like_num


def inverse_s(txt_like_num):
    """
    inverse nonlinear transformation
    :param txt_like_num:
    :type txt_like_num: str
    :return: string of number in hexadecimal system with completed replace
    """

    for i in range(16):
        num_for_replace = txt_like_num[i * 2: i * 2 + 2]

        convert_num = convert_base(num_for_replace, frombs=16)
        num_for_replace = convert_base(nonlinear_params_reverse[int(convert_num)], 16)

        if len(num_for_replace) == 1:
            num_for_replace = '0' + num_for_replace
        txt_like_num = txt_like_num[: i * 2] + num_for_replace + txt_like_num[i * 2 + 2:]

    return txt_like_num


def encrypt(any_text, keys):
    """
    Encrypting text
    :param any_text:
    :type any_text: str
    :param keys:
    :return:
    encrypted_text
    """
    any_text = binascii.hexlify(any_text.encode('utf8')).decode('utf8')

    count = size_of_bock - len(any_text) % size_of_bock
    if count != 0 and count != size_of_bock:
        for i in range(count):
            any_text += '0'
    text_array = []
    for i in range(int(len(any_text) / size_of_bock)):
        text_array.append(any_text[i * size_of_bock: i * size_of_bock + size_of_bock])

    text_encrypt = []
    for txt in text_array:
        text_for_encrypt = txt
        for i in range(9):
            text_for_encrypt = l_transform(s_transform(xor(text_for_encrypt, keys[i])))
        text_for_encrypt = xor(text_for_encrypt, keys[9])
        text_encrypt.append(text_for_encrypt)
    return ''.join(text_encrypt)


def decrypt(any_text, keys):
    """
    Decrypting text
    :param any_text:
    :type any_text: str
    :param keys:
    :return:
    decrypted text
    """
    text_array = []
    for i in range(int(len(any_text) / size_of_bock)):
        text_array.append(any_text[i * size_of_bock:i * size_of_bock + size_of_bock])

    text_decrypt = []
    text_decrypted = ""
    for i in range(len(text_array)):
        text_decrypted = text_array[i]
        for j in range(9, 0, -1):
            text_decrypted = inverse_s(inverse_l(xor(text_decrypted, keys[j])))
        text_decrypted = xor(text_decrypted, keys[0])
        if i == len(text_array) - 1:
            while text_decrypted[-1] == '0':
                text_decrypted = text_decrypted[:-1]
        text_decrypt.append(text_decrypted)
    return binascii.unhexlify(''.join(text_decrypt)).decode('utf8')


if __name__ == "__main__":
    with open('input.txt') as input_file:
        text = input_file.read()
    text.encode("utf-8")
    with open('key.txt') as key_file:
        key = key_file.read()
    key = generate_keys(key)
    encrypted_text = encrypt(text, key)
    decrypted_text = decrypt(encrypted_text, key)
    with open('output.txt', 'w') as out_file:
        out_file.write(decrypted_text)
