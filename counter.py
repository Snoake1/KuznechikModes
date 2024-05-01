import binascii
import time

from main import l, s, x, generate_keys, get_blocks


def get_CTRS(sync_message, amound_of_blocks, keys):
    sync_message = binascii.hexlify(sync_message.encode("utf8")).decode("utf8")
    CTRS = []
    for i in range(amound_of_blocks):
        for j in range(9):
            CTR = l(s(x(sync_message, keys[j])))
        CTRS.append(CTR)
        sync_message = hex(int(sync_message, 16) + 1)[2:]
        if len(sync_message) % 32 != 0:
            sync_message = sync_message[:32]
    return CTRS


def counter(sync_message):
    text_blocks = get_blocks(text)
    CTRS = get_CTRS(sync_message, len(text_blocks), keys)
    return CTRS


def encrypt(text, keys, sync_message):
    blocks = get_blocks(text)
    CTRS = get_CTRS(sync_message, len(blocks), keys)
    encrypted_text = []
    for i, txt in enumerate(blocks):
        encrypted_text.append(x(txt, CTRS[i]))
    return "".join(encrypted_text)


def decrypt(encrypted_text, keys, sync_message):
    text_array = []
    for i in range(int(len(text) / 32)):
        text_array.append(text[i * 32: i * 32 + 32])

    blocks = get_blocks(encrypted_text)
    CTRS = get_CTRS(sync_message, len(blocks), keys)

    decrypted_text = []
    for i, txt in enumerate(blocks):
        decrypted_text.append(x(txt, CTRS[i]).lower())
    return binascii.unhexlify("".join(decrypted_text)).decode('utf8')


if __name__ == "__main__":
    sync_message = "lovecryptography"
    with open("input3x.txt", encoding="utf-8", mode='r') as file:
        text = file.readlines()
    text = ''.join(text)
    text.encode("utf-8")
    text = binascii.hexlify(text.encode("utf8")).decode("utf8")
    keys = generate_keys("СекретныйПароль")
    start = time.time()
    encrypted_text = encrypt(text, keys, sync_message)
    decrypt(encrypted_text, keys, sync_message)
    end = time.time()
    print(end - start)