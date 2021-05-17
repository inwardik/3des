import pyDes
import itertools as it


def get_mutations(input_string):
    """return all permutation of input string according letters befor char '?' """
    replace_dic = {'0': ('D', '8', '0'), 'D' : ('0', '8', 'D'), '8': ('D', '0', '8')}
    a = []
    for i in range(len(input_string)):
        if input_string[i] != '?':
            a.append(input_string[i])
        else:
            if input_string[i-1] in replace_dic:
                a.append(input_string[i])
    variants = []
    replace_indexes = [i[0] for i in enumerate(a) if i[1] == '?']
    comb_list = []
    for r_index in replace_indexes:
        comb_list.append(replace_dic.get(a[r_index-1]))
    full_comb = list(it.product(*comb_list))
    for item in full_comb:
        for r_index in enumerate(replace_indexes):
            a[r_index[1]-1] = item[r_index[0]]
        b = "".join([i for i in a if i != '?'])
        variants.append(b)
    return variants


def byte_xor(ba1, ba2):
    """return XOR for both parameters"""
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


def check_kvc(key1, key2, kvc):
    """return is both keys equial to kvc"""
    k1_hex = bytes.fromhex(key1)
    k2_hex = bytes.fromhex(key2)
    kvc_hex = bytes.fromhex(kvc)
    key3 = byte_xor(k1_hex, k2_hex)
    secret_key = bytes.fromhex('00000000000000000000000000000000')
    k = pyDes.triple_des(key3, mode=pyDes.ECB)
    k1 = k.encrypt(secret_key)
    hex_in_str = ""
    for w in k1:
        hex_in_str += str(hex(w))[2:].upper()
    return hex_in_str[:len(kvc)] == kvc


def find_keys(key1, key2, kvc):
    keys1 = get_mutations(key1)
    keys2 = get_mutations(key2)
    for k1 in keys1:
        for k2 in keys2:
            if check_kvc(k1, k2, kvc):
                return (k1, k2, kvc)
    return None


def main():
    key1 = '928?B04F2EC8?3A7C48?1433DBFA430?497F'
    key2 = '8?138B6E37990?0B7CF14AD54A38526E0?9'
    kvc = '53CEE9'
    print(find_keys(key1, key2, kvc))


if __name__ == '__main__':
    main()