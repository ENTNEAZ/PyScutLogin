# 代码来自 https://bbs.kanxue.com/thread-224363.htm
# 作者 wenglingok
from .DES import *


def strenc(data, firstkey, secondkey, thirdkey):
    bts_data = extend_to_16bits(data)  # 将data长度扩展成64位的倍数
    bts_firstkey = extend_to_16bits(firstkey)  # 将 first_key 长度扩展成64位的倍数
    bts_secondkey = extend_to_16bits(secondkey)  # 将 second_key 长度扩展成64位的倍数
    bts_thirdkey = extend_to_16bits(thirdkey)  # 将 third_key 长度扩展成64位的倍数
    i = 0
    bts_result = []
    while i < len(bts_data):
        bts_temp = bts_data[i:i + 8]  # 将data分成每64位一段，分段加密
        j, k, l = 0, 0, 0
        while j < len(bts_firstkey):
            des_k = des(bts_firstkey[j: j + 8], ECB)  # 分别取出 first_key 的64位作为密钥
            bts_temp = list(des_k.encrypt(bts_temp))
            j += 8
        while k < len(bts_secondkey):
            # 分别取出 second_key 的64位作为密钥
            des_k = des(bts_secondkey[k:k + 8], ECB)
            bts_temp = list(des_k.encrypt(bts_temp))
            k += 8
        while l < len(bts_thirdkey):
            # 分别取出 third_key 的64位作为密钥
            des_k = des(bts_thirdkey[l:l + 8], ECB)
            bts_temp = list(des_k.encrypt(bts_temp))
            l += 8
        bts_result.extend(bts_temp)
        i += 8
    str_result = ''
    for each in bts_result:
        str_result += '%02X' % each  # 分别加密data的各段，串联成字符串
    return str_result


def extend_to_16bits(data):  # 将字符串的每个字符前插入 0，变成16位，并在后面补0，使其长度是64位整数倍
    bts = data.encode()
    filled_bts = []
    for each in bts:
        filled_bts.extend([0, each])  # 每个字符前插入 0
    while len(filled_bts) % 8 != 0:  # 长度扩展到8的倍数
        filled_bts.append(0)  # 不是8的倍数，后面添加0，便于DES加密时分组
    return filled_bts
