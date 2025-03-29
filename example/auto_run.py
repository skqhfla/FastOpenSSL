#!/usr/bin/python3

import subprocess
import re

loop_count = 100

fast_enc_file = "./AES_encrypt_fast"
norm_enc_file = "./AES_encrypt"

fast_enc_result = "encrypt.out"
norm_enc_result = "ciphertext.bin"

enc_binaries = [
        (fast_enc_file, "e46858715f6ca44839c66579759307a2332bb751a28b254e8b5347ac193efd61", "0ee5c8893a86718f5a0d9852"),
        (norm_enc_file, "e46858715f6ca44839c66579759307a2332bb751a28b254e8b5347ac193efd61", "0ee5c8893a86718f5a0d9852"),
        ]

dec_binaries = [
        ("./AES_decrypt_fast", "e46858715f6ca44839c66579759307a2332bb751a28b254e8b5347ac193efd61"),
        ("./AES_decrypt", "e46858715f6ca44839c66579759307a2332bb751a28b254e8b5347ac193efd61"),
        ]


pattern = re.compile(r"Execution time:\s*([0-9.]+)\s*seconds")

def calc_improvement(fast, normal):
    print(f"Compare Execution Time {fast} <-> {normal}")

    if fast is None or normal is None:
        return None
    return ((normal - fast) / fast) * 100


def check_contents(cmp1, cmp2):
    print(f"Compare file context {cmp1} <-> {cmp2}")
    context1 = b""
    context2 = b""
    
    with open(cmp1, "rb") as f1:
        context1 = f1.read();

    with open(cmp2, "rb") as f2:
        context2 = f2.read();


    if context1 == context2:
        print(f"Eqaul between {cmp1} and {cmp2}\n")
    else:
        print(f"Different between {cmp1} and {cmp2}\n")

def compare_main():
    execution_times = []
    for i in range(len(enc_binaries)):
        enc_info = enc_binaries[i];
        dec_info = dec_binaries[i];
        try:
            result = subprocess.run([enc_info[0], enc_info[1], enc_info[2]], capture_output=True, text=True)
            match = pattern.search(result.stdout)
            if match:
                time = float(match.group(1))
                execution_times.append(time)
                print(f"{enc_info[0]} Execution Time: {time:.6f}")
            else:
                print(f"{enc_info[0]} Can not find Execution Time")
                execution_times.append(None)
        except subprocess.CalledProcessError as e:
            print(f"{enc_info[0]} Error Occur: {e}")
            execution_times.append(None)
        finally: 
            result = subprocess.run([dec_info[0], dec_info[1]], capture_output=True, text=True)

    if len(execution_times) > 1:
        print(f"\n## Compare result {fast_enc_file} - {norm_enc_file}")
        check_contents(fast_enc_result, norm_enc_result)
        imp_1_3 = calc_improvement(execution_times[0], execution_times[1])
        # imp_2_4 = calc_improvement(execution_times[1], execution_times[3])

        if imp_1_3 is not None:
            print(f"  - Encryption performance improvement: {imp_1_3:.2f}%")
        else:
            print("  - Can not compare execution time")

        """
        if imp_2_4 is not None:
            print(f"Decnryption performance improvement: {imp_1_3:.2f}%")
        else:
            print("Can not compare execution time")
        """


    return imp_1_3
        
        
if __name__=="__main__":
    res_min, res_max, res_avg, bad_perf_cnt = 100, 0, 0, 0
    perf_res = []
    print("Performance Compare Loop: ", loop_count)

    for idx in range(1, loop_count + 1):
        print(f"###### Loop Count: [{idx}]")
        res = compare_main()
        if res < 0:
            bad_perf_cnt += 1
        res_min = res if res < res_min else res_min
        res_max = res if res > res_max else res_max
        res_avg += res
        perf_res.append(res)
        print()
    
    res_avg /= loop_count
    print("------- Summary ------")
    print("Loop Count: ", loop_count)
    print(f"Avg improvement rate: {res_avg:.2f}%")
    print(f"Max improvement rate: {res_max:.2f}%")
    print(f"Min improvement rate: {res_min:.2f}%")
    print(f"Bad performance rate: {bad_perf_cnt/loop_count:.2f}% [{bad_perf_cnt} / {loop_count}]")

    print()
    print("Total performance rate")
    for idx, perf in enumerate(perf_res):
        print(f"[Loop: {idx + 1}] {perf:.2f}%")
    print()

